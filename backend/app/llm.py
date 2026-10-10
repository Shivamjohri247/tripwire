"""OpenRouter client: ordered model fallback, retries with jitter, per-model circuit breaker, SQLite cache."""
import asyncio
import base64
import collections
import hashlib
import hmac
import json
import os
import random
import re
import time

from openai import AsyncOpenAI, BadRequestError

from . import store
from .config import LLM_RPM, OPENROUTER_API_KEY, OPENROUTER_BASE
from .events import emit

_client = AsyncOpenAI(base_url=OPENROUTER_BASE, api_key=OPENROUTER_API_KEY or 'missing', max_retries=0)
# per-model health: consecutive failures, breaker open-until, recent latencies, last error
health = collections.defaultdict(lambda: {'fails': 0, 'open_until': 0.0, 'lat': collections.deque(maxlen=50), 'calls': 0, 'errors': 0, 'last_error': ''})
counters = {'calls': 0, 'cache_hits': 0}
_reasoning_required = set()  # models that reject reasoning.enabled=false


class LLMUnavailable(Exception):
    pass


_next_slot, _pace_lock = 0.0, asyncio.Lock()


async def _pace():
    """Space call starts at 60/LLM_RPM s: the free tier limits requests per minute per account, across all models."""
    global _next_slot
    async with _pace_lock:
        now = time.monotonic()
        wait, _next_slot = _next_slot - now, max(now, _next_slot) + 60 / LLM_RPM
    if wait > 0:
        await asyncio.sleep(wait)


def breaker_state(model):
    h = health[model]
    if h['open_until'] > time.time():
        return 'open'
    return 'half-open' if h['fails'] else 'closed'


async def chat(models, messages, *, cfg, json_mode=False, max_tokens=None, scan_id=None, trace=None, purpose='llm'):
    """Returns {'text', 'model', 'cached', 'latency_ms'}. Raises LLMUnavailable when every model failed."""
    mc = cfg['models']
    key = hashlib.sha256(json.dumps([models, messages, json_mode, max_tokens], ensure_ascii=False).encode()).hexdigest()
    if mc.get('cache', True):
        hit = store.cache_get(key)
        if hit:
            counters['cache_hits'] += 1
            return {**json.loads(hit), 'cached': True, 'latency_ms': 0}
    if not OPENROUTER_API_KEY:
        raise LLMUnavailable('OPENROUTER_API_KEY not set')
    last_err = None
    for i, model in enumerate(models):
        if breaker_state(model) == 'open':
            emit('llm', 'llm_fallback', f'{_short(model)} breaker open → skipped', scan_id, trace)
            continue
        for attempt in range(mc.get('retries', 2) + 1):
            t0 = time.time()
            try:
                kw = {'response_format': {'type': 'json_object'}} if json_mode else {}
                call = lambda off: _client.chat.completions.create(  # noqa: E731
                    model=model, messages=messages, temperature=mc.get('temperature', 0), max_tokens=max_tokens or mc.get('maxTokens', 600),
                    timeout=mc.get('timeout', 25), extra_body={'reasoning': {'enabled': False}} if off else None, **kw)
                # reasoning models (nemotron) otherwise spend max_tokens thinking and return no content; some (lfm) refuse to disable it
                await _pace()
                try:
                    r = await call(model not in _reasoning_required)
                except BadRequestError as e:
                    if 'easoning is mandatory' not in str(e) or model in _reasoning_required:
                        raise
                    _reasoning_required.add(model)
                    r = await call(False)
                text = (r.choices[0].message.content or '').strip() if r.choices else ''
                if not text:
                    raise RuntimeError(f"empty response (finish={r.choices[0].finish_reason if r.choices else 'none'})")
                ms = int((time.time() - t0) * 1000)
                h = health[model]
                h.update(fails=0, open_until=0.0)
                h['lat'].append(ms)
                h['calls'] += 1
                counters['calls'] += 1
                out = {'text': text, 'model': model}
                if mc.get('cache', True):
                    store.cache_put(key, json.dumps(out, ensure_ascii=False))
                return {**out, 'cached': False, 'latency_ms': ms}
            except Exception as e:  # network, 429, 5xx, timeouts, empty output
                last_err = e
                h = health[model]
                h['fails'] += 1
                h['errors'] += 1
                h['last_error'] = _err(e)
                if h['fails'] >= mc.get('breakerFails', 5):
                    h['open_until'] = time.time() + mc.get('breakerCool', 60)
                    break
                if attempt < mc.get('retries', 2):
                    await asyncio.sleep((1.5 ** attempt) + random.random())
        nxt = next((m for m in models[i + 1:] if breaker_state(m) != 'open'), None)
        emit('llm', 'llm_fallback', f'{_short(model)} {_err(last_err)}' + (f' → {_short(nxt)}' if nxt else ''), scan_id, trace, purpose=purpose)
    emit('llm', 'llm_fallback', f'{purpose}: no fallback left · {_err(last_err)}', scan_id, trace, purpose=purpose)
    raise LLMUnavailable(_err(last_err))


def _short(m):
    return m.split('/')[-1] if m else ''


def _err(e):
    return f"{getattr(e, 'status_code', None) or type(e).__name__}: {str(e)[:80]}"


def parse_json(text):
    """Strict JSON first, then the first {...} block (free models often wrap JSON in prose or fences)."""
    try:
        return json.loads(text)
    except ValueError:
        m = re.search(r'\{[\s\S]*\}', text)
        if m:
            try:
                return json.loads(m.group(0))
            except ValueError:
                pass
    return None


def image_message(prompt, png_bytes, mime='image/png'):
    return {'role': 'user', 'content': [{'type': 'text', 'text': prompt},
                                        {'type': 'image_url', 'image_url': {'url': f'data:{mime};base64,{base64.b64encode(png_bytes).decode()}'}}]}


_ZW = '[\\s\u200b-\u200d\u2060\ufeff\u00ad]*'  # spaces and invisible characters an attacker can slip inside a tag


def defang(text, tag):
    """Neutralise any <tag> or </tag> in untrusted text so it cannot end its wrapper early.
    Escapes the bracket instead of deleting the tag (deletion lets '</unt</untrusted>rusted>' rebuild one),
    and matches lookalike brackets, any case, and invisible characters between letters."""
    name = _ZW.join(re.escape(c) for c in tag)
    return re.sub(rf'[<\uFF1C\uFE64]({_ZW}/?{_ZW})(?={name})', r'&lt;\1', text, flags=re.I)


def server_secret():
    """16 random bytes made once per deployment and kept in the store; keys canaries and wrapper boundaries."""
    m = store.get('meta', 'canary_salt')
    if not m:
        m = store.put('meta', 'canary_salt', {'v': os.urandom(16).hex()})
    return bytes.fromhex(m['v'])


def boundary(tag, text):
    """Wrapper tag name with a keyed code: stable for identical text (LLM cache) but unknowable to the text's author,
    so nothing inside can write the matching closing tag. defang is the second layer."""
    return f"{tag}-{hmac.new(server_secret(), text.encode(), hashlib.sha256).hexdigest()[:12]}"


def spotlight(text, tag='data'):
    """Wrap untrusted text so the firewall's own LLM treats it as data (spec §5 self-protection)."""
    b = boundary(tag, text)
    return f'<{b}>\n{defang(text, tag)}\n</{b}>'

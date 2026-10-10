"""The multi-agent scan graph (LangGraph).

triage → sentinel → session ─┬─ allow ──────────────────────────────┐
                             ├─ confirmed ──────────► neutralize ⟲ ─┤
                             └─ gray ─► decoy A ∥ decoy B ─► judge ─┴─► adjudicate
Routing is policy code; each node is an agent that may call an LLM.
"""
import asyncio
import hashlib
import io
import operator
import time
import uuid
from typing import Annotated, TypedDict

from langgraph.graph import END, START, StateGraph
from langgraph.types import Send

from . import detonator, llm, neutralizer, sentinel, store, triage
from .config import VISION_MODELS
from .events import emit
from .guard import session_risk

T = lambda: time.perf_counter()


class S(TypedDict, total=False):
    req: dict
    segs: list
    meta: dict
    risk: float
    disagree: bool
    zone: str
    session: dict
    detonations: Annotated[list, operator.add]
    det: dict
    passes: int
    dirty: bool
    quarantine: bool
    degraded: bool


def _ctx(config):
    return config['configurable']['ctx']


def _ev(ctx, agent, type, msg, **data):
    emit(agent, type, msg, ctx['scan_id'], ctx['trace'], **data)


def _low(ctx):
    return ctx['cfg']['policy']['lowBandHigh' if ctx['dest']['risk'] == 'high' else 'lowBandLow']


# ---------- ① triage ----------
OCR_PROMPT = ('Transcribe every piece of text in this image exactly, including tiny, faint, low-contrast or watermark-like text. '
              'JSON only: {"lines":[{"text":"...","faint":true|false}]}. faint=true when a person glancing at the image would likely not notice it.')


MAX_PIXELS = 40_000_000  # an image header can claim any size; refuse before decoding (decompression-bomb guard)


async def ocr(data, name, ctx, downscale):
    from PIL import Image
    try:
        img = Image.open(io.BytesIO(data))
    except Image.DecompressionBombError as e:
        raise ValueError(str(e)) from e
    if img.width * img.height > MAX_PIXELS:
        raise ValueError(f'image is {img.width}x{img.height}, over the {MAX_PIXELS // 1_000_000} MP limit')
    img = img.convert('RGB')
    img.thumbnail((4096, 4096))  # the vision models read nothing finer than this
    scales = [1.0, 0.5] if downscale else [1.0]

    async def at(scale):
        im = img if scale == 1 else img.resize((max(1, int(img.width * scale)), max(1, int(img.height * scale))))
        buf = io.BytesIO()
        im.save(buf, 'PNG')
        r = await llm.chat(VISION_MODELS, [llm.image_message(OCR_PROMPT, buf.getvalue())], cfg=ctx['cfg'], json_mode=True,
                           max_tokens=900, scan_id=ctx['scan_id'], trace=ctx['trace'], purpose='ocr')
        ctx['llm_calls'] += 0 if r['cached'] else 1
        return [l for l in (llm.parse_json(r['text']) or {}).get('lines', []) if isinstance(l, dict) and str(l.get('text', '')).strip()]

    full, *small = await asyncio.gather(*(at(s) for s in scales))
    segs = [triage.seg(str(l['text']) + '\n', f'{name} · OCR 1×', 'low_contrast_ocr' if l.get('faint') else None) for l in full]
    for l in (small[0] if small else []):
        t = str(l['text'])
        if all(sentinel.similarity(t, x['t']) < 0.8 for x in segs):
            segs.append(triage.seg(t + '\n', f'{name} · OCR 0.5× only', 'downscale_only'))
    _ev(ctx, 'triage', 'signal', f'OCR {name}: {len(full)} lines at 1×' + (f', {len(small[0])} at 0.5×' if small else ''))
    return segs


async def parse_any(name, data, fmt, ctx, depth=0):
    if fmt == 'image':
        return {'segs': await ocr(data, name, ctx, ctx['cfg']['detect'].get('ocrDownscale', True) and ctx['source'].get('downscale', True))}
    out = triage.parse(data, fmt)
    for an, ad in (out.pop('attachments', None) or [])[:5]:
        if depth >= 2 or not ctx['source'].get('attachments', True):
            break
        af = triage.detect_format(an, None)
        try:
            sub = await parse_any(an, ad, af, ctx, depth + 1)
            out['segs'] += [{**s, 'loc': f"attachment {an} · {s['loc']}"} for s in sub['segs']]
            _ev(ctx, 'triage', 'signal', f'Attachment {an} parsed as {af} · {len(sub["segs"])} segments')
        except Exception as e:
            out['segs'].append(triage.seg(f'[attachment {an} could not be parsed: {e}]\n', 'attachment', meta=True))
    return out


async def triage_node(state: S, config):
    ctx, req = _ctx(config), state['req']
    t0 = T()
    data, name, fmt = req['data'], req['name'], req['fmt']
    _ev(ctx, 'triage', 'started', f'Received {name} · {len(data) / 1024:.1f} KB · {fmt} · channel={req["channel"]}')
    meta = {'unparsed': False, 'title': name, 'notes': []}
    max_mb = ctx['source'].get('maxMb', 10)
    if len(data) > max_mb * 1048576:
        _ev(ctx, 'triage', 'decision', f'Over the {max_mb} MB source limit')
        ctx['timings']['triage'] = int((T() - t0) * 1000)
        return {'segs': [], 'meta': {**meta, 'oversize': True}, 'zone': 'oversize', 'risk': 1.0}
    try:
        parsed = await parse_any(name, data, fmt, ctx)
    except llm.LLMUnavailable as e:
        parsed = {'segs': [triage.seg(f'[image {name}: OCR unavailable ({e})]\n', 'image', meta=True)]}
        meta['unparsed'] = True
    except Exception as e:  # malformed files never crash the pipeline (spec §13)
        parsed = {'segs': [triage.seg(f'[could not parse {name}: {e}]\n', 'parser', meta=True)]}
        meta['unparsed'] = True
    meta['title'] = parsed.get('title') or name
    meta['pages'] = parsed.get('pages')
    if parsed.get('note'):
        _ev(ctx, 'triage', 'signal', parsed['note'])
    _ev(ctx, 'triage', 'decision', f"{len(parsed['segs'])} raw segments" + (f" · {parsed['pages']} pages" if parsed.get('pages') else ''))
    rules = sentinel.compile_rules(ctx['cfg'])
    notes = []
    segs = triage.reveal(parsed['segs'], notes, lambda t: any(r['re'].search(t) for r in rules), ctx['cfg']['policy'].get('decodeDepth', 3))
    for i, s in enumerate(segs):
        s['id'] = f'seg_{i + 1}'
    for n in list(dict.fromkeys(notes))[:6]:
        _ev(ctx, 'triage', 'signal', n)
    hidden = [s for s in segs if triage.is_hidden(s)]
    if hidden:
        _ev(ctx, 'triage', 'signal', f"{len(hidden)} hidden segment(s): {', '.join(dict.fromkeys(s['h'] for s in hidden))}")
    pol = ctx['cfg']['policy']
    _ev(ctx, 'triage', 'decision', f"Plan: {ctx['dest']['risk']}-risk destination → gray band {_low(ctx):.2f}–{pol['highBand']:.2f}"
                                  f" · task “{ctx['task']}”")
    ctx['timings']['triage'] = int((T() - t0) * 1000)
    return {'segs': segs, 'meta': meta, 'zone': 'unparsed' if meta['unparsed'] else ''}


# ---------- ② sentinel ----------
async def sentinel_node(state: S, config):
    ctx = _ctx(config)
    if state.get('zone') in ('oversize',):
        return {}
    t0 = T()
    cfg, segs, pol = ctx['cfg'], state['segs'], ctx['cfg']['policy']
    static = sentinel.static_scan(segs, cfg)
    rule_ids = list(dict.fromkeys(r['id'] for s in segs for r in s['rule_hits']))
    if rule_ids:
        _ev(ctx, 'sentinel', 'signal', f"Rules matched: {', '.join(rule_ids)}")
    mem = [s['mem'] for s in segs if s.get('mem')]
    if mem:
        _ev(ctx, 'sentinel', 'signal', 'Attack memory: ' + ', '.join(f"{m['id']} sim {m['sim']}" for m in mem[:4]))
    # session turns never count as quiet: crescendo turns look innocent one by one, so rules alone keep session risk at 0
    quiet = static == 0 and not any(triage.is_hidden(s) or s.get('enc') for s in segs) and not state['req'].get('session_id')
    use_llm = cfg['detect'].get('llmSentinel', True) and not ctx['opts'].get('rules_only') and not (quiet and ctx['dest']['risk'] == 'low')
    verdicts, degraded = {}, False
    if use_llm and any(not s.get('meta') for s in segs):
        try:
            verdicts, calls, models = await sentinel.llm_scan(segs, cfg, ctx['dest'], ctx['scan_id'], ctx['trace'], state['req']['channel'])
            ctx['llm_calls'] += calls
            if verdicts.pop('_parse_error', False):
                _ev(ctx, 'sentinel', 'signal', 'Classifier JSON unparseable after retry → treated as suspicious')
                degraded = True
            _ev(ctx, 'sentinel', 'decision', f"LLM classifier ({', '.join(m.split('/')[-1] for m in models)}) flagged {sum(v['injection'] for v in verdicts.values())} segment(s)")
        except llm.LLMUnavailable as e:
            degraded = True
            _ev(ctx, 'sentinel', 'llm_fallback', f'LLM classifier unavailable ({e}) → rules and memory only')
    elif not use_llm:
        _ev(ctx, 'sentinel', 'decision', 'LLM classifier skipped (0 calls): ' + ('nothing suspicious, low-risk destination' if quiet else 'rules-only mode'))
    risk, disagree = 0.0, False
    for i, s in enumerate(segs):
        v = verdicts.get(i)
        score = v['conf'] if v and v['injection'] else 0.0
        if v and v['injection']:
            s['by'].append(f"llm:{v['conf']:.2f}")
            s['types'] = list(dict.fromkeys(s['types'] + v['types'])) or ['T9 indirect']
            s['why'] = v['why']
        elif v:  # ambiguous, not injection
            s['by'].append(f"llm:benign {v['conf']:.2f}")
        s['llm'] = score
        if use_llm and not degraded and abs(s['w'] - score) > pol.get('disagreement', 0.5) and max(s['w'], score) >= 0.5:
            disagree = True
            s['by'].append('sentinel:disagreement')
        s['risk'] = round(sentinel.fuse(s, pol, score), 2)
        if s['risk'] >= _low(ctx) and s['types']:
            s['f'] = s['types'][0]
        risk = max(risk, s['risk'])
    _ev(ctx, 'sentinel', 'decision', f'Risk {risk:.2f}' + (' · rules and LLM disagree → gray zone' if disagree else ''))
    ctx['timings']['sentinel'] = int((T() - t0) * 1000)
    return {'segs': segs, 'risk': round(risk, 2), 'disagree': disagree, 'degraded': degraded}


# ---------- ⑥ session ----------
async def session_node(state: S, config):
    ctx, req = _ctx(config), state['req']
    sid = req.get('session_id')
    if not sid or state.get('zone') == 'oversize':
        return {}
    text = '\n'.join(triage.text_of(s) for s in state['segs'] if not s.get('meta')).strip()
    doc = store.get('session', sid) or {'id': sid, 'dest': ctx['dest']['id'], 'user': req.get('user') or 'unknown', 'turns': [], 'detonated': False}
    before = session_risk(doc['turns'], ctx['cfg']['policy'])['alert'] if doc['turns'] else False
    types = list(dict.fromkeys(t for s in state['segs'] for t in s.get('types', [])))
    doc['turns'].append({'t': text[:400], 'hash': hashlib.sha256(text.encode()).hexdigest()[:12], 'risk': state.get('risk', 0), 'types': types, 'scan_id': ctx['scan_id']})
    sr = session_risk(doc['turns'], ctx['cfg']['policy'])
    fresh = sr['alert'] and not before
    window = None
    if fresh:
        doc['detonated'] = True
        window = [t['t'] for t in doc['turns'][-ctx['cfg']['policy'].get('sessionWindow', 10):-1]]
        _ev(ctx, 'session', 'signal', f"session_alert {sid} · risk {sr['risk']:.2f}" + (' · rising 3 turns' if sr['rising'] else '') + ' → window sent to Detonator')
    else:
        _ev(ctx, 'session', 'decision', f"{sid} turn {len(doc['turns'])} · session risk {sr['risk']:.2f}")
    store.put('session', sid, doc)
    return {'session': {**sr, 'id': sid, 'turns': len(doc['turns']), 'fresh_alert': fresh, 'window': window}}


def route(state: S, config):
    ctx = _ctx(config)
    zone = state.get('zone')
    if zone in ('oversize', 'unparsed'):
        return 'adjudicate'
    pol, risk, segs = ctx['cfg']['policy'], state.get('risk', 0), state['segs']
    alert = (state.get('session') or {}).get('fresh_alert')
    if risk < _low(ctx) and not state.get('disagree') and not alert:
        return 'adjudicate'
    confirmed = risk >= pol['highBand'] and not state.get('disagree') and any(
        s['risk'] >= pol['highBand'] and (any(r['sev'] == 'critical' for r in s['rule_hits']) or (s['rule_hits'] and s['llm'] >= 0.8)) for s in segs)
    if confirmed and not alert:
        return 'neutralize'
    if not ctx['can_detonate']:
        return 'adjudicate'
    chunk = detonation_chunk(segs)
    hist = (state.get('session') or {}).get('window')
    slots = ['A', 'B'] if ctx['cfg']['models'].get('dual', True) else ['A']
    return [Send('decoy', {'slot': s, 'chunk': chunk, 'history': hist}) for s in slots]


def detonation_chunk(segs, limit=6000):
    """Full decoded text (hidden layers included), trimmed around the riskiest segments if long."""
    parts = [triage.text_of(s) for s in segs if not s.get('meta')]
    text = ''.join(parts)
    if len(text) <= limit:
        return text
    hot = sorted(range(len(segs)), key=lambda i: -segs[i].get('risk', 0))[:12]
    return '\n…\n'.join(triage.text_of(segs[i]).strip() for i in sorted(hot))[:limit]


# ---------- ③ detonator ----------
async def decoy_node(state: dict, config):
    ctx = _ctx(config)
    t0 = T()
    task = ctx['task']
    _ev(ctx, 'detonator', 'started', f"Decoy {state['slot']} · fresh canaries · {len(ctx['cfg']['detect']['fakeTools'])} fake tools"
                                      + (f" · replaying {len(state['history'])} prior turns" if state.get('history') else ''))
    d = await detonator.detonate(state['slot'], state['chunk'], task, ctx['cfg'], state.get('history'), ctx['scan_id'], ctx['trace'])
    ctx['llm_calls'] += 0 if d.get('cached') or d['verdict'] == 'error' else 1
    if d['verdict'] == 'error':
        _ev(ctx, 'detonator', 'error', f"Decoy {state['slot']} unavailable: {d['error']}")
    else:
        hits = [k for k, v in d['signals'].items() if v]
        _ev(ctx, 'detonator', 'signal' if hits else 'decision',
            f"{d['model'].split('/')[-1]}: {', '.join(_sig_label(k, d['signals'][k]) for k in hits) or 'no signals'} → {d['verdict']}"
            + (' (cached)' if d['cached'] else ''))
    ctx['timings']['detonation'] = max(ctx['timings'].get('detonation', 0), int((T() - t0) * 1000))
    return {'detonations': [d]}


def _sig_label(k, v):
    if k == 'tool_fired':
        return 'tool_fired ' + ', '.join(f"{a['tool']}({', '.join(f'{x}={str(y)[:24]}' for x, y in a['args'].items())})" for a in v[:2])
    if k == 'canary_leak':
        return 'canary_leak ' + ', '.join(x.split(':')[0] for x in v)
    return k


async def judge_node(state: S, config):
    ctx = _ctx(config)
    dets = [d for d in state.get('detonations', []) if d['verdict'] != 'error']
    if not dets:
        _ev(ctx, 'detonator', 'decision', 'All decoys unavailable → failure policy')
        return {'det': {'verdict': 'error'}, 'degraded': True}
    strong = any(d['verdict'] == 'malicious' and d['confidence'] >= 0.95 for d in dets)
    if not strong and ctx['cfg']['detect'].get('taskDrift', True) and state.get('risk', 0) >= 0.5:
        d = max(dets, key=lambda x: {'malicious': 3, 'suspicious': 2, 'benign': 1}[x['verdict']])
        j = await detonator.judge_task_drift(d, ctx['cfg'], ctx['scan_id'], ctx['trace'])
        if j:
            ctx['llm_calls'] += 1
            d['signals']['task_drift'] = j['drift']
            if not j['drift'] and not d['signals'].get('persona_drift'):
                d['signals']['kad_missing'] = False  # judge read the output and it stayed on task; a lone dropped token is small-model noise
            d['verdict'], d['confidence'] = detonator.verdict_of(d['signals'])
            _ev(ctx, 'detonator', 'signal' if j['drift'] else 'decision', f"Task-drift judge: {'off task' if j['drift'] else 'on task'} · {j['reason']}")
    order = {'malicious': 3, 'suspicious': 2, 'benign': 1}
    top = max(dets, key=lambda d: order[d['verdict']])
    types = list(dict.fromkeys(t for d in dets for t in detonator.attack_types_of(d['signals'])))
    n_mal = sum(d['verdict'] == 'malicious' for d in dets)
    _ev(ctx, 'detonator', 'decision', f"{n_mal}/{len(dets)} decoys malicious → {top['verdict']} · confidence {top['confidence']:.2f}")
    if top['verdict'] in ('malicious', 'suspicious'):
        for s in state['segs']:
            if s.get('f') or s.get('risk', 0) > 0:
                s['by'].extend(f'detonator:{k}' for k, v in top['signals'].items() if v and f'detonator:{k}' not in s['by'])
                s['types'] = list(dict.fromkeys(s['types'] + types))
                s['f'] = s['types'][0] if s['types'] else None
    return {'det': {'verdict': top['verdict'], 'confidence': top['confidence'], 'types': types}, 'segs': state['segs']}


def route_after_judge(state: S, config):
    v = state['det']['verdict']
    if v == 'malicious' or (v == 'suspicious' and _ctx(config)['dest']['risk'] == 'low'):
        return 'neutralize'
    # decoys that resist only clear rule-only flags; a span the LLM classifier independently called injection still gets cut
    if v == 'benign' and any(seg.get('llm', 0) >= 0.5 for seg in state['segs']):
        return 'neutralize'
    return 'adjudicate'


# ---------- ④ neutralizer ----------
async def neutralize_node(state: S, config):
    ctx = _ctx(config)
    t0 = T()
    segs, cfg = state['segs'], ctx['cfg']
    strip = cfg['policy'].get('stripHidden', True)
    passes = state.get('passes', 0)
    if passes == 0 and not any(s.get('f') for s in segs):
        n = await neutralizer.locate(segs, cfg, ctx['scan_id'], ctx['trace'])
        ctx['llm_calls'] += 1
        _ev(ctx, 'neutralizer', 'decision', f'Span locator matched {n} segment(s)')
    removed = [s for s in segs if neutralizer.removable(s, strip)]
    if not removed:
        _ev(ctx, 'neutralizer', 'decision', 'Malicious behaviour but no isolatable span → withhold everything')
        ctx['timings']['neutralize'] = ctx['timings'].get('neutralize', 0) + int((T() - t0) * 1000)
        return {'quarantine': True, 'passes': passes + 1}
    rest = [dict(s) for s in segs if not neutralizer.removable(s, strip)]
    re_risk = sentinel.static_scan(rest, cfg)
    kept = sum(len(s['t'].strip()) for s in rest if not s.get('meta'))
    dirty = re_risk >= _low(ctx)
    _ev(ctx, 'neutralizer', 'signal' if dirty else 'decision', f'Pass {passes + 1}: removed {len(removed)} span(s) · re-scan risk {re_risk:.2f}'
                                                               + (' · still dirty' if dirty else ' · clean') + f' · {kept} chars kept')
    if dirty:  # mark what still fires so the next pass cuts it
        by_id = {s['id']: s for s in rest}
        for s in segs:
            r = by_id.get(s['id'])
            if r and r['w'] > 0 and r['types']:
                s['f'], s['types'] = r['types'][0], list(dict.fromkeys(s.get('types', []) + r['types']))
                s['by'] = list(dict.fromkeys(s.get('by', []) + r['by']))
    ctx['timings']['neutralize'] = ctx['timings'].get('neutralize', 0) + int((T() - t0) * 1000)
    return {'segs': segs, 'passes': passes + 1, 'quarantine': (dirty and passes + 1 >= 2) or kept <= 20, 'dirty': dirty}


def route_after_neutralize(state: S, config):
    return 'neutralize' if state.get('dirty') and not state.get('quarantine') and state.get('passes', 0) < 2 else 'adjudicate'


# ---------- ⑤ adjudicator ----------
async def adjudicate_node(state: S, config):
    ctx = _ctx(config)
    t0 = T()
    cfg, req, dest, pol = ctx['cfg'], state['req'], ctx['dest'], ctx['cfg']['policy']
    segs, risk, zone = state.get('segs', []), state.get('risk', 0.0), state.get('zone')
    det = state.get('det') or {}
    strip = pol.get('stripHidden', True)
    hidden = [s for s in segs if triage.is_hidden(s)]
    fail = dest.get('failMode') if dest.get('failMode') in ('open', 'closed') else pol['failHigh' if dest['risk'] == 'high' else 'failLow']
    degraded = bool(state.get('degraded'))
    neutralized = state.get('passes', 0) > 0
    why = None
    if zone == 'oversize':
        verdict, why = 'QUARANTINE', f"File exceeds the {ctx['source'].get('maxMb', 10)} MB source limit and was not forwarded."
    elif zone == 'unparsed':
        verdict = 'ESCALATE' if dest['risk'] == 'high' else 'ALLOW'
        degraded = True
        why = ('The content could not be parsed' + ('; OCR models were unavailable' if any('OCR unavailable' in s['t'] for s in segs) else '') + '; unparsed content to a high-risk destination is held for review.' if verdict == 'ESCALATE'
               else 'The content could not be parsed; allowed as degraded for a low-risk destination.')
    elif neutralized:
        verdict = 'QUARANTINE' if state.get('quarantine') else 'SANITIZE'
        why = None
    elif det.get('verdict') == 'suspicious':
        verdict, why = 'ESCALATE', None
    elif det.get('verdict') == 'benign':
        verdict = 'SANITIZE' if hidden and strip else 'ALLOW'
        why = ('Decoys behaved normally, so the flagged wording was judged benign' + (f'; {len(hidden)} hidden segment(s) were still stripped.' if verdict == 'SANITIZE' else '.'))
    elif risk < _low(ctx) and not state.get('disagree'):
        verdict = 'SANITIZE' if hidden and strip else 'ALLOW'
        why = None
    else:  # gray zone without a behavioural verdict (detonation off, or every LLM failed)
        degraded = True
        verdict = 'ESCALATE' if fail == 'closed' else ('SANITIZE' if any(s.get('f') for s in segs) or hidden else 'ALLOW')

    types = list(dict.fromkeys(t for s in segs for t in s.get('types', []) if s.get('risk', 0) > 0 or s.get('f'))) + \
        [t for t in det.get('types', []) if verdict != 'ALLOW']
    types = list(dict.fromkeys(types))
    if verdict == 'ALLOW' and det.get('verdict') == 'benign':
        types = []
    taint_id = 'tnt_' + uuid.uuid4().hex[:6]
    sanitized = ''
    if verdict in ('ALLOW', 'SANITIZE'):
        body = neutralizer.cut(segs, strip) if verdict == 'SANITIZE' else ''.join(s['t'] for s in segs if not s.get('meta'))
        sanitized = neutralizer.spotlight(body, req['channel'], taint_id) if dest.get('spotlight', True) else body
    full_text = '\n'.join(triage.text_of(s) for s in segs)
    store.put('taint', taint_id, {'id': taint_id, 'scan_id': ctx['scan_id'], 'text': full_text[:50000], 'entities': neutralizer.entities(full_text)})

    tlist, hid = ', '.join(types) or 'none', ', '.join(dict.fromkeys(s['h'] for s in hidden))
    n_cut = sum(1 for s in segs if neutralizer.removable(s, strip))
    kept = sum(len(s['t'].strip()) for s in segs if not neutralizer.removable(s, strip) and not s.get('meta'))
    if why is None:
        if verdict == 'ALLOW':
            why = (f"No instructions aimed at an AI across {len(segs)} segments; decided in {int((T() - ctx['t0']) * 1000)} ms with {ctx['llm_calls']} LLM call(s).")
        elif verdict == 'SANITIZE' and not any(s.get('f') for s in segs):
            why = f'No instructions found, but {len(hidden)} hidden segment(s) ({hid}) were stripped per policy.'
        elif verdict == 'SANITIZE':
            why = (f"{n_cut} span(s) carried instructions aimed at the AI ({tlist})" + (f", including hidden {hid} text" if hid else '')
                   + (f"; {sum(d['verdict'] == 'malicious' for d in state.get('detonations', []))} decoy(s) acted on them" if det.get('verdict') == 'malicious' else '')
                   + f". They were cut and {kept} characters of content kept." + (' Marked degraded: no behavioural verdict.' if degraded else ''))
        elif verdict == 'QUARANTINE':
            why = f'Instructions aimed at the AI ({tlist}) could not be separated from the content; nothing was forwarded.'
        elif det.get('verdict') == 'suspicious':
            why = f'Decoys showed only weak signals ({tlist}) on a high-risk destination; held for human review.'
        else:
            why = (f'Risk {risk:.2f} sits in the gray zone ({tlist}) and no behavioural verdict was available; '
                   f"held for review because the destination fails closed.")

    review_id = None
    if verdict == 'ESCALATE':
        review_id = 'rev_' + uuid.uuid4().hex[:6]
        ev = [f"{s['loc']}: “{triage.text_of(s).strip()[:140]}”" for s in segs if s.get('risk', 0) > 0][:3]
        ev += [f"{d['model'].split('/')[-1]}: {', '.join(k for k, v in d['signals'].items() if v) or 'no signals'}" for d in state.get('detonations', []) if d['verdict'] != 'error']
        store.put('review', review_id, {'id': review_id, 'kind': 'Escalated verdict', 'title': state['meta']['title'], 'scan_id': ctx['scan_id'],
                                        'src': f"{req['fmt']} · {dest['id']} ({dest['risk']})", 'why': why, 'ev': ev or [f'risk {risk:.2f}'],
                                        'suggest': 'Deny and keep withheld' if risk >= 0.5 else 'Approve sanitized content', 'status': 'pending',
                                        'created_at': time.time(), 'release': neutralizer.cut(segs, strip)})
    emit_msg = f"{verdict}{' · degraded' if degraded else ''} · taint {taint_id}" + (f' · review {review_id}' if review_id else '')
    _ev(ctx, 'adjudicator', 'completed', emit_msg)
    ctx['timings']['adjudicate'] = int((T() - t0) * 1000)
    ctx['result'] = {'verdict': verdict, 'why': why, 'types': types, 'degraded': degraded, 'taint_id': taint_id, 'review_id': review_id,
                     'sanitized': sanitized, 'risk': risk}
    return {}


def _build():
    g = StateGraph(S)
    for name, fn in [('triage', triage_node), ('sentinel', sentinel_node), ('session', session_node), ('decoy', decoy_node),
                     ('judge', judge_node), ('neutralize', neutralize_node), ('adjudicate', adjudicate_node)]:
        g.add_node(name, fn)
    g.add_edge(START, 'triage')
    g.add_edge('triage', 'sentinel')
    g.add_edge('sentinel', 'session')
    g.add_conditional_edges('session', route, ['adjudicate', 'neutralize', 'decoy'])
    g.add_edge('decoy', 'judge')
    g.add_conditional_edges('judge', route_after_judge, ['neutralize', 'adjudicate'])
    g.add_conditional_edges('neutralize', route_after_neutralize, ['neutralize', 'adjudicate'])
    g.add_edge('adjudicate', END)
    return g.compile()


GRAPH = _build()


async def scan(cfg, data: bytes, name: str, fmt: str | None = None, *, channel=None, destination=None, source='playground',
               task=None, session_id=None, user=None, options=None, cfg_version=None):
    """Run the graph and return a ScanResponse dict (spec §6.5, plus UI fields). Also stores it in the audit log."""
    options = options or {}
    src = {**(cfg['sources'].get(source) or cfg['sources'].get('playground') or {}), 'id': source}
    dest_id = (destination or {}).get('name') or src.get('destination') or 'rm-copilot'
    dest = {**(cfg['destinations'].get(dest_id) or {'name': dest_id, 'risk': 'high', 'tools': [], 'task': cfg['detect']['decoyTask']}), 'id': dest_id}
    if (destination or {}).get('risk') in ('low', 'high'):
        dest['risk'] = destination['risk']
    fmt = fmt if fmt and fmt != 'auto' else triage.detect_format(name, None if name.lower().endswith(('.pdf', '.docx', '.png', '.jpg', '.jpeg')) else data[:4000].decode('utf-8', 'replace'))
    scan_id = 'scn_' + uuid.uuid4().hex[:6]
    ctx = {'scan_id': scan_id, 'trace': [], 'cfg': cfg, 'dest': dest, 'source': src, 'opts': options, 'timings': {}, 'llm_calls': 0, 't0': T(),
           'task': task or dest.get('task') or cfg['detect']['decoyTask'],
           'can_detonate': options.get('detonate', True) and not options.get('sentinel_only') and dest.get('detonate', True)}
    req = {'data': data, 'name': name, 'fmt': fmt, 'channel': channel or src.get('channel', 'retrieved'), 'session_id': session_id, 'user': user}
    final = await GRAPH.ainvoke({'req': req, 'detonations': []}, config={'configurable': {'ctx': ctx}})
    r = ctx['result']
    segs = final.get('segs', [])
    ctx['timings']['total'] = int((T() - ctx['t0']) * 1000)
    resp = {
        'scan_id': scan_id, 'verdict': r['verdict'], 'risk': r['risk'], 'attack_types': r['types'], 'degraded': r['degraded'],
        'reason': r['why'], 'title': final['meta']['title'], 'filename': name, 'content_type': fmt, 'size_bytes': len(data),
        'source': src.get('name', source), 'source_id': source, 'destination': {'name': dest_id, 'risk': dest['risk'], 'tools': dest.get('tools', [])},
        'channel': req['channel'], 'task': ctx['task'], 'session_id': session_id, 'created_at': time.time(), 'config_version': cfg_version,
        'llm_calls': ctx['llm_calls'],
        'segments': [{'id': s['id'], 'location': s['loc'], 'text': s['t'], 'decoded_text': s.get('dec'),
                      'visibility': f"hidden:{s['h']}" if triage.is_hidden(s) else (s['h'] or 'visible'), 'encodings': s.get('encodings', []),
                      'finding': s.get('f'), 'risk': s.get('risk', 0), 'meta': bool(s.get('meta'))} for s in segs],
        'findings': [{'segment_id': s['id'], 'location': s['loc'], 'text': triage.text_of(s).strip()[:300], 'attack_types': s['types'] or ['T9 indirect'],
                      'detected_by': list(dict.fromkeys(s['by'] + ([f"triage:hidden:{s['h']}"] if triage.is_hidden(s) else []) + [f'decoder:{e}' for e in s.get('encodings', [])])),
                      'confidence': s['risk'], 'rationale': s.get('why')} for s in segs if s.get('risk', 0) > 0],
        'detonations': final.get('detonations', []),
        'sanitized_content': r['sanitized'], 'system_addendum': neutralizer.SYSTEM_ADDENDUM if r['sanitized'] else None,
        'taint_id': r['taint_id'], 'review_id': r['review_id'], 'session': final.get('session'),
        'timings_ms': {k: ctx['timings'].get(k, 0) for k in ('triage', 'sentinel', 'detonation', 'neutralize', 'adjudicate', 'total')},
        'trace': ctx['trace'],
    }
    if not options.get('ephemeral'):
        store.put('scan', scan_id, resp)
    return resp

"""Tripwire API (spec §8) + demo endpoints + static console."""
import asyncio
import ipaddress
import json
import os
import secrets
import socket
import statistics
import time
import urllib.parse
import uuid
from datetime import datetime

import httpx
from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

from . import corpus, demo, evals, events, guard, llm, pipeline, store, triage
from .config import (AGENT_MODELS, BENIGN, DECOY_A_MODELS, DECOY_B_MODELS, DEFAULT_CONFIG, OPENROUTER_API_KEY, SENTINEL_MODELS,
                     VISION_MODELS)
from .sentinel import similarity

app = FastAPI(title='Tripwire', version='1.0')


# ---------- config versions ----------
def current():
    v = store.list('config', limit=1)
    if not v:
        v = [store.put('config', '000001', {'v': 1, 'by': 'system', 'at': time.time(), 'note': 'Seed config (rules.yaml, tools.yaml, policy)', 'snap': DEFAULT_CONFIG})]
    return v[0]


def publish(cfg, note, by='ananya.rao'):
    n = current()['v'] + 1
    return store.put('config', f'{n:06d}', {'v': n, 'by': by, 'at': time.time(), 'note': note or 'No description', 'snap': cfg})


@app.on_event('startup')
async def _startup():
    current()
    corpus.manifest()


@app.get('/v1/config')
def get_config():
    c = current()
    return {'version': c['v'], 'by': c['by'], 'at': c['at'], 'config': c['snap'], 'benign': BENIGN}


@app.post('/v1/config/publish')
async def post_publish(body: dict):
    cfg = body.get('config')
    if not isinstance(cfg, dict) or 'policy' not in cfg or 'rules' not in cfg:
        raise HTTPException(400, 'config must include policy and rules')
    v = publish(cfg, body.get('note', ''))
    events.emit('adjudicator', 'decision', f"Config v{v['v']} published · {v['note']}")
    await notify('config_published', {'version': v['v'], 'note': v['note']})
    return {'version': v['v']}


@app.get('/v1/config/versions')
def versions():
    return store.list('config', newest_first=False)


# ---------- scan ----------
def _pin_public(url):
    """Resolve once; refuse unless every address is public, then pin the request to that address.
    Connecting to the checked IP (Host header + TLS SNI keep the real name) closes the DNS-rebinding gap."""
    p = urllib.parse.urlparse(url)
    if p.scheme not in ('http', 'https') or not p.hostname:
        return None
    try:
        infos = socket.getaddrinfo(p.hostname, p.port or (443 if p.scheme == 'https' else 80), proto=socket.IPPROTO_TCP)
    except (socket.gaierror, UnicodeError):
        return None
    ips = sorted({i[4][0] for i in infos})
    if not ips or any(not ipaddress.ip_address(ip).is_global for ip in ips):
        return None
    host = f'[{ips[0]}]' if ':' in ips[0] else ips[0]
    port = f':{p.port}' if p.port else ''
    return (p._replace(netloc=host + port).geturl(), {'Host': p.hostname + port}, {'sni_hostname': p.hostname})


async def fetch_url(url):
    """Server-side fetch for 'Fetch URL'. Refuses non-http(s) and private/loopback targets (SSRF)."""
    pin = _pin_public(url)
    if not pin:
        raise HTTPException(400, 'Only public http(s) URLs can be fetched')
    target, headers, ext = pin
    body = bytearray()
    async with httpx.AsyncClient(timeout=10, follow_redirects=False) as c:
        async with c.stream('GET', target, headers={**headers, 'User-Agent': 'Tripwire-fetcher/1.0'}, extensions=ext) as r:
            if r.status_code >= 400:
                raise HTTPException(400, f'Fetch failed: HTTP {r.status_code}')
            async for chunk in r.aiter_bytes():  # stop reading at the cap instead of buffering the whole response
                body += chunk
                if len(body) >= 5_000_000:
                    break
    return bytes(body[:5_000_000])


async def _do_scan(meta, data, name):
    c = current()
    r = await pipeline.scan(c['snap'], data, name, meta.get('content_type'), channel=meta.get('channel'), destination=meta.get('destination'),
                            source=meta.get('source') or 'playground', task=meta.get('task'), session_id=meta.get('session_id'), user=meta.get('user'),
                            options=meta.get('options') or {}, cfg_version=c['v'])
    if r['verdict'] in ('QUARANTINE', 'ESCALATE'):
        asyncio.create_task(notify(r['verdict'], {'scan_id': r['scan_id'], 'reason': r['reason']}))
    return r


@app.post('/v1/scan')
async def scan(request: Request):
    ct = request.headers.get('content-type', '')
    if ct.startswith('multipart/'):
        form = await request.form()
        f = form.get('file')
        if f is None:
            raise HTTPException(400, 'multipart scan needs a file field')
        meta = json.loads(form.get('meta') or '{}')
        data, name = await f.read(), f.filename or 'upload'
    else:
        meta = await request.json()
        if meta.get('url'):
            data, name = await fetch_url(meta['url']), meta['url']
            meta.setdefault('content_type', 'html')
            meta.setdefault('source', 'web')
        else:
            data, name = str(meta.get('content') or '').encode(), meta.get('filename') or 'pasted text'
    if not data.strip():
        raise HTTPException(400, 'Nothing to scan')
    return await _do_scan(meta, data, name)


@app.get('/v1/scans')
def scans(limit: int = 300):
    keep = ('scan_id', 'verdict', 'risk', 'attack_types', 'title', 'source', 'destination', 'created_at', 'content_type', 'degraded', 'llm_calls', 'timings_ms')
    return [{k: s.get(k) for k in keep} for s in store.list('scan', limit=limit)]


@app.get('/v1/scans/{sid}')
def scan_detail(sid: str):
    s = store.get('scan', sid)
    if not s:
        raise HTTPException(404)
    return s


@app.post('/v1/scans/{sid}/false-positive')
def false_positive(sid: str):
    s = scan_detail(sid)
    s['false_positive'] = True
    store.put('scan', sid, s)
    store.put('devset', sid, {'id': sid, 'text': '\n'.join(x['decoded_text'] or x['text'] for x in s['segments']), 'label': 0})
    return {'ok': True}


@app.post('/v1/scans/{sid}/memory')
def propose_memory(sid: str):
    s = scan_detail(sid)
    f = max(s['findings'], key=lambda x: x['confidence'], default=None)
    if not f:
        raise HTTPException(400, 'This scan has no findings to learn from')
    return {'review_id': memory_proposal(f['text'], f['attack_types'][0], f'scan {sid}')}


def memory_proposal(text, attack_type, src, run_id=None):
    sim = max(similarity(text, b) for b in BENIGN)
    rid = 'rev_' + uuid.uuid4().hex[:6]
    store.put('review', rid, {'id': rid, 'kind': 'Memory proposal', 'title': text[:80], 'src': src, 'text': text, 'type': attack_type, 'run_id': run_id,
                              'why': f'Nearest hard negative similarity {sim:.2f}' + (' · at or above 0.85, auto-rejected to protect FPR' if sim >= 0.85 else ', below the 0.85 rejection line.'),
                              'ev': [f'“{text[:160]}”', f'attack type: {attack_type}'], 'suggest': 'Reject' if sim >= 0.85 else 'Approve',
                              'status': 'denied' if sim >= 0.85 else 'pending', 'auto': sim >= 0.85, 'note': 'auto-rejected' if sim >= 0.85 else '',
                              'created_at': time.time(), 'benign_sim': round(sim, 2)})
    return rid


# ---------- events ----------
@app.get('/v1/events')
async def sse(request: Request, scan_id: str | None = None):
    q = events.subscribe()

    async def gen():
        try:
            for ev in list(events.recent)[-40:]:
                if not scan_id or ev['scan_id'] == scan_id:
                    yield f'data: {json.dumps(ev, ensure_ascii=False)}\n\n'
            while not await request.is_disconnected():
                try:
                    ev = await asyncio.wait_for(q.get(), 15)
                except asyncio.TimeoutError:
                    yield ': keepalive\n\n'
                    continue
                if not scan_id or ev['scan_id'] == scan_id:
                    yield f'data: {json.dumps(ev, ensure_ascii=False)}\n\n'
        finally:
            events.unsubscribe(q)
    return StreamingResponse(gen(), media_type='text/event-stream', headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'})


# ---------- guard + sessions ----------
@app.post('/v1/guard/tool-call')
def tool_call(body: dict):
    cfg = body.get('config') or current()['snap']  # 'config' lets the console test a draft
    taints = [store.get('taint', t) for t in body.get('taint_ids') or []]
    text = '\n'.join(t['text'] for t in taints if t) + ('\n' + body['taint_text'] if body.get('taint_text') else '')
    args = body.get('args') or {}
    g = guard.evaluate(cfg, body.get('tool', ''), args, body.get('user_request', ''), text)
    demo.log_toolcall(body.get('session_id') or 'api', body.get('tool', ''), args, g)
    rid = demo.create_tool_review(body.get('tool', ''), args, g, f"guard · {body.get('session_id') or 'api'}") if g['decision'] == 'require_approval' else None
    events.emit('guard', 'decision', f"{body.get('tool')} → {g['decision']} ({g['reason']})")
    return {**g, 'review_id': rid}


@app.get('/v1/toolcalls')
def toolcalls():
    return store.list('toolcall', limit=500)


@app.get('/v1/sessions')
def sessions():
    pol = current()['snap']['policy']
    return [{**s, 'calc': guard.session_risk(s['turns'], pol)} for s in store.list('session', limit=200)]


@app.post('/v1/sessions/{sid}/turns')
async def session_turn(sid: str, body: dict):
    text = str(body.get('text') or '').strip()
    if not text:
        raise HTTPException(400, 'text required')
    meta = {'content_type': 'chat', 'source': 'chat', 'channel': 'user', 'session_id': sid, 'user': body.get('user', 'console'),
            'destination': {'name': body.get('destination') or (store.get('session', sid) or {}).get('dest') or 'support-bot'}}
    return await _do_scan(meta, text.encode(), f'{sid} turn')


# ---------- reviews ----------
@app.get('/v1/reviews')
def reviews(status: str | None = None):
    rs = store.list('review', limit=500)
    return [r for r in rs if not status or r['status'] == status or (status == 'resolved' and r['status'] != 'pending')]


@app.post('/v1/reviews/{rid}')
async def decide(rid: str, body: dict):
    r = store.get('review', rid)
    if not r:
        raise HTTPException(404)
    d, note = body.get('decision'), str(body.get('note') or '').strip()
    if d == 'reopen':
        r.update(status='pending', note='', decided_at=None)
        return store.put('review', rid, r)
    if d not in ('approve', 'deny'):
        raise HTTPException(400, 'decision must be approve, deny or reopen')
    if d == 'deny' and not note:
        raise HTTPException(400, 'A note is required to deny')
    r.update(status='approved' if d == 'approve' else 'denied', note=note, decided_at=time.time(), decided_by=body.get('by', 'ananya.rao'))
    if r['kind'] == 'Memory proposal' and d == 'approve':
        cfg = json.loads(json.dumps(current()['snap']))
        n = max([int(m['id'].split('-')[1]) for m in cfg['memory'] if m['id'].startswith('M-')] or [0]) + 1
        cfg['memory'].append({'id': f'M-{n:03d}', 'type': r['type'], 'text': r['text'], 'source': 'mutator' if r.get('run_id') else 'review',
                              'added': datetime.now().date().isoformat(), 'note': f'approved in {rid}'})
        v = publish(cfg, f'Approve memory entry M-{n:03d} ({rid})', r['decided_by'])
        r['memory_id'] = f'M-{n:03d}'
        if r.get('run_id'):
            asyncio.create_task(retest(r['run_id']))
        events.emit('adjudicator', 'decision', f"Memory M-{n:03d} approved → config v{v['v']}")
    if r['kind'] == 'Escalated verdict':
        s = store.get('scan', r['scan_id'])
        if s:
            s['review_decision'] = r['status']
            if d == 'approve':
                s['released_content'] = r.get('release')
            store.put('scan', s['scan_id'], s)
    return store.put('review', rid, r)


# ---------- red team (user-supplied variants) ----------
@app.post('/v1/redteam/run')
async def redteam(body: dict):
    variants = [v for v in body.get('variants') or [] if isinstance(v, dict) and str(v.get('text', '')).strip()][:40]
    if not variants:
        raise HTTPException(400, 'Provide variants: [{"label": "...", "text": "..."}]')
    run_id = 'rt_' + uuid.uuid4().hex[:5]
    doc = {'id': run_id, 'seed': body.get('seed', ''), 'attack_type': body.get('attack_type', 'T1 instruction override'), 'status': 'running', 'created_at': time.time(),
           'variants': [{'label': v.get('label') or f'variant {i + 1}', 'text': v['text'], 'result': 'Queued'} for i, v in enumerate(variants)]}
    store.put('redteam', run_id, doc)
    asyncio.create_task(_run_variants(run_id, first=True))
    return doc


async def _run_variants(run_id, first):
    doc = store.get('redteam', run_id)
    cfg, sem = current()['snap'], asyncio.Semaphore(3)

    async def one(v):
        async with sem:
            r = await pipeline.scan(cfg, v['text'].encode(), 'variant.txt', None, destination={'name': 'rm-copilot'}, source='upload',
                                    options={'sentinel_only': True, 'ephemeral': True})
        blocked = r['verdict'] != 'ALLOW'
        by = sorted({b.split(':')[0] + (':' + b.split(':')[1] if b.startswith(('rule', 'memory')) else '') for f in r['findings'] for b in f['detected_by']})
        v.update({'result' if first else 'after': 'Blocked' if blocked else 'Bypass', 'by': ', '.join(by[:3]) or '—'})
    await asyncio.gather(*(one(v) for v in doc['variants'] if first or v.get('result') == 'Bypass'))
    n = len(doc['variants'])
    if first:
        doc['before'] = sum(v['result'] == 'Blocked' for v in doc['variants']) / n
        for v in doc['variants']:
            if v['result'] == 'Bypass':
                v['proposal'] = memory_proposal(v['text'], doc['attack_type'], f'red team · {run_id}', run_id)
    doc['after'] = sum(v['result'] == 'Blocked' or v.get('after') == 'Blocked' for v in doc['variants']) / n
    doc['status'] = 'complete'
    store.put('redteam', run_id, doc)
    if first and any(v['result'] == 'Bypass' for v in doc['variants']):
        await notify('bypass', {'run_id': run_id})


async def retest(run_id):
    await _run_variants(run_id, first=False)


@app.get('/v1/redteam/runs')
def redteam_runs():
    return store.list('redteam', limit=20)


# ---------- evals + metrics ----------
@app.post('/v1/evals/corpus')
async def eval_corpus(body: dict | None = None):
    c = current()
    return await evals.run(c['snap'], c['v'], 'corpus', f'corpus · frozen {corpus.frozen_hash()[:8]}', evals.corpus_items(), (body or {}).get('options') or {})


@app.post('/v1/evals/dataset')
async def eval_dataset(file: UploadFile = File(...), mode: str = Form('sentinel_only')):
    try:
        items = evals.dataset_items((await file.read()).decode('utf-8', 'replace'))
    except ValueError as e:
        raise HTTPException(400, f'Could not parse dataset: {e}')
    if not items:
        raise HTTPException(400, 'No rows with a text field')
    c = current()
    return await evals.run(c['snap'], c['v'], 'dataset', file.filename, items, {'sentinel_only': mode == 'sentinel_only'})


@app.get('/v1/evals')
def eval_runs():
    return [{k: v for k, v in e.items() if k != 'rows'} for e in store.list('eval', limit=30)]


@app.get('/v1/evals/{eid}')
def eval_run(eid: str):
    return store.get('eval', eid) or JSONResponse({'detail': 'not found'}, 404)


@app.get('/v1/corpus')
def corpus_list():
    return {'frozen_hash': corpus.frozen_hash(), 'items': corpus.manifest()}


@app.get('/v1/corpus/{cid}/file')
def corpus_file(cid: str):
    m, _ = corpus.load(cid)
    return FileResponse(os.path.join(corpus.CORPUS_DIR, m['file']), filename=m['file'])


@app.get('/v1/metrics')
def metrics():
    ss = store.list('scan', limit=5000)
    now = time.time()
    day = [s for s in ss if now - s['created_at'] < 86400]
    mix = {v: sum(s['verdict'] == v for s in day) for v in ('ALLOW', 'SANITIZE', 'QUARANTINE', 'ESCALATE')}
    pct = lambda xs, q: (sorted(xs)[min(len(xs) - 1, int(len(xs) * q))] if xs else 0)
    stage = {k: [s['timings_ms'].get(k, 0) for s in day if s['timings_ms'].get(k)] for k in ('triage', 'sentinel', 'detonation', 'total')}
    hours = []
    for h in range(23, -1, -1):
        b = [s for s in day if h * 3600 <= now - s['created_at'] < (h + 1) * 3600]
        hours.append({'cpu': sum(not s['llm_calls'] for s in b), 'llm': sum(bool(s['llm_calls']) for s in b)})
    ev = next((e for e in store.list('eval', limit=30) if e['status'] == 'complete' and e['kind'] == 'corpus'), None)
    return {'scans_24h': len(day), 'scans_total': store.count('scan'), 'mix': mix, 'threats': mix['SANITIZE'] + mix['QUARANTINE'] + mix['ESCALATE'],
            'cpu_share': (sum(not s['llm_calls'] for s in day) / len(day)) if day else None,
            'latency': {k: {'p50': pct(v, .5), 'p95': pct(v, .95)} for k, v in stage.items()}, 'hours': hours,
            'pending_reviews': sum(r['status'] == 'pending' for r in store.list('review', limit=1000)),
            'oldest_pending': min([r['created_at'] for r in store.list('review', limit=1000) if r['status'] == 'pending'] or [None], key=lambda x: x or now),
            'latest_corpus_eval': ev and {k: v for k, v in ev.items() if k != 'rows'}, 'frozen_hash': corpus.frozen_hash(), 'corpus_n': len(corpus.manifest())}


@app.get('/v1/health')
def health():
    roles = [(SENTINEL_MODELS, 'Sentinel · neutralizer · judge'), (DECOY_A_MODELS, 'Detonation A'), (DECOY_B_MODELS, 'Detonation B'),
             (VISION_MODELS, 'Vision OCR'), (AGENT_MODELS, 'Arena RM Copilot')]
    models = []
    for ms, role in roles:
        for i, m in enumerate(ms):
            h = llm.health[m]
            lat = list(h['lat'])
            models.append({'model': m, 'role': role + (' · fallback' if i else ''), 'breaker': llm.breaker_state(m), 'calls': h['calls'], 'errors': h['errors'],
                           'last_error': h['last_error'], 'p50': statistics.median(lat) if lat else None})
    return {'status': 'ok', 'llm_configured': bool(OPENROUTER_API_KEY), 'models': models, 'cache_entries': store.cache_stats(),
            'cache_hits': llm.counters['cache_hits'], 'llm_calls': llm.counters['calls'], 'config_version': current()['v']}


# ---------- keys + webhooks ----------
@app.get('/v1/keys')
def keys():
    return store.list('key')


@app.post('/v1/keys')
def create_key(body: dict):
    if not str(body.get('name', '')).strip() or not body.get('scopes'):
        raise HTTPException(400, 'name and scopes required')
    secret = 'tw_live_' + secrets.token_hex(16)
    k = {'id': 'k_' + uuid.uuid4().hex[:6], 'name': body['name'].strip(), 'prefix': secret[:12] + '…', 'scopes': body['scopes'], 'expiry': body.get('expiry', '90'),
         'created_at': time.time(), 'last_used': None, 'status': 'active'}
    store.put('key', k['id'], k)
    return {**k, 'secret': secret}  # keys are issued and listed, not enforced (auth is a declared non-goal)


@app.post('/v1/keys/{kid}/revoke')
def revoke_key(kid: str):
    k = store.get('key', kid) or {}
    k['status'] = 'revoked'
    return store.put('key', kid, k)


@app.get('/v1/webhooks')
def hooks():
    return store.list('hook')


@app.post('/v1/webhooks')
def add_hook(body: dict):
    url = str(body.get('url', ''))
    if not body.get('events'):
        raise HTTPException(400, 'events required')
    if not _pin_public(url):  # same SSRF gate as Fetch URL: the server POSTs to this address
        raise HTTPException(400, 'Webhook URL must be a public http(s) address')
    h = {'id': 'h_' + uuid.uuid4().hex[:6], 'url': url, 'events': body['events'], 'last': 'never'}
    return store.put('hook', h['id'], h)


@app.delete('/v1/webhooks/{hid}')
def del_hook(hid: str):
    store.delete('hook', hid)
    return {'ok': True}


@app.post('/v1/webhooks/{hid}/test')
async def test_hook(hid: str):
    h = store.get('hook', hid)
    if not h:
        raise HTTPException(404)
    await _deliver(h, {'event': 'test', 'source': 'tripwire'})
    return store.get('hook', hid)


async def _deliver(h, payload):
    pin = _pin_public(h['url'])  # re-checked per delivery: DNS may have changed since the hook was added
    if not pin:
        h['last'] = 'blocked · not a public address'
        store.put('hook', h['id'], h)
        return
    target, headers, ext = pin
    try:
        async with httpx.AsyncClient(timeout=5, follow_redirects=False) as c:
            r = await c.post(target, headers=headers, extensions=ext, json={**payload, 'ts': time.time()})
        h['last'] = f'{r.status_code} · {datetime.now():%H:%M}'
    except httpx.HTTPError as e:
        h['last'] = f'failed · {type(e).__name__}'
    store.put('hook', h['id'], h)


async def notify(event, payload):
    for h in store.list('hook'):
        if event in h['events']:
            await _deliver(h, {'event': event, **payload})


# ---------- demo / arena ----------
@app.get('/demo/inbox')
def demo_inbox():
    return demo.inbox()


@app.post('/demo/inbox')
async def demo_add(file: UploadFile = File(...)):
    data = await file.read()
    iid = 'U' + uuid.uuid4().hex[:4]
    fmt = triage.detect_format(file.filename, None if file.filename.lower().endswith(('.pdf', '.docx', '.png', '.jpg', '.jpeg')) else data[:4000].decode('utf-8', 'replace'))
    store.put('inbox_blob', iid, {'hex': data.hex()})
    return store.put('inbox', iid, {'id': iid, 'from': 'uploaded', 'subj': file.filename, 'fmt': fmt, 'file': file.filename})


@app.delete('/demo/inbox/{iid}')
def demo_del(iid: str):
    store.delete('inbox', iid)
    store.delete('inbox_blob', iid)
    return {'ok': True}


@app.post('/demo/agent/run')
async def demo_run(body: dict):
    c = current()

    async def gen():
        async for ev in demo.run(c['snap'], bool(body.get('firewall', True)), body.get('item_ids'), c['v']):
            yield f'data: {json.dumps(ev, ensure_ascii=False)}\n\n'
    return StreamingResponse(gen(), media_type='text/event-stream', headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'})


@app.get('/attacker/collect')
def collect(d: str = ''):
    store.put('loot', uuid.uuid4().hex[:8], {'run_id': 'beacon', 'what': d[:200], 'via': 'GET /attacker/collect'})
    return {'ok': True}


@app.get('/attacker/loot')
def loot(run_id: str | None = None):
    return [x for x in store.list('loot', limit=200) if not run_id or x['run_id'] == run_id]


# ---------- console ----------
DIST = os.environ.get('FRONTEND_DIST', os.path.join(os.path.dirname(__file__), '..', '..', 'frontend', 'dist'))
if os.path.isdir(DIST):
    app.mount('/assets', StaticFiles(directory=os.path.join(DIST, 'assets')), name='assets')

    @app.get('/{path:path}', include_in_schema=False)
    def spa(path: str):
        root = os.path.realpath(DIST)
        f = os.path.realpath(os.path.join(root, path))
        ok = path and f.startswith(root + os.sep) and os.path.isfile(f)
        return FileResponse(f if ok else os.path.join(root, 'index.html'))

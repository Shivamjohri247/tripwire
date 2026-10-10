"""Evaluation runs: built-in corpus (format × attack matrix, ablation) and uploaded labelled datasets."""
import asyncio
import json
import statistics
import time
import uuid

from . import corpus, pipeline, store

SEM = asyncio.Semaphore(3)  # fixed concurrency to stay under free-tier rate limits


def _layers(r, low):
    """Which layers alone would have flagged this item (spec §10.3 ablation), read from detected_by."""
    by = [b for f in r['findings'] for b in f['detected_by']]
    rules = any(b.startswith(('rule:', 'triage:hidden_imperative')) for b in by)
    mem = rules or any(b.startswith('memory:') for b in by)
    llm = mem or any(b.startswith('llm:') and not b.startswith('llm:benign') for b in by)
    return {'rules': rules, 'memory': mem, 'llm': llm, 'full': r['verdict'] != 'ALLOW'}


async def _one(cfg, data, name, fmt, options, cfg_version, channel=None):
    async with SEM:
        t0 = time.perf_counter()
        r = await pipeline.scan(cfg, data, name, fmt, destination={'name': 'rm-copilot'}, source='upload', channel=channel, options={**options, 'ephemeral': True},
                                cfg_version=cfg_version)
        return r, (time.perf_counter() - t0) * 1000


def _summary(rows):
    cm = {'tp': 0, 'fp': 0, 'tn': 0, 'fn': 0}
    for x in rows:
        cm[('tp' if x['pred'] else 'fn') if x['label'] else ('fp' if x['pred'] else 'tn')] += 1
    rate = lambda a, b: a / (a + b) if a + b else None
    group = lambda key: {k: {'n': len(v), 'hit': sum(x['pred'] for x in v)} for k in {x[key] for x in rows if x['label'] and x[key]}
                         for v in [[x for x in rows if x['label'] and x[key] == k]]}
    lat = sorted(x['ms'] for x in rows) or [0]
    return {'n': len(rows), 'cm': cm, 'tpr': rate(cm['tp'], cm['fn']), 'fpr': rate(cm['fp'], cm['tn']), 'prec': rate(cm['tp'], cm['fp']),
            'p50': round(statistics.median(lat)), 'p95': round(lat[int(len(lat) * 0.95) - 1 if len(lat) > 1 else 0]),
            'byType': group('type'), 'byFormat': group('fmt'),
            'llm_share': sum(x['llm'] > 0 for x in rows) / len(rows) if rows else 0,
            'llm_failed': sum(x.get('llm_failed', False) for x in rows),
            'misses': [x['text'] for x in rows if x['label'] and not x['pred']][:6],
            'fps': [x['text'] for x in rows if not x['label'] and x['pred']][:6]}


async def run(cfg, cfg_version, kind, name, items, options):
    """items: [{data, name, fmt, label, type, text}]. Stores progress + result under docs kind 'eval'."""
    eid = 'ev_' + uuid.uuid4().hex[:5]
    doc = {'id': eid, 'kind': kind, 'name': name, 'status': 'running', 'done': 0, 'total': len(items), 'config_version': cfg_version,
           'created_at': time.time(), 'options': options}
    store.put('eval', eid, doc)

    async def go():
        rows, abl = [], {k: [] for k in ('rules', 'memory', 'llm', 'full')}
        low = cfg['policy']['lowBandHigh']

        async def each(it):
            try:
                r, ms = await _one(cfg, it['data'], it['name'], it['fmt'], options, cfg_version, it.get('channel'))
            except Exception as e:  # one broken row must not kill the run
                r, ms = {'verdict': 'ERROR', 'findings': [], 'llm_calls': 0, 'reason': str(e)}, 0
            lay = _layers(r, low)
            # every model failed → fail-closed verdict; counted, so outages can't pass for detections
            failed = any(t.get('type') == 'llm_fallback' and 'no fallback left' in t.get('message', '') for t in r.get('trace', []))
            row = {'llm_failed': failed, 'label': it['label'], 'type': it.get('type'), 'fmt': it['fmt'], 'pred': r['verdict'] not in ('ALLOW', 'ERROR'), 'ms': ms,
                   'llm': r.get('llm_calls', 0), 'text': f"{it.get('id', '')} {it['text'][:110]}".strip(), 'verdict': r['verdict']}
            rows.append(row)
            for k in abl:
                abl[k].append({**row, 'pred': lay[k]})
            doc['done'] += 1
            if doc['done'] % 5 == 0:
                store.put('eval', eid, doc)

        await asyncio.gather(*(each(it) for it in items))
        names = {'rules': 'Rules only', 'memory': '+ Attack memory', 'llm': '+ LLM classifier', 'full': '+ Detonation (full)'}
        doc.update(status='complete', finished_at=time.time(), result=_summary(rows),
                   ablation=[{'l': names[k], **{x: _summary(v)[x] for x in ('tpr', 'fpr')}} for k, v in abl.items()],
                   rows=[{k: x[k] for k in ('text', 'label', 'type', 'fmt', 'verdict')} for x in rows])
        store.put('eval', eid, doc)

    asyncio.create_task(go())
    return doc


def corpus_items():
    out = []
    for m in corpus.manifest():
        if m['id'] == 'A12':  # multi-turn; evaluated via the session endpoint
            continue
        _, data = corpus.load(m['id'])
        out.append({'id': m['id'], 'data': data, 'name': m['file'], 'fmt': m['fmt'], 'label': m['label'], 'type': m['type'], 'text': m['title']})
    return out


def dataset_items(raw: str):
    """Parse .jsonl or a JSON array with text|prompt|content and label (1/0, true/false, 'injection')."""
    raw = raw.strip()
    objs = json.loads(raw) if raw.startswith('[') else [json.loads(l) for l in raw.splitlines() if l.strip()]
    out = []
    for o in objs[:1000]:
        text = str(o.get('text') or o.get('prompt') or o.get('content') or o.get('input') or '')
        if not text.strip():
            continue
        l = o.get('label', o.get('is_injection', o.get('injection', o.get('malicious'))))
        label = str(l).lower() in ('1', 'true', 'injection', 'malicious', 'attack', 'jailbreak', 'unsafe')
        fmt = o.get('content_type') or o.get('format') or 'text'
        ch = o.get('channel') if o.get('channel') in ('user', 'retrieved', 'tool_output') else None
        out.append({'id': str(o.get('id') or ''), 'channel': ch, 'data': text.encode(), 'name': 'row.txt', 'fmt': fmt, 'label': label, 'type': o.get('attack_type') or o.get('type'), 'text': text})
    return out

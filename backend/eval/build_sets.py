"""Pull small, fixed samples of public prompt-injection datasets into eval/data/*.jsonl (spec §10.1, plan §6.6).

    cd backend && uv run python eval/build_sets.py

notinject.jsonl  — leolee99/NotInject, all 3 splits: benign prompts full of trigger words (primary FPR metric)
detection.jsonl  — deepset/prompt-injections test (mixed labels), Lakera gandalf (T1/T3), jackhhao jailbreaks (T2),
                   microsoft/llmail-inject-challenge Phase1 (indirect injection in email, T9)
Rows: {"id", "text", "label", "attack_type", "source", "channel"}; direct prompts are channel=user, emails are retrieved. Fixed seed, so re-running gives the same files.
"""
import json
import os
import random

import httpx

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data')
API = 'https://datasets-server.huggingface.co/rows'
rng = random.Random(20261010)


def rows(dataset, split, n=None, page=100):
    """All rows of a split (or the first n), via the HF datasets-server API (no `datasets`/pyarrow install)."""
    out, off = [], 0
    with httpx.Client(timeout=60) as c:
        while n is None or len(out) < n:
            r = c.get(API, params={'dataset': dataset, 'config': 'default', 'split': split, 'offset': off, 'length': page})
            r.raise_for_status()
            got = [x['row'] for x in r.json()['rows']]
            out += got
            off += page
            if len(got) < page:
                break
    return out if n is None else out[:n]


def sample(xs, k):
    return rng.sample(xs, min(k, len(xs)))


def notinject():
    out = []
    for split in ('NotInject_one', 'NotInject_two', 'NotInject_three'):
        for i, r in enumerate(rows('leolee99/NotInject', split)):
            out.append({'id': f'ni-{split[10:]}-{i}', 'text': r['prompt'], 'label': 0, 'attack_type': None, 'source': f'NotInject/{r["category"]}', 'channel': 'user'})
    return out


def detection():
    out = []
    for i, r in enumerate(rows('deepset/prompt-injections', 'test')):
        lab = int(r['label'])
        out.append({'id': f'ds-{i}', 'text': r['text'], 'label': lab, 'attack_type': 'T1 instruction override' if lab else None, 'source': 'deepset', 'channel': 'user'})
    for i, r in enumerate(sample(rows('Lakera/gandalf_ignore_instructions', 'test'), 50)):
        out.append({'id': f'gd-{i}', 'text': r['text'], 'label': 1, 'attack_type': 'T3 secret extraction', 'source': 'gandalf', 'channel': 'user'})
    jb = rows('jackhhao/jailbreak-classification', 'test')
    for i, r in enumerate(sample([x for x in jb if x['type'] == 'jailbreak'], 40) + sample([x for x in jb if x['type'] == 'benign'], 40)):
        lab = int(r['type'] == 'jailbreak')
        out.append({'id': f'jb-{i}', 'text': r['prompt'], 'label': lab, 'attack_type': 'T2 role change' if lab else None, 'source': 'jackhhao', 'channel': 'user'})
    seen, mail = set(), []
    for r in rows('microsoft/llmail-inject-challenge', 'Phase1', n=2000):  # first 2k submissions, deduped by body
        b = (r.get('body') or '').strip()
        if len(b) > 40 and b not in seen:
            seen.add(b)
            mail.append(r)
    for i, r in enumerate(sample(mail, 50)):
        out.append({'id': f'lm-{i}', 'text': f"Subject: {r.get('subject') or ''}\n\n{r['body']}", 'label': 1, 'attack_type': 'T9 indirect', 'source': 'llmail', 'channel': 'retrieved'})
    return out


def write(name, data):
    os.makedirs(OUT, exist_ok=True)
    with open(os.path.join(OUT, name), 'w') as f:
        f.writelines(json.dumps(x, ensure_ascii=False) + '\n' for x in data)
    pos = sum(x['label'] for x in data)
    print(f'{name}: {len(data)} rows ({pos} attack, {len(data) - pos} benign)')


if __name__ == '__main__':
    write('notinject.jsonl', notinject())
    write('detection.jsonl', detection())

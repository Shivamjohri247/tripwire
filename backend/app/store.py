"""SQLite storage. One JSON document table for everything, plus the LLM cache.

Limit: list() loads a whole kind and filters in Python; fine for demo volumes (<100k docs),
add per-kind tables with indexed columns if the audit log grows past that.
"""
import json
import os
import sqlite3
import threading
import time

from .config import DB_PATH

_lock = threading.Lock()
os.makedirs(os.path.dirname(DB_PATH) or '.', exist_ok=True)
_db = sqlite3.connect(DB_PATH, check_same_thread=False)
_db.executescript('''
create table if not exists docs (kind text, id text, created_at real, data text, primary key (kind, id));
create index if not exists docs_kind_time on docs (kind, created_at);
create table if not exists llm_cache (key text primary key, response text, created_at real);
''')


def put(kind, id, data, created_at=None):
    with _lock:
        row = _db.execute('select created_at from docs where kind=? and id=?', (kind, id)).fetchone()
        ts = row[0] if row else (created_at or time.time())
        _db.execute('insert or replace into docs values (?,?,?,?)', (kind, id, ts, json.dumps(data, ensure_ascii=False)))
        _db.commit()
    return data


def get(kind, id):
    with _lock:
        row = _db.execute('select data from docs where kind=? and id=?', (kind, id)).fetchone()
    return json.loads(row[0]) if row else None


def list(kind, limit=None, newest_first=True):
    q = f"select data from docs where kind=? order by created_at {'desc' if newest_first else 'asc'}" + (f' limit {int(limit)}' if limit else '')
    with _lock:
        return [json.loads(r[0]) for r in _db.execute(q, (kind,))]


def count(kind):
    with _lock:
        return _db.execute('select count(*) from docs where kind=?', (kind,)).fetchone()[0]


def delete(kind, id):
    with _lock:
        _db.execute('delete from docs where kind=? and id=?', (kind, id))
        _db.commit()


def cache_get(key):
    with _lock:
        row = _db.execute('select response from llm_cache where key=?', (key,)).fetchone()
    return row[0] if row else None


def cache_put(key, response):
    with _lock:
        _db.execute('insert or replace into llm_cache values (?,?,?)', (key, response, time.time()))
        _db.commit()


def cache_stats():
    with _lock:
        return _db.execute('select count(*) from llm_cache').fetchone()[0]

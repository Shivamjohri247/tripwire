"""In-process TraceEvent bus feeding GET /v1/events (SSE)."""
import asyncio
import collections
from datetime import datetime, timezone

recent = collections.deque(maxlen=300)
_subs: set[asyncio.Queue] = set()


def emit(agent, type, message, scan_id=None, trace=None, **data):
    ev = {'scan_id': scan_id, 'ts': datetime.now(timezone.utc).isoformat(timespec='milliseconds'), 'agent': agent,
          'type': type, 'message': message, 'data': data}
    if trace is not None:
        trace.append(ev)
    recent.append(ev)
    for q in list(_subs):
        q.put_nowait(ev)
    return ev


def subscribe():
    q = asyncio.Queue(maxsize=1000)
    _subs.add(q)
    return q


def unsubscribe(q):
    _subs.discard(q)

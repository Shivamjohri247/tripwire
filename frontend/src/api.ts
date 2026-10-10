// Thin REST + SSE helpers. Same origin in production; Vite proxies /v1, /demo, /attacker in dev.
export async function api<T = any>(path: string, init?: RequestInit & { json?: unknown }): Promise<T> {
  const { json, ...rest } = init || {}
  const res = await fetch(path, json === undefined ? rest : { method: 'POST', ...rest, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(json) })
  const body = await res.json().catch(() => ({}))
  if (!res.ok) throw new Error(typeof body.detail === 'string' ? body.detail : `HTTP ${res.status}`)
  return body
}

export async function upload<T = any>(path: string, form: FormData): Promise<T> {
  return api<T>(path, { method: 'POST', body: form })
}

/** POST that streams `data:` lines back (Arena run). */
export async function postStream(path: string, json: unknown, onEvent: (e: any) => void) {
  const res = await fetch(path, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(json) })
  if (!res.ok || !res.body) throw new Error(`HTTP ${res.status}`)
  const reader = res.body.getReader(), dec = new TextDecoder()
  let buf = ''
  for (;;) {
    const { done, value } = await reader.read()
    if (done) break
    buf += dec.decode(value, { stream: true })
    const parts = buf.split('\n\n'); buf = parts.pop()!
    for (const p of parts) if (p.startsWith('data: ')) onEvent(JSON.parse(p.slice(6)))
  }
}

export function download(name: string, data: string, type = 'application/json') {
  const a = document.createElement('a')
  a.href = URL.createObjectURL(new Blob([data], { type }))
  a.download = name
  a.click()
  setTimeout(() => URL.revokeObjectURL(a.href), 1000)
}

export const clip = (t: unknown, n: number) => { const s = String(t ?? ''); return s.length > n ? s.slice(0, n - 1) + '…' : s }
export const hhmmss = (ts: number | string) => new Date(typeof ts === 'number' ? ts * 1000 : ts).toTimeString().slice(0, 8)
export const ago = (ts: number) => { const m = Math.round((Date.now() / 1000 - ts) / 60); return m < 1 ? 'just now' : m < 60 ? `${m} min ago` : m < 1440 ? `${Math.round(m / 60)} h ago` : `${Math.round(m / 1440)} d ago` }
export const pct = (x: number | null | undefined, d = 1) => x == null || isNaN(x) ? '—' : `${(x * 100).toFixed(d)}%`

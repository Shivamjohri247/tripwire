import { createContext, useContext, useEffect, useRef, useState, type ReactNode } from 'react'
import { api } from './api'

export type Toast = { msg: string; kind: 'ok' | 'warn' | 'err' } | null
type Ctx = {
  route: string[]; go: (path: string) => void
  saved: any; draft: any; setDraft: (f: (d: any) => any) => void; version: number; benign: string[]
  reloadConfig: () => Promise<void>
  toast: (msg: string, kind?: 'ok' | 'warn' | 'err') => void
  live: any[]; paused: boolean; setPaused: (p: boolean) => void
  health: any; pending: number; refreshPending: () => void
  q: string; setQ: (q: string) => void
}
const C = createContext<Ctx>(null as any)
export const useApp = () => useContext(C)

/** Poll a GET endpoint; returns [data, reload]. */
export function useGet<T = any>(path: string | null, every?: number): [T | undefined, () => void] {
  const [d, setD] = useState<T>()
  const [n, setN] = useState(0)
  useEffect(() => {
    if (!path) return
    let alive = true
    const load = () => api<T>(path).then(x => alive && setD(x)).catch(() => {})
    load()
    const t = every ? setInterval(load, every) : undefined
    return () => { alive = false; clearInterval(t) }
  }, [path, every, n])
  return [d, () => setN(x => x + 1)]
}

const parse = () => (location.hash.replace(/^#\/?/, '') || 'overview').split('/')

export function AppProvider({ children }: { children: ReactNode }) {
  const [route, setRoute] = useState(parse)
  const [saved, setSaved] = useState<any>(null)
  const [draft, setDraftS] = useState<any>(null)
  const [version, setVersion] = useState(0)
  const [benign, setBenign] = useState<string[]>([])
  const [toastS, setToast] = useState<Toast>(null)
  const [live, setLive] = useState<any[]>([])
  const [paused, setPaused] = useState(false)
  const [q, setQ] = useState('')
  const pausedRef = useRef(false)
  const tt = useRef<number>(undefined)
  const [health] = useGet('/v1/health', 10000)
  const [reviews, refreshPending] = useGet<any[]>('/v1/reviews?status=pending', 8000)

  useEffect(() => { const f = () => setRoute(parse()); addEventListener('hashchange', f); return () => removeEventListener('hashchange', f) }, [])
  useEffect(() => { pausedRef.current = paused }, [paused])
  useEffect(() => {
    const es = new EventSource('/v1/events')
    es.onmessage = e => { if (!pausedRef.current) setLive(l => [JSON.parse(e.data), ...l].slice(0, 300)) }
    return () => es.close()
  }, [])
  const reloadConfig = async () => {
    const c = await api('/v1/config')
    setSaved(c.config); setDraftS(c.config); setVersion(c.version); setBenign(c.benign)
  }
  useEffect(() => { reloadConfig() }, [])
  const toast = (msg: string, kind: 'ok' | 'warn' | 'err' = 'ok') => { setToast({ msg, kind }); clearTimeout(tt.current); tt.current = window.setTimeout(() => setToast(null), 3200) }
  const value: Ctx = {
    route, go: p => { location.hash = '/' + p }, saved, draft, setDraft: f => setDraftS((d: any) => f(d)), version, benign, reloadConfig, toast,
    live, paused, setPaused, health, pending: reviews?.length ?? 0, refreshPending, q, setQ,
  }
  if (!saved) return <div className="p-10 text-t3">Connecting to Tripwire API…</div>
  return <C.Provider value={value}>{children}<ToastView t={toastS} /></C.Provider>
}

function ToastView({ t }: { t: Toast }) {
  if (!t) return null
  const dot = t.kind === 'err' ? 'oklch(0.6 0.19 28)' : t.kind === 'warn' ? 'oklch(0.72 0.14 75)' : 'oklch(0.6 0.13 155)'
  return (
    <div className="fixed right-5 bottom-5 bg-white border border-line rounded-lg px-3.5 py-2.5 z-40 flex gap-2 items-center max-w-[380px]" style={{ boxShadow: '0 8px 24px rgba(0,0,0,.1)' }}>
      <span className="w-[7px] h-[7px] rounded-full flex-none" style={{ background: dot }} />{t.msg}
    </div>
  )
}

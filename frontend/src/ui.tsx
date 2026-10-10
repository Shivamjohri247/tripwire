// Design-system primitives for the Tripwire console (tokens from the design handoff README).
import { useState, type CSSProperties, type ReactNode } from 'react'

export const INK = '#1c1b19', T2 = '#5f5d58', T3 = '#8b8984'
export const GREEN = 'oklch(0.6 0.13 155)', AMBER = 'oklch(0.72 0.14 75)', RED = 'oklch(0.6 0.19 28)', VIOLET = 'oklch(0.58 0.15 290)'
export const RED_T = 'oklch(0.47 0.17 28)', GREEN_T = 'oklch(0.42 0.11 155)', AMBER_T = 'oklch(0.46 0.11 65)', VIOLET_T = 'oklch(0.45 0.15 290)'
export const VC: Record<string, { c: string; bg: string; dot: string }> = {
  ALLOW: { c: GREEN_T, bg: 'oklch(0.965 0.03 155)', dot: GREEN },
  SANITIZE: { c: AMBER_T, bg: 'oklch(0.965 0.04 85)', dot: AMBER },
  QUARANTINE: { c: RED_T, bg: 'oklch(0.965 0.022 28)', dot: RED },
  ESCALATE: { c: VIOLET_T, bg: 'oklch(0.965 0.02 290)', dot: VIOLET },
}
export const AGENT_C: Record<string, string> = { triage: '#7d8aa6', sentinel: '#4f7f9c', detonator: RED, neutralizer: AMBER, adjudicator: INK, llm: AMBER, guard: VIOLET, session: '#9a7ab8', mutator: '#6f9a6f', agent: T3 }
export const SEV: Record<string, [string, string]> = { critical: ['oklch(0.965 0.022 28)', RED_T], high: ['oklch(0.965 0.04 85)', AMBER_T], medium: ['#f4f3f1', T2] }
export const typeColor = (t: string) => (t === 'llm_fallback' ? 'oklch(0.5 0.12 65)' : t === 'signal' || t === 'error' ? 'oklch(0.5 0.17 28)' : T3)

export const cx = (...c: (string | false | null | undefined)[]) => c.filter(Boolean).join(' ')
export const mono = 'font-mono'

export function Page({ title, desc, actions, children }: { title: ReactNode; desc?: ReactNode; actions?: ReactNode; children: ReactNode }) {
  return (
    <div className="flex flex-col gap-4">
      <div className="flex justify-between items-end gap-4 flex-wrap">
        <div><h1 className="m-0 text-[20px] font-semibold tracking-[-0.01em]">{title}</h1>{desc && <div className="text-t2 mt-1">{desc}</div>}</div>
        {actions && <div className="flex gap-2 items-center flex-wrap">{actions}</div>}
      </div>
      {children}
    </div>
  )
}

export function Card({ title, right, children, className, pad, style }: { title?: ReactNode; right?: ReactNode; children?: ReactNode; className?: string; pad?: boolean; style?: CSSProperties }) {
  return (
    <section className={cx('border border-line rounded-lg bg-white', className)} style={style}>
      {(title || right) && <div className="px-4 py-3 border-b border-div flex justify-between items-center gap-2 flex-wrap"><span className="font-semibold">{title}</span>{right}</div>}
      {pad ? <div className="px-4 py-3.5">{children}</div> : children}
    </section>
  )
}

export function Stats({ items, min = 180 }: { items: { l: ReactNode; v: ReactNode; s?: ReactNode; sc?: string; vc?: string }[]; min?: number }) {
  return (
    <div className="grid border border-line rounded-lg bg-white overflow-hidden" style={{ gridTemplateColumns: `repeat(auto-fit,minmax(${min}px,1fr))` }}>
      {items.map((k, i) => (
        <div key={i} className="px-4 py-3.5 border-r border-div flex flex-col gap-1.5">
          <span className="text-t2">{k.l}</span>
          <span className="text-[22px] font-semibold tracking-[-0.01em]" style={{ color: k.vc }}>{k.v}</span>
          {k.s != null && <span className="text-[12.5px]" style={{ color: k.sc || T3 }}>{k.s}</span>}
        </div>
      ))}
    </div>
  )
}

export function Dot({ c, size = 6, className }: { c: string; size?: number; className?: string }) {
  return <span className={cx('rounded-full flex-none inline-block', className)} style={{ width: size, height: size, background: c }} />
}

export function Verdict({ v, big }: { v: string; big?: boolean }) {
  const s = VC[v] || { c: T2, bg: '#f4f3f1', dot: '#d6d4cf' }
  return (
    <span className={cx('inline-flex items-center gap-1.5 rounded-[5px] font-medium whitespace-nowrap', big ? 'h-6 px-[9px] text-[12.5px] font-semibold' : 'h-[22px] px-2 text-[12px]')} style={{ background: s.bg, color: s.c }}>
      <Dot c={s.dot} />{v}
    </span>
  )
}

export function Badge({ children, bg = '#f4f3f1', c = '#3a3935', mono: m, className }: { children: ReactNode; bg?: string; c?: string; mono?: boolean; className?: string }) {
  return <span className={cx('inline-block h-[22px] leading-[22px] px-[7px] rounded text-[12px] whitespace-nowrap', m && 'font-mono text-[11.5px]', className)} style={{ background: bg, color: c }}>{children}</span>
}

export function TypeChip({ t }: { t: string }) {
  return <Badge bg="oklch(0.96 0.025 28)" c={RED_T}>{t}</Badge>
}

type BtnProps = { children: ReactNode; onClick?: (e: React.MouseEvent) => void; primary?: boolean; danger?: boolean; small?: boolean; disabled?: boolean; className?: string; title?: string }
export function Btn({ children, onClick, primary, danger, small, disabled, className, title }: BtnProps) {
  return (
    <button title={title} disabled={disabled} onClick={onClick} className={cx(small ? 'h-[30px]' : 'h-8', 'rounded-md px-3 inline-flex items-center gap-2 whitespace-nowrap disabled:opacity-50',
      primary ? 'bg-ink text-white font-medium border-0 px-3.5' : 'bg-white border border-ctl', danger && 'text-[oklch(0.47_0.17_28)]', className)}>
      {children}
    </button>
  )
}

export function LinkBtn({ children, onClick, danger }: { children: ReactNode; onClick?: () => void; danger?: boolean }) {
  return <button onClick={onClick} className={cx('border-0 bg-transparent p-0 text-[12.5px]', danger ? 'text-[oklch(0.47_0.17_28)]' : 'underline')}>{children}</button>
}

export function Spinner() {
  return <span className="inline-block w-3 h-3 rounded-full border-2 border-white/35 border-t-white animate-spin" />
}

/** variant ink = filter seg (ink active); form = white active with shadow. */
export function Seg<T extends string | boolean>({ options, value, onChange, variant = 'ink' }: { options: [T, ReactNode][]; value: T; onChange: (v: T) => void; variant?: 'ink' | 'form' }) {
  return (
    <div className={cx('flex border border-ctl rounded-md p-0.5 gap-0.5 self-start', variant === 'form' ? 'bg-side' : 'bg-white')}>
      {options.map(([v, l]) => {
        const a = v === value
        return (
          <button key={String(v)} onClick={() => onChange(v)} className="h-[26px] border-0 rounded px-2.5 font-medium text-[13px] whitespace-nowrap"
            style={variant === 'ink' ? { background: a ? INK : 'transparent', color: a ? '#fff' : '#3a3935' } : { background: a ? '#fff' : 'transparent', color: a ? INK : T2, boxShadow: a ? '0 1px 2px rgba(0,0,0,.08)' : 'none' }}>
            {l}
          </button>
        )
      })}
    </div>
  )
}

export function Toggle({ on, onChange, big, label }: { on: boolean; onChange: (v: boolean) => void; big?: boolean; label?: ReactNode }) {
  const w = big ? 34 : 30, h = big ? 20 : 18, k = big ? 16 : 14
  const sw = (
    <span className="relative flex-none rounded-full" style={{ width: w, height: h, background: on ? INK : '#d6d4cf' }}>
      <span className="absolute top-0.5 rounded-full bg-white shadow-[0_1px_2px_rgba(0,0,0,.2)]" style={{ width: k, height: k, left: on ? w - k - 2 : 2 }} />
    </span>
  )
  return <button onClick={e => { e.stopPropagation(); onChange(!on) }} className="flex gap-2 items-center border-0 bg-transparent p-0">{sw}{label}</button>
}

export function Tabs<T extends string>({ tabs, value, onChange, pad = 'py-2' }: { tabs: [T, ReactNode, (number | null)?][]; value: T; onChange: (v: T) => void; pad?: string }) {
  return (
    <div className="flex gap-5 border-b border-line">
      {tabs.map(([k, l, n]) => (
        <button key={k} onClick={() => onChange(k)} className={cx('border-0 bg-transparent px-0 -mb-px font-medium flex gap-1.5 items-center', pad)}
          style={{ borderBottom: `2px solid ${value === k ? INK : 'transparent'}`, color: value === k ? INK : T2 }}>
          {l}{n != null && <span className="text-[11.5px] text-t3">{n}</span>}
        </button>
      ))}
    </div>
  )
}

export function Bar({ w, c = INK, h = 6 }: { w: number; c?: string; h?: number }) {
  return <div className="bg-div rounded-sm overflow-hidden flex-1" style={{ height: h }}><div className="h-full" style={{ width: `${Math.max(0, Math.min(100, w))}%`, background: c }} /></div>
}

export function Chips({ options, value, onChange, single }: { options: [string, ReactNode][]; value: string[] | string; onChange: (v: any) => void; single?: boolean }) {
  const has = (k: string) => (single ? value === k : (value as string[]).includes(k))
  return (
    <div className="flex gap-[5px] flex-wrap">
      {options.map(([k, l]) => {
        const on = has(k)
        return (
          <button key={k} onClick={() => onChange(single ? k : on ? (value as string[]).filter(x => x !== k) : [...(value as string[]), k])}
            className="h-[26px] px-[9px] rounded-[5px] text-[12.5px] border" style={{ background: on ? INK : '#fff', color: on ? '#fff' : T2, borderColor: on ? INK : '#e2e0db' }}>{l}</button>
        )
      })}
    </div>
  )
}

export function Grid({ cols, head, children, minW, className, onClick, style }: { cols: string; head?: boolean; children: ReactNode; minW?: number; className?: string; onClick?: () => void; style?: CSSProperties }) {
  return (
    <div onClick={onClick} className={cx('grid gap-3 px-4 items-center', head ? 'h-9 border-b border-line text-[12.5px] text-t2 font-medium bg-page' : 'border-b border-row', onClick && 'cursor-pointer hover:bg-page', className)}
      style={{ gridTemplateColumns: cols, minWidth: minW, ...style }}>{children}</div>
  )
}

export const Empty = ({ children }: { children: ReactNode }) => <div className="p-10 text-center text-t3">{children}</div>

export const inputCls = 'h-8 border border-ctl rounded-md px-2.5 bg-white'
export const selectCls = 'h-8 border border-ctl rounded-md px-2 bg-white'
export const areaCls = 'w-full box-border border border-ctl rounded-md px-2.5 py-2 font-mono text-[12.5px] leading-[1.55] resize-y bg-white'

// ---------- config fields ----------
export type FieldDef = { k: string | null; type: string; label: string; help?: string; opts?: [string, string][]; options?: [string, string][]; min?: number; max?: number; step?: number; unit?: string; prefix?: string; rows?: number; placeholder?: string; text?: string; btn?: string; run?: () => void; status?: ReactNode; statusC?: string; wide?: boolean }
export const F = (k: string | null, type: string, label: string, help = '', x: Partial<FieldDef> = {}): FieldDef => ({ k, type, label, help, ...x })

export function FieldRow({ f, value, set, dirty, onCopy }: { f: FieldDef; value: any; set: (v: any) => void; dirty?: boolean; onCopy?: (t: string) => void }) {
  const [reveal, setReveal] = useState(false)
  const t = f.type, wide = f.wide || t === 'area'
  const dec = (f.step ?? 1) >= 1 ? 0 : (f.step! >= 0.1 ? 1 : 2)
  let ctl: ReactNode = null
  if (t === 'toggle') ctl = <Toggle big on={!!value} onChange={set} />
  else if (t === 'number') ctl = (
    <div className="flex items-center h-8 border border-ctl rounded-md bg-white overflow-hidden">
      {f.prefix && <span className="px-2 text-t2 border-r border-[#eceae6] h-full flex items-center bg-page">{f.prefix}</span>}
      <input type="number" value={value ?? ''} min={f.min} max={f.max} step={f.step} onChange={e => set(Number(e.target.value))} className="w-[100px] border-0 h-full px-2 text-right bg-transparent !shadow-none" />
      {f.unit && <span className="px-2 text-t2 border-l border-[#eceae6] h-full flex items-center bg-page">{f.unit}</span>}
    </div>)
  else if (t === 'slider') ctl = <><input type="range" min={f.min ?? 0} max={f.max ?? 1} step={f.step ?? 0.01} value={value ?? 0} onChange={e => set(Number(e.target.value))} className="flex-1 min-w-[120px] max-w-[220px]" /><span className="font-mono text-[12.5px] w-10 text-right">{Number(value).toFixed(dec)}</span></>
  else if (t === 'select') ctl = <select value={value ?? ''} onChange={e => set(e.target.value)} className={cx(selectCls, 'w-full max-w-[340px]')}>{(f.opts || []).map(([v, l]) => <option key={v} value={v}>{l}</option>)}</select>
  else if (t === 'text') ctl = <input value={value ?? ''} placeholder={f.placeholder} onChange={e => set(e.target.value)} className={cx(inputCls, 'w-full font-mono text-[12.5px] box-border')} />
  else if (t === 'secret') ctl = <div className="flex gap-1.5 w-full"><input type={reveal ? 'text' : 'password'} value={value ?? ''} onChange={e => set(e.target.value)} className={cx(inputCls, 'flex-1 min-w-0 font-mono text-[12.5px]')} /><Btn onClick={() => setReveal(!reveal)}>{reveal ? 'Hide' : 'Reveal'}</Btn></div>
  else if (t === 'seg') ctl = <Seg variant="form" options={f.options as [string, string][]} value={value} onChange={set} />
  else if (t === 'tags') ctl = <Tags value={value || []} onChange={set} />
  else if (t === 'chips') ctl = <div className="flex justify-end"><Chips options={f.options!} value={value || []} onChange={set} /></div>
  else if (t === 'area') ctl = <textarea rows={f.rows || 4} value={value ?? ''} placeholder={f.placeholder} onChange={e => set(e.target.value)} className={areaCls} />
  else if (t === 'readonly') ctl = <div className="flex gap-1.5 w-full"><span className="flex-1 min-w-0 h-8 leading-8 border border-[#eceae6] rounded-md px-2.5 font-mono text-[12px] bg-page overflow-hidden text-ellipsis whitespace-nowrap">{f.text}</span><Btn onClick={() => onCopy?.(f.text || '')}>Copy</Btn></div>
  else if (t === 'action') ctl = <><span className="text-[12.5px]" style={{ color: f.statusC || T2 }}>{f.status}</span><Btn onClick={f.run} className="font-medium">{f.btn}</Btn></>
  return (
    <div className="flex flex-wrap gap-x-6 gap-y-2.5 px-[18px] py-3 border-t border-row items-center">
      <div className="min-w-0" style={{ flex: '1 1 220px' }}>
        <div className="flex gap-1.5 items-center font-medium">{f.label}<Dot c={dirty ? AMBER : 'transparent'} /></div>
        {f.help && <div className="text-[12.5px] text-t2 mt-0.5 leading-[1.45]">{f.help}</div>}
      </div>
      <div className="flex justify-end items-center gap-2 flex-wrap min-w-0 ml-auto" style={{ flex: `1 1 ${wide ? '100%' : '240px'}`, maxWidth: wide ? '100%' : 360 }}>{ctl}</div>
    </div>
  )
}

export function Tags({ value, onChange }: { value: string[]; onChange: (v: string[]) => void }) {
  return (
    <div className="flex flex-wrap gap-[5px] items-center border border-ctl rounded-md p-1 w-full box-border bg-white">
      {value.map(x => (
        <span key={x} className="inline-flex items-center gap-[5px] h-6 pl-2 pr-1 rounded bg-row font-mono text-[12px]">{x}
          <button onClick={() => onChange(value.filter(y => y !== x))} className="border-0 bg-transparent text-t3 px-[3px] text-[14px] leading-none">×</button></span>
      ))}
      <input placeholder="Add + Enter" className="flex-1 min-w-[90px] border-0 h-6 px-1 !shadow-none text-[12.5px]"
        onKeyDown={e => { if (e.key === 'Enter' || e.key === ',') { e.preventDefault(); const v = e.currentTarget.value.trim(); if (v && !value.includes(v)) onChange([...value, v]); e.currentTarget.value = '' } }} />
    </div>
  )
}

export function Section({ title, desc, children }: { title: ReactNode; desc?: ReactNode; children: ReactNode }) {
  return (
    <section className="border border-line rounded-lg bg-white">
      <div className="px-[18px] py-3.5 flex flex-col gap-[3px]"><span className="font-semibold text-[14px]">{title}</span>{desc && <span className="text-t2 leading-[1.45]">{desc}</span>}</div>
      {children}
    </section>
  )
}

export function Drawer({ title, sub, onClose, footer, children }: { title: ReactNode; sub?: ReactNode; onClose: () => void; footer: ReactNode; children: ReactNode }) {
  return (
    <>
      <div onClick={onClose} className="fixed inset-0 z-30" style={{ background: 'rgba(28,27,25,.18)' }} />
      <aside className="fixed top-0 right-0 bottom-0 bg-white border-l border-line z-[31] flex flex-col" style={{ width: 'min(580px,100vw)', boxShadow: '-12px 0 32px rgba(0,0,0,.08)' }}>
        <div className="h-[58px] px-[18px] border-b border-line flex items-center justify-between gap-3 flex-none">
          <div className="flex flex-col leading-[1.3] min-w-0"><span className="font-semibold text-[15px]">{title}</span><span className="text-[12.5px] text-t3">{sub}</span></div>
          <button onClick={onClose} className="w-[30px] h-[30px] border border-ctl rounded-md bg-white text-[16px] leading-none flex-none">×</button>
        </div>
        <div className="flex-1 overflow-auto">{children}</div>
        <div className="px-[18px] py-3 border-t border-line flex gap-2 items-center flex-none">{footer}</div>
      </aside>
    </>
  )
}

export function Modal({ onClose, children }: { onClose: () => void; children: ReactNode }) {
  return (
    <>
      <div onClick={onClose} className="fixed inset-0 z-30" style={{ background: 'rgba(28,27,25,.25)' }} />
      <div className="fixed left-1/2 top-1/2 -translate-x-1/2 -translate-y-1/2 bg-white rounded-[10px] z-[31] flex flex-col overflow-hidden" style={{ width: 'min(600px,92vw)', maxHeight: '84vh', boxShadow: '0 24px 64px rgba(0,0,0,.2)' }}>{children}</div>
    </>
  )
}

export function ErrBox({ children }: { children: ReactNode }) {
  return <div className="mx-[18px] mb-4 px-3 py-2.5 rounded-md text-[13px]" style={{ background: 'oklch(0.965 0.022 28)', color: 'oklch(0.45 0.17 28)' }}>{children}</div>
}

export const getP = (o: any, p: string) => p.split('.').reduce((a, k) => (a == null ? a : a[k]), o)
export const setP = (o: any, p: string, v: any): any => { const ks = p.split('.'); const r = { ...o }; let c = r; for (let i = 0; i < ks.length - 1; i++) { c[ks[i]] = { ...c[ks[i]] }; c = c[ks[i]] } c[ks[ks.length - 1]] = v; return r }
export const flat = (o: any, pre = '', out: Record<string, string> = {}) => {
  for (const k in o) {
    const v = o[k], p = pre ? `${pre}.${k}` : k
    if (Array.isArray(v) && v.length && v[0] && typeof v[0] === 'object' && 'id' in v[0]) v.forEach((x: any) => { const { id, ...rest } = x; flat(rest, `${p}[${id}]`, out) })
    else if (v && typeof v === 'object' && !Array.isArray(v)) flat(v, p, out)
    else out[p] = JSON.stringify(v)
  }
  return out
}
export const diffCfg = (a: any, b: any) => { const A = flat(a), B = flat(b); return [...new Set([...Object.keys(A), ...Object.keys(B)])].filter(k => A[k] !== B[k]).map(k => ({ path: k, before: A[k] ?? '—', after: B[k] ?? '—' })) }

// character-trigram cosine, same as backend sentinel.similarity (used for live previews only)
const grams = (t: string) => { const m = new Map<string, number>(); const x = ' ' + String(t).toLowerCase().replace(/[^a-z0-9ऀ-ॿ]+/g, ' ').trim() + ' '; for (let i = 0; i < x.length - 2; i++) { const g = x.slice(i, i + 3); m.set(g, (m.get(g) || 0) + 1) } return m }
export const sim = (a: string, b: string) => { const A = grams(a), B = grams(b); let dot = 0, na = 0, nb = 0; A.forEach((v, k) => { na += v * v; if (B.has(k)) dot += v * B.get(k)! }); B.forEach(v => { nb += v * v }); return na && nb ? dot / Math.sqrt(na * nb) : 0 }

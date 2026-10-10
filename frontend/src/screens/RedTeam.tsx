import { useState } from 'react'
import { api } from '../api'
import { useApp, useGet } from '../ctx'
import { areaCls, Btn, Card, Dot, Empty, Grid, INK, Page, selectCls, Spinner, Stats, T3, VC } from '../ui'

const TYPES = ['T1 instruction override', 'T2 role change', 'T3 secret extraction', 'T4 tool abuse', 'T5 credential theft', 'T6 context poisoning', 'T7 multi-step', 'T8 encoded instructions', 'T9 indirect']

export function RedTeam() {
  const a = useApp()
  const [runs, reload] = useGet<any[]>('/v1/redteam/runs', 3000)
  const [reviews, reloadRev] = useGet<any[]>('/v1/reviews', 3000)
  const [raw, setRaw] = useState('')
  const [type, setType] = useState(TYPES[3])
  const [sel, setSel] = useState('')
  const [busy, setBusy] = useState(false)
  const run = runs?.find(r => r.id === sel) || runs?.[0]
  const start = async () => {
    const variants = raw.split('\n').map(l => l.trim()).filter(Boolean).map((l, i) => { const [lab, ...rest] = l.split(' | '); return rest.length ? { label: lab, text: rest.join(' | ') } : { label: `variant ${i + 1}`, text: l } })
    if (!variants.length) return a.toast('Paste at least one variant', 'warn')
    setBusy(true)
    try { const r = await api('/v1/redteam/run', { json: { variants, attack_type: type } }); setSel(r.id); reload() } catch (e: any) { a.toast(e.message, 'err') }
    setBusy(false)
  }
  const props = (reviews || []).filter(r => r.kind === 'Memory proposal' && run && r.run_id === run.id)
  const approve = async (id: string) => {
    try { await api(`/v1/reviews/${id}`, { json: { decision: 'approve' } }); a.toast(`${id} approved · added to attack memory · re-testing`); reloadRev(); a.reloadConfig(); a.refreshPending() } catch (e: any) { a.toast(e.message, 'err') }
  }
  const n = run?.variants.length || 0
  const blockedBefore = run ? run.variants.filter((v: any) => v.result === 'Blocked').length : 0
  const blockedAfter = run ? run.variants.filter((v: any) => v.result === 'Blocked' || v.after === 'Blocked').length : 0
  return (
    <Page title="Red team" desc="Test your own attack variants against the published config, turn bypasses into memory proposals, approve them and re-test.">
      <Card title="Variants to test" right={<span className="text-[12.5px] text-t3">one per line · optional “label | text”</span>}>
        <div className="p-4 flex flex-col gap-3">
          <textarea value={raw} onChange={e => setRaw(e.target.value)} rows={6} className={areaCls} placeholder="paraphrase | your variant text here" />
          <div className="flex gap-2 items-center justify-end flex-wrap">
            <span className="text-[12.5px] text-t2">Attack type for proposals</span>
            <select value={type} onChange={e => setType(e.target.value)} className={selectCls}>{TYPES.map(t => <option key={t}>{t}</option>)}</select>
            <Btn primary onClick={start} disabled={busy}>{busy && <Spinner />}Run variants</Btn>
          </div>
        </div>
      </Card>
      {runs && runs.length > 1 && <select value={run?.id} onChange={e => setSel(e.target.value)} className={`${selectCls} self-start`}>{runs.map(r => <option key={r.id} value={r.id}>{r.id} · {r.variants.length} variants · {r.status}</option>)}</select>}
      {run && <>
        <Stats items={[
          { l: 'Block rate before', v: `${Math.round(blockedBefore / n * 100)}%`, s: `${blockedBefore} / ${n} variants` },
          { l: 'Block rate after memory', v: `${Math.round(blockedAfter / n * 100)}%`, s: `${blockedAfter} / ${n} · ${blockedAfter - blockedBefore} fixed by memory`, vc: blockedAfter > blockedBefore ? 'oklch(0.42 0.11 155)' : INK },
          { l: 'Run status', v: run.status === 'running' ? 'Running' : 'Complete', s: `${run.id} · sentinel-only scans` },
        ]} />
        <section className="border border-line rounded-lg bg-white overflow-hidden">
          <Grid head cols="minmax(120px,0.8fr) minmax(200px,2fr) 110px 110px minmax(120px,1fr)"><span>Variant</span><span>Text</span><span>Result</span><span>After memory</span><span>Caught by</span></Grid>
          {run.variants.map((v: any, i: number) => (
            <Grid key={i} cols="minmax(120px,0.8fr) minmax(200px,2fr) 110px 110px minmax(120px,1fr)" className="py-2">
              <span className="font-medium">{v.label}</span><span className="font-mono text-[12px] text-body truncate" title={v.text}>{v.text}</span>
              <Res r={v.result} /><Res r={v.result === 'Bypass' ? v.after || 'Pending' : '—'} />
              <span className="font-mono text-[12px] text-t2">{v.by || '—'}</span>
            </Grid>
          ))}
        </section>
        <Card title="Memory proposals">
          {!props.length && <Empty>{run.status === 'running' ? 'Scanning…' : 'No bypasses, so nothing to learn.'}</Empty>}
          {props.map(p => (
            <div key={p.id} className="px-4 py-3 border-b border-row grid gap-4 items-center" style={{ gridTemplateColumns: 'minmax(0,1fr) auto' }}>
              <div className="flex flex-col gap-1 min-w-0"><div className="flex gap-2 items-baseline flex-wrap"><span className="font-mono text-[12px] text-t3">{p.id}</span><span className="font-semibold">{p.type}</span><span className="text-[12.5px] text-t3">benign sim {p.benign_sim}</span></div>
                <div className="font-mono text-[12px] text-body leading-normal">“{p.text}”</div></div>
              {p.status === 'pending' ? <Btn primary small onClick={() => approve(p.id)}>Approve</Btn>
                : <span className="flex gap-1.5 items-center text-[12.5px] font-medium" style={{ color: p.status === 'approved' ? 'oklch(0.42 0.11 155)' : T3 }}><Dot c={p.status === 'approved' ? 'oklch(0.42 0.11 155)' : T3} />{p.auto ? 'Auto-rejected · would raise FPR' : p.status === 'approved' ? `In memory (${p.memory_id}) · re-tested` : 'Denied'}</span>}
            </div>
          ))}
        </Card>
      </>}
    </Page>
  )
}

function Res({ r }: { r: string }) {
  const s = r === 'Blocked' ? VC.ALLOW : r === 'Bypass' ? VC.QUARANTINE : { bg: '#f4f3f1', c: T3, dot: '#d6d4cf' }
  if (r === '—') return <span className="text-t3">—</span>
  return <span><span className="inline-flex items-center gap-1.5 h-[22px] px-2 rounded-[5px] text-[12px] font-medium" style={{ background: s.bg, color: s.c }}><Dot c={s.dot} />{r}</span></span>
}

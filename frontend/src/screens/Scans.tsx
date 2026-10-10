import { useState } from 'react'
import { download, hhmmss } from '../api'
import { useApp, useGet } from '../ctx'
import { Btn, Empty, Grid, Page, Seg, selectCls, Verdict } from '../ui'

const COLS = '96px 76px minmax(200px,1.5fr) minmax(120px,1fr) minmax(130px,1fr) 118px 52px minmax(110px,1fr)'
const short = (ts: string[]) => (ts || []).map(t => t.split(' ')[0]).join(' ') || '—'

export function Scans() {
  const a = useApp()
  const [rows] = useGet<any[]>('/v1/scans', 5000)
  const [vf, setVf] = useState('all')
  const [df, setDf] = useState('all')
  const ql = a.q.trim().toLowerCase()
  const list = (rows || []).filter(r => (vf === 'all' || r.verdict === vf) && (df === 'all' || r.destination?.name === df) &&
    (!ql || [r.scan_id, r.title, r.source, short(r.attack_types), r.verdict].join(' ').toLowerCase().includes(ql)))
  const csv = () => download('tripwire-scans.csv', [['scan', 'time', 'content', 'source', 'destination', 'verdict', 'risk', 'types'],
    ...list.map(r => [r.scan_id, hhmmss(r.created_at), r.title, r.source, r.destination?.name, r.verdict, r.risk, short(r.attack_types)])]
    .map(r => r.map(x => `"${String(x ?? '').replace(/"/g, '""')}"`).join(',')).join('\n'), 'text/csv')
  return (
    <Page title="Scans" desc="Audit log of every verdict. Click a row to inspect it."
      actions={<><Btn onClick={csv}>Export CSV</Btn><Btn primary onClick={() => a.go('playground')}>New scan</Btn></>}>
      <div className="flex gap-2 flex-wrap items-center">
        <Seg options={[['all', 'All'], ['ALLOW', 'Allow'], ['SANITIZE', 'Sanitize'], ['QUARANTINE', 'Quarantine'], ['ESCALATE', 'Escalate']]} value={vf} onChange={setVf} />
        <select value={df} onChange={e => setDf(e.target.value)} className={selectCls}><option value="all">All destinations</option>{Object.entries(a.saved.destinations).map(([id, d]: any) => <option key={id} value={id}>{d.name}</option>)}</select>
        {ql && <span className="flex gap-1.5 items-center h-7 px-2 rounded-[5px] bg-[#efeeeb]">“{a.q}”<button onClick={() => a.setQ('')} className="border-0 bg-transparent p-0 text-t2">×</button></span>}
      </div>
      <section className="border border-line rounded-lg bg-white overflow-auto">
        <Grid head cols={COLS} minW={960}><span>Scan</span><span>Time</span><span>Content</span><span>Source</span><span>Destination</span><span>Verdict</span><span>Risk</span><span>Attack types</span></Grid>
        {rows && !list.length && <Empty>No scans match these filters.</Empty>}
        {list.map(r => (
          <Grid key={r.scan_id} cols={COLS} minW={960} className="h-[42px]" onClick={() => a.go(`scan/${r.scan_id}`)}>
            <span className="font-mono text-[12.5px]">{r.scan_id}</span>
            <span className="font-mono text-[12.5px] text-t3">{hhmmss(r.created_at)}</span>
            <span className="truncate font-medium">{r.title}</span>
            <span className="text-t2 truncate">{r.source}</span>
            <span className="text-t2 truncate">{r.destination?.name} · {r.destination?.risk}</span>
            <span><Verdict v={r.verdict} /></span>
            <span className="font-mono text-[12.5px]">{Number(r.risk).toFixed(2)}</span>
            <span className="font-mono text-[12px] text-t2 truncate">{short(r.attack_types)}</span>
          </Grid>
        ))}
        <div className="flex justify-between items-center px-4 py-2.5 text-t2 text-[12.5px] min-w-[960px]"><span>Showing {list.length} of {rows?.length ?? 0} scans</span></div>
      </section>
    </Page>
  )
}

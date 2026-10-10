import { useState } from 'react'
import { ago, api } from '../api'
import { useApp, useGet } from '../ctx'
import { Btn, Dot, GREEN_T, Page, RED_T, T3, Tabs } from '../ui'

export function Review() {
  const a = useApp()
  const [tab, setTab] = useState<'pending' | 'resolved' | 'all'>('pending')
  const [rows, reload] = useGet<any[]>('/v1/reviews', 5000)
  const [notes, setNotes] = useState<Record<string, string>>({})
  const all = rows || []
  const pending = all.filter(r => r.status === 'pending')
  const list = tab === 'all' ? all : tab === 'pending' ? pending : all.filter(r => r.status !== 'pending')
  const sla = a.saved.settings.sla * 60
  const decide = async (id: string, decision: string) => {
    try {
      await api(`/v1/reviews/${id}`, { json: { decision, note: notes[id] || '' } })
      a.toast(decision === 'reopen' ? `${id} reopened` : `${id} ${decision === 'approve' ? 'approved' : 'denied'}`)
      reload(); a.refreshPending()
      if (decision === 'approve') a.reloadConfig()
    } catch (e: any) { a.toast(e.message, 'warn') }
  }
  return (
    <Page title="Review queue" desc="Escalated verdicts, tool-call approvals and memory changes waiting for a human.">
      <Tabs tabs={[['pending', `Pending ${pending.length}`], ['resolved', `Resolved ${all.length - pending.length}`], ['all', 'All']]} value={tab} onChange={setTab} />
      {rows && !list.length && <div className="p-10 text-center text-t3 border border-dashed border-ctl rounded-lg">Nothing here.</div>}
      {list.map(r => {
        const late = r.status === 'pending' && Date.now() / 1000 - r.created_at > sla
        return (
          <section key={r.id} className="border border-line rounded-lg bg-white grid" style={{ gridTemplateColumns: 'minmax(0,1fr) 280px' }}>
            <div className="px-[18px] py-4 flex flex-col gap-2 min-w-0">
              <div className="flex gap-2 items-center flex-wrap">
                <span className="h-[22px] leading-[22px] px-2 rounded-[5px] text-[12px] font-medium" style={{ background: 'oklch(0.96 0.02 290)', color: 'oklch(0.45 0.15 290)' }}>{r.kind}</span>
                <span className="font-mono text-[12px] text-t3">{r.id} · {r.src}</span>
                <span className="text-[12px]" style={{ color: late ? RED_T : T3 }}>{ago(r.created_at)}</span>
              </div>
              <div className="text-[15px] font-semibold">{r.title}</div>
              <div className="leading-normal text-body">{r.why}</div>
              <div className="flex flex-col gap-1 mt-1">{(r.ev || []).map((x: string, i: number) => <div key={i} className="font-mono text-[12px] text-t2 bg-[#f8f7f5] rounded px-2 py-[5px] break-words">{x}</div>)}</div>
              {r.scan_id && <button onClick={() => a.go(`scan/${r.scan_id}`)} className="self-start border-0 bg-transparent p-0 underline text-[12.5px]">Open scan {r.scan_id}</button>}
            </div>
            <div className="border-l border-div p-4 flex flex-col gap-2.5">
              <span className="text-[12.5px] text-t2">Suggested: <span className="text-ink font-medium">{r.suggest}</span></span>
              {r.status === 'pending' ? <>
                <textarea value={notes[r.id] || ''} onChange={e => setNotes({ ...notes, [r.id]: e.target.value })} placeholder="Reviewer note (required for deny)" rows={3} className="border border-ctl rounded-md px-2.5 py-2 resize-y bg-white text-[13px]" />
                <div className="flex gap-2"><Btn className="flex-1 justify-center font-medium" onClick={() => decide(r.id, 'deny')}>Deny</Btn><Btn primary className="flex-1 justify-center" onClick={() => decide(r.id, 'approve')}>Approve</Btn></div>
              </> : (
                <div className="flex flex-col gap-1.5">
                  <span className="flex gap-1.5 items-center font-medium" style={{ color: r.status === 'approved' ? GREEN_T : RED_T }}><Dot c={r.status === 'approved' ? GREEN_T : RED_T} size={7} />{r.status === 'approved' ? 'Approved' : 'Denied'} by {r.decided_by || (r.auto ? 'policy' : 'ananya.rao')}</span>
                  <span className="text-[12.5px] text-t2">{r.note ? `“${r.note}”` : 'No note'}{r.memory_id ? ` · added as ${r.memory_id}` : ''}</span>
                  {!r.auto && <button onClick={() => decide(r.id, 'reopen')} className="self-start border-0 bg-transparent p-0 text-t2 underline text-[12.5px]">Reopen</button>}
                </div>
              )}
            </div>
          </section>
        )
      })}
    </Page>
  )
}

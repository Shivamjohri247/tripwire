import { useRef, useState } from 'react'
import { api, postStream, upload } from '../api'
import { useApp, useGet } from '../ctx'
import { Btn, Card, GREEN_T, INK, Page, Seg, Spinner, T3, VC, Verdict, VIOLET_T } from '../ui'

const TAG: Record<string, [string, string]> = { read: ['READ', T3], leak: ['LEAKED', 'oklch(0.5 0.18 28)'], deny: ['BLOCKED', VIOLET_T], ok: ['ALLOWED', GREEN_T], done: ['DONE', INK], error: ['ERROR', 'oklch(0.5 0.18 28)'] }

export function Arena() {
  const a = useApp()
  const [items, reloadInbox] = useGet<any[]>('/demo/inbox')
  const [fw, setFw] = useState(true)
  const [running, setRunning] = useState(false)
  const [evs, setEvs] = useState<any[]>([])
  const [ranFw, setRanFw] = useState(true)
  const file = useRef<HTMLInputElement>(null)
  const done = evs.find(e => e.k === 'done')
  const loot = evs.filter(e => e.loot).map(e => e.loot)
  const verdicts: Record<string, any> = Object.fromEntries(evs.filter(e => e.k === 'scan').map(e => [e.item, e]))
  const run = async () => {
    setRunning(true); setEvs([]); setRanFw(fw)
    try { await postStream('/demo/agent/run', { firewall: fw }, e => setEvs(l => [...l, e])) } catch (e: any) { a.toast(`Run failed: ${e.message}`, 'err') }
    setRunning(false); a.refreshPending()
  }
  const add = async (f: File) => {
    const fd = new FormData(); fd.append('file', f)
    try { await upload('/demo/inbox', fd); reloadInbox(); a.toast(`${f.name} added to the inbox`) } catch (e: any) { a.toast(e.message, 'err') }
  }
  const started = evs.length > 0
  return (
    <Page title="Arena" desc="Run Bharat Bank RM Copilot over a poisoned inbox with Tripwire on or off. Task: “Summarise today’s inbox and prepare follow-ups.”"
      actions={<>
        <input ref={file} type="file" className="hidden" onChange={e => { const f = e.target.files?.[0]; e.target.value = ''; if (f) add(f) }} />
        <Btn onClick={() => file.current?.click()}>Add to inbox</Btn>
        <Seg options={[[false, 'Tripwire off'], [true, 'Tripwire on']]} value={fw} onChange={v => { setFw(v); setEvs([]) }} />
        <Btn primary onClick={run} disabled={running}>{running && <Spinner />}{running ? 'Running…' : started ? 'Run again' : 'Run agent'}</Btn></>}>
      <div className="grid gap-4 items-start" style={{ gridTemplateColumns: 'repeat(auto-fit,minmax(300px,1fr))' }}>
        <Card title="Inbox" right={<span className="text-t3 text-[12.5px]">{items?.length ?? 0} items</span>}>
          {items?.map(m => {
            const v = ranFw ? verdicts[m.id] : null
            return (
              <div key={m.id} onClick={() => v && a.go(`scan/${v.scan_id}`)} className="px-4 py-2.5 border-b border-row flex flex-col gap-1" style={{ cursor: v ? 'pointer' : 'default' }}>
                <div className="flex justify-between gap-2 items-center"><span className="font-medium">{m.subj}</span>{v && <Verdict v={v.verdict} />}</div>
                <div className="text-[12.5px] text-t3 flex justify-between">{m.from} · {m.fmt} · {m.id}
                  {m.custom && <button onClick={e => { e.stopPropagation(); api(`/demo/inbox/${m.id}`, { method: 'DELETE' }).then(reloadInbox) }} className="border-0 bg-transparent p-0 text-t3">remove</button>}</div>
                {v && <div className="text-[12.5px] text-body leading-[1.45]">{v.why}</div>}
              </div>
            )
          })}
        </Card>
        <Card title="Agent actions" right={<span className="text-t3 text-[12.5px]">{running ? 'running' : started ? `${evs.length} steps` : 'idle'}</span>}>
          {!started && <div className="px-4 py-9 text-center text-t3">Run the agent to see its actions.</div>}
          {evs.map((e, i) => {
            const [tag, c] = e.k === 'scan' ? [e.verdict, VC[e.verdict].c] : TAG[e.k] || ['', T3]
            return (
              <div key={i} className="grid gap-2 px-4 py-2 border-b border-row text-[13px] items-baseline" style={{ gridTemplateColumns: '40px 84px minmax(0,1fr)' }}>
                <span className="font-mono text-[11.5px] text-t3">{e.t}s</span>
                <span className="text-[11.5px] font-semibold" style={{ color: c }}>{tag}</span>
                <span className="leading-[1.45] break-words"><span className="text-t3">{e.a === 'tripwire' ? 'tripwire' : e.a} · </span>{e.k === 'scan' ? `scan ${e.item}` : e.text}</span>
              </div>
            )
          })}
        </Card>
        <Card title="Attacker sink" right={<span className="font-mono text-[12px] text-t3">/attacker/loot</span>}>
          <div className="p-4 flex items-baseline gap-2.5">
            <span className="text-[32px] font-semibold" style={{ color: loot.length ? 'oklch(0.5 0.18 28)' : ranFw && done ? GREEN_T : INK }}>{loot.length}</span>
            <span className="text-t2">{!started ? 'items received' : loot.length ? 'items exfiltrated or executed' : done ? 'items received · every poisoned item was caught' : 'items received so far'}</span>
          </div>
          {loot.map((l, i) => <div key={i} className="px-4 py-[9px] border-t border-row flex flex-col gap-0.5"><span className="font-mono text-[12.5px] break-words" style={{ color: 'oklch(0.47 0.17 28)' }}>{l.what}</span><span className="text-[12px] text-t3">via {l.via}</span></div>)}
        </Card>
      </div>
      {done && (
        <Card pad>
          <div className="flex flex-col gap-2.5">
            <div className="flex justify-between gap-3 flex-wrap"><span className="font-semibold">Summary delivered to RM</span>
              <span className="text-[12.5px] font-medium" style={{ color: ranFw ? GREEN_T : 'oklch(0.5 0.18 28)' }}>{ranFw ? 'Tripwire on · clean' : 'Tripwire off · poisoned'} · {done.model}</span></div>
            <ul className="m-0 pl-[18px] flex flex-col gap-[5px] leading-normal">{done.summary.map((s: string, i: number) => <li key={i} style={{ color: done.bad?.includes(s) ? 'oklch(0.5 0.18 28)' : INK }}>{s}</li>)}</ul>
          </div>
        </Card>
      )}
    </Page>
  )
}

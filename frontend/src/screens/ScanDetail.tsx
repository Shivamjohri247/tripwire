import { useState } from 'react'
import { api, download, hhmmss } from '../api'
import { useApp, useGet } from '../ctx'
import { AGENT_C, AMBER, Badge, Btn, Card, Dot, GREEN_T, INK, Page, RED, RED_T, Seg, T2, T3, Tabs, TypeChip, typeColor, VC, Verdict } from '../ui'

const STRONG = ['tool_fired', 'canary_leak', 'exfil_render', 'memory_write']

export function ScanDetail({ id }: { id: string }) {
  const a = useApp()
  const [s] = useGet<any>(`/v1/scans/${id}`)
  const [tab, setTab] = useState<'content' | 'trace' | 'det' | 'json'>('content')
  const [mode, setMode] = useState<'original' | 'revealed' | 'sanitized'>('revealed')
  if (!s) return <div className="text-t3">Loading {id}…</div>
  const v = VC[s.verdict]
  const total = s.timings_ms.total || 1
  const t0 = s.trace[0] ? Date.parse(s.trace[0].ts) : 0
  const segs: any[] = s.segments.filter((g: any) => !g.meta)
  const withheld = mode === 'sanitized' && !s.sanitized_content
  const stripHidden = a.saved.policy.stripHidden
  const json = JSON.stringify({ ...s, trace: `${s.trace.length} events` }, null, 2)
  const parts = withheld ? [] : segs.flatMap((g, i) => {
    const hidden = g.visibility.startsWith('hidden:'), enc = g.visibility.startsWith('encoded:')
    const text = g.decoded_text || g.text
    if (mode === 'original') return hidden ? [] : [<span key={i} className="whitespace-pre-wrap">{g.text}</span>]
    if (mode === 'revealed') {
      if (hidden || enc) return [
        <span key={i} className="whitespace-pre-wrap rounded-[3px] px-1 py-0.5" style={{ background: hidden ? 'oklch(0.96 0.025 28)' : 'oklch(0.965 0.03 85)', color: hidden ? 'oklch(0.42 0.16 28)' : 'oklch(0.4 0.1 65)' }}>
          <Tag bg={hidden ? 'oklch(0.55 0.17 28)' : 'oklch(0.58 0.12 65)'}>{enc ? g.visibility.replace('encoded:', 'decoded ') : `${g.visibility}${g.encodings.length ? ' · decoded' : ''}`}</Tag>{text}</span>]
      if (g.finding) return [<span key={i} className="whitespace-pre-wrap px-0.5" style={{ textDecoration: 'underline wavy oklch(0.6 0.19 28)' }}><Tag bg="oklch(0.55 0.17 28)">{g.finding}</Tag>{text}</span>]
      return [<span key={i} className="whitespace-pre-wrap">{text}</span>]
    }
    if ((hidden && stripHidden) || g.finding) return [
      <span key={i} className="whitespace-pre-wrap font-mono text-[12.5px] rounded-[3px] px-1.5 py-0.5" style={{ background: VC.SANITIZE.bg, color: VC.SANITIZE.c }}>[⚠ removed by Tripwire: {g.finding || g.visibility}]</span>, g.text.endsWith('\n') ? '\n' : ' ']
    return [<span key={i} className="whitespace-pre-wrap">{g.text}</span>]
  })
  const props: [string, string, boolean?][] = [['Verdict', s.verdict], ['Risk', Number(s.risk).toFixed(2), true], ['Source', s.source], ['Destination', `${s.destination.name} · ${s.destination.risk} risk`],
    ['Format', s.content_type], ['Size', `${(s.size_bytes / 1024).toFixed(1)} KB`, true], ['Channel', s.channel], ['Taint', s.taint_id, true], ['LLM calls', String(s.llm_calls), true],
    ['Config', `v${s.config_version ?? '—'}`, true], ['Created', hhmmss(s.created_at), true], ...(s.review_id ? [['Review', `${s.review_id}${s.review_decision ? ' · ' + s.review_decision : ''}`, true] as [string, string, boolean]] : [])]
  const STC: Record<string, string> = { triage: AGENT_C.triage, sentinel: AGENT_C.sentinel, detonation: RED, neutralize: AMBER, adjudicate: INK }
  const det = s.detonations as any[]
  return (
    <Page title={<span className="flex gap-2.5 items-center flex-wrap">{s.title}<Verdict v={s.verdict} big />{s.degraded && <span className="h-6 leading-6 px-2 rounded-[5px] border border-ctl text-[12px] text-t2 font-normal">degraded</span>}</span>}
      desc={<span className="font-mono text-[12.5px]">{s.scan_id} · {s.content_type} · {s.filename}</span>}
      actions={<>
        <Btn onClick={() => api(`/v1/scans/${id}/false-positive`, { method: 'POST' }).then(() => a.toast(`${id} marked false positive · added to dev set`))}>Mark false positive</Btn>
        <Btn onClick={() => api(`/v1/scans/${id}/memory`, { method: 'POST' }).then(r => { a.toast(`Memory proposal ${r.review_id} created · see Review queue`); a.refreshPending() }).catch(e => a.toast(e.message, 'warn'))}>Add to attack memory</Btn>
        <Btn primary onClick={() => download(`${id}.json`, JSON.stringify(s, null, 2))}>Download JSON</Btn></>}>
      <div className="border border-line rounded-lg bg-white px-4 py-3.5 flex gap-3 items-start">
        <Dot c={v.dot} size={8} className="mt-1.5" />
        <div className="flex flex-col gap-2 min-w-0"><div className="text-[14.5px] leading-normal">{s.reason}</div>
          <div className="flex gap-1.5 flex-wrap">{(s.attack_types.length ? s.attack_types : ['none']).map((t: string) => <Badge key={t}>{t}</Badge>)}</div></div>
      </div>
      <Tabs tabs={[['content', 'Content', s.findings.length], ['trace', 'Trace', s.trace.length], ['det', 'Detonation', det.length], ['json', 'Response', null]]} value={tab} onChange={setTab} />
      <div className="grid gap-4 items-start" style={{ gridTemplateColumns: 'minmax(0,1fr) 300px' }}>
        <div className="flex flex-col gap-4 min-w-0">
          {tab === 'content' && <>
            <section className="border border-line rounded-lg bg-white overflow-hidden">
              <div className="px-3 py-2 border-b border-div flex items-center gap-2.5 flex-wrap">
                <Seg variant="form" options={[['original', 'Original'], ['revealed', 'Revealed'], ['sanitized', 'Sanitized']]} value={mode} onChange={setMode} />
                <span className="text-t3 text-[12.5px]">{{ original: 'What a person sees', revealed: 'Hidden layers and decoded payloads', sanitized: 'What the agent receives' }[mode]}</span>
              </div>
              <div className="px-[18px] py-4 text-[14px] leading-[1.75] break-words min-h-[160px] max-h-[560px] overflow-auto">
                {withheld && <div className="font-mono text-[13px] px-3.5 py-3 border border-dashed border-off rounded-md text-t2">[Tripwire: content withheld ({s.verdict}){s.review_id ? ` · review ${s.review_id}` : ''}{s.released_content ? ' · released by reviewer' : ''}.]</div>}
                {parts}
              </div>
            </section>
            <Card title={<>Findings <span className="text-t3 font-normal">{s.findings.length}</span></>}>
              {!s.findings.length && <div className="p-4 text-t3">No findings.</div>}
              {s.findings.map((f: any) => (
                <div key={f.segment_id} className="px-4 py-3 border-b border-row flex flex-col gap-[7px]">
                  <div className="flex justify-between gap-2.5"><span className="font-mono text-[12px] text-t2">{f.segment_id} · {f.location}</span><span className="text-[12.5px] text-t2">confidence <span className="text-ink font-medium">{Number(f.confidence).toFixed(2)}</span></span></div>
                  <div className="leading-normal">{f.text}</div>
                  {f.rationale && <div className="text-[12.5px] text-t2">LLM: {f.rationale}</div>}
                  <div className="flex gap-[5px] flex-wrap">{f.attack_types.map((t: string) => <TypeChip key={t} t={t} />)}{f.detected_by.map((b: string) => <Badge key={b} mono>{b}</Badge>)}</div>
                </div>
              ))}
            </Card>
          </>}
          {tab === 'trace' && (
            <section className="border border-line rounded-lg bg-white overflow-hidden">
              <div className="grid gap-3 px-4 h-9 items-center border-b border-line text-[12.5px] text-t2 font-medium bg-page" style={{ gridTemplateColumns: '64px 100px 110px minmax(0,1fr)' }}><span>+ms</span><span>Agent</span><span>Type</span><span>Message</span></div>
              {s.trace.map((e: any, i: number) => (
                <div key={i} className="grid gap-3 px-4 py-2 border-b border-row items-baseline" style={{ gridTemplateColumns: '64px 100px 110px minmax(0,1fr)' }}>
                  <span className="font-mono text-[12px] text-t3">{Math.max(0, Date.parse(e.ts) - t0)}</span>
                  <span className="flex gap-1.5 items-center"><Dot c={AGENT_C[e.agent] || INK} />{e.agent}</span>
                  <span className="font-mono text-[12px]" style={{ color: typeColor(e.type) }}>{e.type}</span>
                  <span className="leading-[1.45] break-words">{e.message}</span>
                </div>
              ))}
            </section>
          )}
          {tab === 'det' && (
            <section className="border border-line rounded-lg bg-white overflow-hidden">
              <div className="px-4 py-3 border-b border-div flex flex-col gap-1"><span className="font-semibold">Detonation chamber</span>
                <span className="text-t2 text-[12.5px]">{det.length ? `Decoy “Bharat Bank RM Copilot” · undefended · task: ${det[0].task}` : 'No gray-zone content was detonated'}</span></div>
              {!det.length && <div className="px-4 py-5 text-t2 leading-normal">{s.risk < 0.15 ? 'Sentinel decided this without detonation (risk below the low band).' : s.degraded ? 'Detonation was unavailable; the failure policy was applied.' : 'Confirmed by Sentinel above the high band, or detonation is off for this destination.'}</div>}
              {!!det.length && <>
                <div className="px-4 py-2.5 flex gap-1.5 flex-wrap border-b border-div items-center"><span className="text-t2 text-[12.5px] mr-1">Canaries</span>{det[0].canaries.map((c: string) => <Badge key={c} mono>{c}</Badge>)}</div>
                <div className="grid" style={{ gridTemplateColumns: 'repeat(auto-fit,minmax(300px,1fr))' }}>
                  {det.map((r, i) => (
                    <div key={i} className="px-4 py-3.5 border-r border-div flex flex-col gap-2.5">
                      <div className="flex justify-between gap-2 flex-wrap"><span className="font-mono text-[12.5px] font-medium">Decoy {r.slot} · {r.model}</span><span className="text-[12.5px] text-t3">{r.error ? 'unavailable' : `${(r.latency_ms / 1000).toFixed(1)} s${r.cached ? ' · cached' : ''}`}</span></div>
                      <pre className="m-0 bg-side border border-[#eceae6] rounded-md px-3 py-2.5 font-mono text-[12px] leading-[1.55] whitespace-pre-wrap break-words max-h-[360px] overflow-auto">{r.error || r.raw_output}</pre>
                      <div className="flex flex-wrap gap-[5px]">{Object.entries(r.signals || {}).filter(([, x]) => x !== null).map(([k, x]: any) => {
                        const hit = Array.isArray(x) ? x.length > 0 : !!x
                        return <Badge key={k} mono bg={hit ? 'oklch(0.965 0.022 28)' : '#f4f3f1'} c={hit ? RED_T : T3}>{k}{hit ? ` · ${STRONG.includes(k) ? 'strong' : 'medium'}` : ''}</Badge>
                      })}</div>
                      {r.signals?.tool_fired?.length > 0 && <div className="font-mono text-[12px] text-body">{r.signals.tool_fired.map((t: any, j: number) => <div key={j}>→ {t.tool}({JSON.stringify(t.args)})</div>)}</div>}
                      {r.signals?.canary_leak?.length > 0 && <div className="font-mono text-[12px]" style={{ color: RED_T }}>leaked: {r.signals.canary_leak.join(', ')}</div>}
                      <div className="text-[13px] text-t2">Decoy verdict <span className="font-semibold" style={{ color: r.verdict === 'malicious' ? RED_T : r.verdict === 'benign' ? GREEN_T : T2 }}>{r.verdict}</span></div>
                    </div>
                  ))}
                </div>
              </>}
            </section>
          )}
          {tab === 'json' && (
            <Card title={<span className="font-mono text-[12.5px] font-normal">ScanResponse</span>} right={<button onClick={() => { navigator.clipboard?.writeText(JSON.stringify(s, null, 2)); a.toast('Copied') }} className="border-0 bg-transparent text-t2 p-0">Copy</button>}>
              <pre className="m-0 px-4 py-3.5 font-mono text-[12px] leading-[1.6] whitespace-pre-wrap break-words max-h-[560px] overflow-auto">{json}</pre>
            </Card>
          )}
        </div>
        <aside className="flex flex-col gap-4">
          <Card title="Details">
            <div className="px-4 pt-1.5 pb-3 flex flex-col">{props.map(([k, val, m]) => <div key={k} className="flex justify-between gap-3 py-1.5 border-b border-row"><span className="text-t2">{k}</span><span className={`text-[12.5px] text-right break-all ${m ? 'font-mono' : ''}`}>{val}</span></div>)}</div>
          </Card>
          <Card title="Pipeline" right={<span className="font-mono text-[12.5px] text-t2">{total} ms</span>}>
            <div className="px-4 py-3 flex flex-col gap-[9px]">
              {[['Triage', 'triage'], ['Sentinel', 'sentinel'], ['Detonator', 'detonation'], ['Neutralizer', 'neutralize'], ['Adjudicator', 'adjudicate']].map(([n, k]) => {
                const ms = s.timings_ms[k] || 0
                return <div key={k} className="flex flex-col gap-1"><div className="flex justify-between text-[12.5px]"><span>{n}</span><span className="font-mono text-t2">{ms ? `${ms} ms` : 'skipped'}</span></div>
                  <div className="h-1 bg-div rounded-sm overflow-hidden"><div className="h-full" style={{ width: ms ? `${Math.max(2, ms / total * 100)}%` : 0, background: STC[k] }} /></div></div>
              })}
            </div>
          </Card>
        </aside>
      </div>
    </Page>
  )
}

const Tag = ({ bg, children }: { bg: string; children: React.ReactNode }) => (
  <span className="font-mono text-[10.5px] font-medium text-white rounded-[3px] px-[5px] py-px mr-1.5 inline-block leading-normal whitespace-nowrap" style={{ background: bg, textDecoration: 'none' }}>{children}</span>
)

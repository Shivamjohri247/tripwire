import { useState } from 'react'
import { hhmmss, pct } from '../api'
import { useApp, useGet } from '../ctx'
import { AGENT_C, AMBER, Btn, Card, Dot, GREEN, INK, Page, RED, Stats, T3, typeColor, VC } from '../ui'

const fmtMs = (ms: number) => (!ms ? '—' : ms >= 1000 ? `${(ms / 1000).toFixed(1)} s` : `${ms} ms`)

export function Overview() {
  const a = useApp()
  const [m] = useGet('/v1/metrics', 5000)
  const [agentF, setAgentF] = useState('all')
  const h = a.health
  const mix = m ? Object.entries(m.mix as Record<string, number>) : []
  const tot = mix.reduce((s, [, v]) => s + v, 0) || 1
  const hours: any[] = m?.hours || []
  const maxH = Math.max(1, ...hours.map(x => x.cpu + x.llm))
  const oldest = m?.oldest_pending ? Math.round((Date.now() / 1000 - m.oldest_pending) / 60) : null
  const AG = ['all', 'triage', 'sentinel', 'session', 'detonator', 'llm', 'neutralizer', 'adjudicator', 'guard']
  const live = a.live.filter(e => agentF === 'all' || e.agent === agentF).slice(0, 80)
  const roles: any[] = (h?.models || []).filter((x: any) => !x.role.includes('fallback') || x.calls || x.errors)
  return (
    <Page title="Overview" desc="Firewall activity across all sources in the last 24 hours."
      actions={<Btn onClick={() => a.setPaused(!a.paused)}><Dot c={a.paused ? '#d6d4cf' : GREEN} size={7} />{a.paused ? 'Paused' : 'Live'}</Btn>}>
      <Stats items={[
        { l: 'Scans', v: (m?.scans_24h ?? 0).toLocaleString('en-IN'), s: `${m?.scans_total ?? 0} all time` },
        { l: 'Threats neutralised', v: m?.threats ?? 0, s: m?.scans_24h ? `${pct(m.threats / m.scans_24h)} of scans` : '—' },
        { l: 'Pending review', v: a.pending, s: a.pending ? `oldest ${oldest} min · SLA ${a.saved.settings.sla} min` : 'queue clear', sc: a.pending ? 'oklch(0.45 0.15 290)' : undefined },
        { l: 'Decided on CPU', v: pct(m?.cpu_share), s: 'no LLM call needed · target ≥ 80%' },
        { l: 'Latency p50', v: fmtMs(m?.latency?.total?.p50), s: `p95 ${fmtMs(m?.latency?.total?.p95)}` },
      ]} />
      <div className="grid gap-4 items-start" style={{ gridTemplateColumns: 'repeat(auto-fit,minmax(380px,1fr))' }}>
        <Card title="Scan volume · last 24 h" right={<span className="flex gap-3.5 text-[12.5px] text-t2"><span className="flex gap-1.5 items-center"><span className="w-2 h-2 rounded-[2px] bg-ink" />Decided on CPU</span><span className="flex gap-1.5 items-center"><span className="w-2 h-2 rounded-[2px]" style={{ background: 'oklch(0.75 0.12 75)' }} />Used LLM</span></span>}>
          <div className="p-4 flex flex-col gap-4">
            <div className="flex items-end gap-[3px] h-[150px] border-b border-div">
              {hours.map((x, i) => (
                <div key={i} className="flex-1 flex flex-col justify-end h-full gap-px" title={`${23 - i} h ago · ${x.cpu} CPU · ${x.llm} LLM`}>
                  <div style={{ height: `${x.llm / maxH * 100}%`, background: 'oklch(0.75 0.12 75)', borderRadius: '2px 2px 0 0' }} />
                  <div style={{ height: `${x.cpu / maxH * 100}%`, background: INK }} />
                </div>
              ))}
            </div>
            <div className="flex flex-col gap-2">
              <div className="flex h-2 rounded overflow-hidden gap-0.5">{mix.map(([l, v]) => v ? <div key={l} style={{ width: `${v / tot * 100}%`, background: VC[l].dot }} /> : null)}</div>
              <div className="flex gap-4 flex-wrap">{mix.map(([l, v]) => <span key={l} className="flex gap-1.5 items-center text-[12.5px] text-t2"><span className="w-2 h-2 rounded-[2px]" style={{ background: VC[l].dot }} />{l} <span className="text-ink font-medium">{pct(v / tot)}</span></span>)}</div>
            </div>
          </div>
        </Card>
        <Card title="Model health" right={<button onClick={() => a.go('models')} className="border-0 bg-transparent text-t2 p-0">Configure →</button>}>
          {!h?.llm_configured && <div className="px-4 py-2.5 border-b border-row text-[12.5px]" style={{ color: 'oklch(0.46 0.11 65)' }}>OPENROUTER_API_KEY is not set: LLM layers are skipped and gray-zone content fails per policy.</div>}
          {roles.map((x: any) => {
            const c = x.breaker === 'open' ? RED : x.breaker === 'half-open' || (x.errors && !x.calls) ? AMBER : GREEN
            const st = x.breaker === 'open' ? 'breaker open' : x.breaker === 'half-open' ? 'degraded' : x.calls ? 'healthy' : 'idle'
            return (
              <div key={x.model + x.role} className="px-4 py-2.5 border-b border-row grid gap-3 items-center" style={{ gridTemplateColumns: 'minmax(0,1fr) auto' }}>
                <div className="flex flex-col gap-0.5 min-w-0"><span className="font-mono text-[12.5px] truncate">{x.model}</span><span className="text-[12.5px] text-t3">{x.role}</span></div>
                <div className="flex flex-col gap-0.5 items-end"><span className="flex gap-1.5 items-center text-[12.5px] font-medium"><Dot c={c} size={7} />{st}</span>
                  <span className="text-[12px] text-t3" title={x.last_error}>{x.p50 ? `p50 ${fmtMs(Math.round(x.p50))}` : ''}{x.errors ? ` · ${x.errors} err` : ''}</span></div>
              </div>
            )
          })}
          <div className="px-4 py-3 grid grid-cols-4 gap-2">
            {[['Triage', 'triage'], ['Sentinel', 'sentinel'], ['Detonator', 'detonation'], ['End to end', 'total']].map(([l, k]) => (
              <div key={k} className="flex flex-col gap-0.5"><span className="text-[12px] text-t3">{l} p50</span><span className="font-medium">{fmtMs(m?.latency?.[k]?.p50)}</span><span className="text-[12px] text-t3">p95 {fmtMs(m?.latency?.[k]?.p95)}</span></div>
            ))}
          </div>
          <div className="px-4 pb-3 text-[12px] text-t3">LLM cache: {h?.cache_entries ?? 0} entries · {h?.cache_hits ?? 0} hits this session</div>
        </Card>
      </div>
      <section className="border border-line rounded-lg bg-white overflow-hidden">
        <div className="px-4 py-2.5 border-b border-div flex gap-1.5 items-center flex-wrap">
          <span className="font-semibold mr-2.5">Trace events</span>
          {AG.map(x => <button key={x} onClick={() => setAgentF(x)} className="h-[26px] border px-[9px] rounded-[5px] text-[12.5px]" style={{ background: agentF === x ? INK : '#fff', color: agentF === x ? '#fff' : '#3a3935', borderColor: agentF === x ? INK : '#e2e0db' }}>{x}</button>)}
          <span className="ml-auto font-mono text-[12px] text-t3">GET /v1/events</span>
        </div>
        <div className="max-h-[320px] overflow-auto">
          {!live.length && <div className="p-8 text-center text-t3">No events yet. Run a scan or the Arena.</div>}
          {live.map((e, i) => (
            <div key={i} onClick={() => e.scan_id && a.go(`scan/${e.scan_id}`)} className="grid gap-3 px-4 py-[7px] border-b border-row text-[13px] items-baseline" style={{ gridTemplateColumns: '76px 96px 104px minmax(0,1fr)', cursor: e.scan_id ? 'pointer' : 'default' }}>
              <span className="font-mono text-[12px] text-t3">{hhmmss(e.ts)}</span>
              <span className="flex gap-1.5 items-center"><Dot c={AGENT_C[e.agent] || INK} />{e.agent}</span>
              <span className="font-mono text-[12px]" style={{ color: typeColor(e.type) }}>{e.type}</span>
              <span className="text-body break-words">{e.scan_id && <span className="font-mono text-[12px]" style={{ color: T3 }}>{e.scan_id} · </span>}{e.message}</span>
            </div>
          ))}
        </div>
      </section>
    </Page>
  )
}

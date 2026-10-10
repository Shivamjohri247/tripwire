import { useState } from 'react'
import { api } from './api'
import { AppProvider, useApp } from './ctx'
import { Arena } from './screens/Arena'
import { CfgPage, CFG_PAGES } from './screens/Config'
import { Evals } from './screens/Evals'
import { History, Keys } from './screens/Admin'
import { Overview } from './screens/Overview'
import { Playground } from './screens/Playground'
import { RedTeam } from './screens/RedTeam'
import { Review } from './screens/Review'
import { ScanDetail } from './screens/ScanDetail'
import { Scans } from './screens/Scans'
import { Sessions, ToolCalls } from './screens/Sessions'
import { diffCfg, GREEN, INK, Modal, RED, VIOLET } from './ui'

const GROUPS: [string, [string, string][]][] = [
  ['Monitor', [['overview', 'Overview'], ['scans', 'Scans'], ['sessions', 'Sessions'], ['toolcalls', 'Tool calls'], ['review', 'Review queue']]],
  ['Test', [['arena', 'Arena'], ['playground', 'Scan content'], ['redteam', 'Red team'], ['evals', 'Evaluations']]],
  ['Configure', [['sources', 'Sources'], ['destinations', 'Destinations'], ['detection', 'Classifiers & decoy'], ['policies', 'Verdict policy'], ['guard', 'Tool policies'], ['models', 'Models']]],
  ['Admin', [['keys', 'API keys & webhooks'], ['history', 'Config history'], ['settings', 'Settings']]],
]

export default function App() {
  return <AppProvider><Shell /></AppProvider>
}

function Shell() {
  const a = useApp()
  const [scr, arg] = a.route
  const active = scr === 'scan' ? 'scans' : scr
  const label = GROUPS.flatMap(g => g[1]).find(i => i[0] === active)?.[1] || ''
  const llmOk = a.health?.llm_configured
  const conn = !a.health ? { dot: RED, label: 'API unreachable' } : llmOk ? { dot: GREEN, label: 'Tripwire API' } : { dot: 'oklch(0.72 0.14 75)', label: 'API · no LLM key' }
  const screen = (() => {
    switch (scr) {
      case 'overview': return <Overview />
      case 'scans': return <Scans />
      case 'scan': return <ScanDetail id={arg} />
      case 'sessions': return <Sessions />
      case 'toolcalls': return <ToolCalls />
      case 'review': return <Review />
      case 'arena': return <Arena />
      case 'playground': return <Playground />
      case 'redteam': return <RedTeam />
      case 'evals': return <Evals />
      case 'keys': return <Keys />
      case 'history': return <History />
      default: return CFG_PAGES[scr] ? <CfgPage scr={scr} /> : <Overview />
    }
  })()
  const projector = new URLSearchParams(location.search).has('projector')
  return (
    <div className={projector ? 'projector' : ''} style={{ display: 'grid', gridTemplateColumns: '236px minmax(0,1fr)', minHeight: '100vh' }}>
      <aside className="border-r border-line bg-side flex flex-col sticky top-0 h-screen box-border">
        <div className="h-[52px] flex items-center gap-2.5 px-4 border-b border-line">
          <div className="w-6 h-6 rounded-md bg-ink grid place-items-center flex-none"><div className="w-[9px] h-[9px] rounded-[2px] rotate-45" style={{ border: '1.8px solid #f6f5f3' }} /></div>
          <div className="flex flex-col leading-[1.2] min-w-0"><span className="font-semibold text-[14px]">Tripwire</span><span className="text-[12px] text-t3 truncate">Bharat Bank · Local</span></div>
        </div>
        <nav className="flex-1 overflow-y-auto overflow-x-hidden px-2.5 py-3 flex flex-col gap-4">
          {GROUPS.map(([g, items]) => (
            <div key={g} className="flex flex-col gap-px">
              <div className="text-[11.5px] font-medium text-t3 px-2 pb-1.5">{g}</div>
              {items.map(([k, l]) => {
                const on = active === k
                const badge = k === 'review' && a.pending > 0 ? a.pending : null
                return (
                  <button key={k} onClick={() => a.go(k)} className="flex items-center gap-2 h-[30px] border-0 px-2 rounded-md text-left" style={{ background: on ? '#e9e7e3' : 'transparent', color: on ? INK : '#3a3935', fontWeight: on ? 600 : 500 }}>
                    <span className="w-1.5 h-1.5 rounded-[2px] flex-none" style={{ background: on ? INK : '#cfccc5' }} />
                    <span className="flex-1">{l}</span>
                    {badge != null && <span className="text-[11.5px] font-medium min-w-[18px] h-[18px] leading-[18px] text-center rounded-[9px] px-[5px] text-white" style={{ background: VIOLET }}>{badge}</span>}
                  </button>
                )
              })}
            </div>
          ))}
        </nav>
        <div className="border-t border-line px-4 py-3 flex items-center gap-2.5">
          <div className="w-7 h-7 rounded-full bg-ctl grid place-items-center text-[11.5px] font-semibold">AR</div>
          <div className="flex flex-col leading-[1.25] min-w-0"><span className="font-medium">Ananya Rao</span><span className="text-[12px] text-t3">Security reviewer</span></div>
        </div>
      </aside>
      <div className="flex flex-col min-w-0">
        <header className="h-[52px] border-b border-line bg-page flex items-center gap-2.5 px-5 sticky top-0 z-[5]">
          <div className="flex items-center gap-2 flex-auto min-w-[170px] overflow-hidden whitespace-nowrap">
            <button onClick={() => a.go(active)} className="border-0 bg-transparent p-0" style={{ color: scr === 'scan' ? '#8b8984' : INK, fontWeight: scr === 'scan' ? 400 : 500 }}>{label}</button>
            {scr === 'scan' && <><span className="text-[#c4c2bc]">/</span><span className="font-medium truncate">{arg}</span></>}
          </div>
          <div className="flex items-center gap-1.5 h-8 border border-ctl rounded-md bg-white px-2.5 min-w-[110px]" style={{ flex: '0 1 240px' }}>
            <span className="w-2.5 h-2.5 rounded-full flex-none" style={{ border: '1.5px solid #8b8984' }} />
            <input value={a.q} onChange={e => a.setQ(e.target.value)} onKeyDown={e => e.key === 'Enter' && a.go('scans')} placeholder="Search scans…" className="border-0 bg-transparent flex-1 min-w-0 !shadow-none" />
            <span className="text-[11px] text-t3 border border-ctl rounded px-1">↵</span>
          </div>
          <button onClick={() => a.go('settings')} className="flex items-center gap-[7px] h-8 border border-ctl rounded-md bg-white px-2.5 whitespace-nowrap"><span className="w-[7px] h-[7px] rounded-full" style={{ background: conn.dot }} />{conn.label}</button>
        </header>
        <main className="px-7 pt-6 pb-24 flex flex-col gap-5 min-w-0 max-w-[1480px] w-full box-border">{screen}</main>
      </div>
      <UnsavedBar />
    </div>
  )
}

function UnsavedBar() {
  const a = useApp()
  const [open, setOpen] = useState(false)
  const [note, setNote] = useState('')
  const d = diffCfg(a.saved, a.draft)
  if (!d.length) return null
  const publish = async () => {
    try {
      const r = await api('/v1/config/publish', { json: { config: a.draft, note } })
      await a.reloadConfig()
      setOpen(false); setNote('')
      a.toast(`Config v${r.version} published · applies to new scans`)
    } catch (e: any) { a.toast(`Publish failed: ${e.message}`, 'err') }
  }
  return (
    <>
      <div className="fixed left-1/2 bottom-5 -translate-x-1/2 bg-ink text-white rounded-lg pl-4 pr-2 py-2 flex gap-3.5 items-center z-20 whitespace-nowrap" style={{ boxShadow: '0 8px 24px rgba(0,0,0,.18)' }}>
        <span>{d.length} unsaved change{d.length > 1 ? 's' : ''}</span>
        <button onClick={() => a.setDraft(() => a.saved)} className="h-[30px] border border-[#45443f] rounded-md bg-transparent text-white px-3">Discard</button>
        <button onClick={() => setOpen(true)} className="h-[30px] border-0 rounded-md bg-white text-ink px-3 font-semibold">Publish v{a.version + 1}</button>
      </div>
      {open && (
        <Modal onClose={() => setOpen(false)}>
          <div className="px-5 py-4 border-b border-line flex flex-col gap-[3px]"><span className="font-semibold text-[15px]">Publish config v{a.version + 1}</span><span className="text-[12.5px] text-t2">New scans use this version immediately. You can roll back from Config history.</span></div>
          <div className="flex-1 overflow-auto">
            {d.slice(0, 14).map(x => (
              <div key={x.path} className="grid gap-2.5 px-5 py-[7px] border-b border-row font-mono text-[12px]" style={{ gridTemplateColumns: 'minmax(150px,1fr) minmax(0,1fr) minmax(0,1fr)' }}>
                <span className="break-all">{x.path}</span><span className="break-all" style={{ color: 'oklch(0.45 0.15 28)' }}>{x.before.slice(0, 40)}</span><span className="break-all" style={{ color: 'oklch(0.4 0.1 155)' }}>{x.after.slice(0, 40)}</span>
              </div>
            ))}
            {d.length > 14 && <div className="px-5 py-[7px] text-[12.5px] text-t3">and {d.length - 14} more</div>}
          </div>
          <div className="px-5 py-3.5 border-t border-line flex flex-col gap-2.5">
            <input value={note} onChange={e => setNote(e.target.value)} placeholder="Describe this change (shown in history)" className="h-[34px] border border-ctl rounded-md px-2.5" />
            <div className="flex justify-end gap-2">
              <button onClick={() => setOpen(false)} className="h-8 border border-ctl rounded-md bg-white px-3">Cancel</button>
              <button onClick={publish} className="h-8 border-0 rounded-md bg-ink text-white px-3.5 font-medium">Publish</button>
            </div>
          </div>
        </Modal>
      )}
    </>
  )
}

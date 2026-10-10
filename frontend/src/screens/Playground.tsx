import { useState } from 'react'
import { api, upload } from '../api'
import { useApp, useGet } from '../ctx'
import { AMBER, Badge, Btn, Card, Dot, inputCls, Page, RED, selectCls, Spinner, T2, Tabs, Toggle, VC, Verdict } from '../ui'

const FMT = ['auto', 'email', 'html', 'pdf', 'docx', 'markdown', 'json', 'image', 'code', 'ics', 'chat', 'text']
const BINARY = ['pdf', 'docx', 'image']

export function Playground() {
  const a = useApp()
  const [corpus] = useGet<any>('/v1/corpus')
  const [tab, setTab] = useState<'upload' | 'paste' | 'url'>('upload')
  const [text, setText] = useState('')
  const [url, setUrl] = useState('')
  const [fmt, setFmt] = useState('auto')
  const [source, setSource] = useState('playground')
  const [dest, setDest] = useState('rm-copilot')
  const [task, setTask] = useState('')
  const [detonate, setDetonate] = useState(true)
  const [sentinelOnly, setSentinelOnly] = useState(false)
  const [busy, setBusy] = useState(false)
  const [last, setLast] = useState<any>(null)
  const [batch, setBatch] = useState<any[]>([])
  const [drag, setDrag] = useState(false)
  const d = a.saved.destinations[dest] || {}
  const src = a.saved.sources[source] || {}
  const meta = () => ({ content_type: fmt === 'auto' ? undefined : fmt, source, channel: src.channel, destination: { name: dest, risk: d.risk, tools: d.tools },
    task: task || undefined, options: { detonate, sentinel_only: sentinelOnly } })
  const scanFiles = async (files: File[]) => {
    if (!files.length) return
    const rows = files.map((f, i) => ({ bid: `${Date.now()}_${i}`, name: f.name, size: f.size > 1048576 ? `${(f.size / 1048576).toFixed(1)} MB` : `${(f.size / 1024).toFixed(1)} KB`, status: 'queued' }))
    setBatch(b => [...rows, ...b].slice(0, 30)); setBusy(true)
    for (let i = 0; i < files.length; i++) {
      const bid = rows[i].bid
      setBatch(b => b.map(x => x.bid === bid ? { ...x, status: 'scanning' } : x))
      try {
        const fd = new FormData(); fd.append('file', files[i]); fd.append('meta', JSON.stringify({ ...meta(), content_type: files.length > 1 ? undefined : meta().content_type }))
        const r = await upload('/v1/scan', fd)
        setLast(r); setBatch(b => b.map(x => x.bid === bid ? { ...x, status: r.verdict, id: r.scan_id } : x))
      } catch (e: any) { setBatch(b => b.map(x => x.bid === bid ? { ...x, status: 'error', err: e.message } : x)) }
    }
    setBusy(false); a.refreshPending()
  }
  const run = async () => {
    if (busy) return
    if (tab === 'upload') { (document.getElementById('pg-files') as HTMLInputElement)?.click(); return }
    setBusy(true)
    try {
      const r = await api('/v1/scan', { json: tab === 'url' ? { ...meta(), url } : { ...meta(), content: text } })
      setLast(r); a.refreshPending()
    } catch (e: any) { a.toast(`Scan failed: ${e.message}`, 'err') }
    setBusy(false)
  }
  const loadSample = async (id: string) => {
    const it = corpus.items.find((x: any) => x.id === id)
    const blob = await (await fetch(`/v1/corpus/${id}/file`)).blob()
    if (BINARY.includes(it.fmt)) { setTab('upload'); scanFiles([new File([blob], it.file)]) }
    else { setTab('paste'); setText(await blob.text()); setFmt(it.fmt) }
  }
  const preview = JSON.stringify({ content: tab === 'paste' ? (text.length > 80 ? text.slice(0, 80) + '…' : text) : undefined, file: tab === 'upload' ? '<multipart file>' : undefined,
    url: tab === 'url' ? url : undefined, ...meta(), task: task || d.task }, null, 2)
  return (
    <Page title="Scan content" desc="Upload files, paste text or fetch a URL. Every result is added to Scans.">
      <div className="grid gap-4 items-start" style={{ gridTemplateColumns: 'repeat(auto-fit,minmax(420px,1fr))' }}>
        <section className="border border-line rounded-lg bg-white overflow-hidden">
          <div className="px-4"><Tabs pad="py-[11px]" tabs={[['upload', 'Upload files'], ['paste', 'Paste text'], ['url', 'Fetch URL']]} value={tab} onChange={setTab} /></div>
          <div className="p-4 flex flex-col gap-3.5">
            {tab === 'paste' && <textarea value={text} onChange={e => setText(e.target.value)} rows={10} placeholder="Paste an email, web page HTML, JSON tool output, markdown…" className="w-full box-border border border-ctl rounded-md px-3 py-2.5 font-mono text-[12.5px] leading-[1.6] resize-y bg-white" />}
            {tab === 'upload' && <>
              <label onDragOver={e => { e.preventDefault(); setDrag(true) }} onDragLeave={() => setDrag(false)} onDrop={e => { e.preventDefault(); setDrag(false); scanFiles([...e.dataTransfer.files]) }}
                className="flex flex-col items-center justify-center gap-1.5 min-h-[170px] rounded-lg cursor-pointer text-center p-4" style={{ border: `1.5px dashed ${drag ? '#1c1b19' : '#d6d4cf'}`, background: drag ? '#f4f3f1' : '#fbfaf9' }}>
                <input id="pg-files" type="file" multiple className="hidden" onChange={e => { scanFiles([...(e.target.files || [])]); e.target.value = '' }} accept=".eml,.html,.htm,.md,.pdf,.docx,.json,.txt,.ics,.png,.jpg,.jpeg,.js,.ts,.py,.yaml,.yml,.cursorrules,.mdc" />
                <span className="font-semibold">Drop files here or click to browse</span>
                <span className="text-t2 text-[12.5px]">.eml · .html · .pdf · .docx · .md · .json · .ics · .txt · code · images</span>
                <span className="text-t3 text-[12px]">Up to {src.maxMb || 10} MB each · parsed, OCR’d and detonated by the Tripwire API</span>
              </label>
              {!!batch.length && <div className="border border-line rounded-md overflow-hidden">{batch.map(b => {
                const V = VC[b.status]
                return <div key={b.bid} className="grid gap-2.5 items-center px-3 h-10 border-b border-row" style={{ gridTemplateColumns: 'minmax(0,1fr) 70px 120px 60px' }}>
                  <span className="truncate font-medium">{b.name}</span><span className="text-[12px] text-t3">{b.size}</span>
                  <span className="inline-flex items-center gap-1.5 text-[12px] font-medium" title={b.err} style={{ color: V ? V.c : b.status === 'error' ? 'oklch(0.47 0.17 28)' : T2 }}><Dot c={V ? V.dot : b.status === 'scanning' ? AMBER : b.status === 'error' ? RED : '#d6d4cf'} size={7} />{b.status}</span>
                  {b.id && <button onClick={() => a.go(`scan/${b.id}`)} className="border-0 bg-transparent p-0 underline text-[12.5px] text-right">Inspect</button>}
                </div>
              })}</div>}
            </>}
            {tab === 'url' && <div className="flex flex-col gap-1.5"><span className="font-medium">Page URL</span><input value={url} onChange={e => setUrl(e.target.value)} placeholder="https://example.com/article" className={`${inputCls} h-[34px] font-mono text-[12.5px]`} />
              <span className="text-[12.5px] text-t3">Fetched server-side by the Tripwire web fetcher (public http(s) only; private and loopback addresses are refused).</span></div>}
            {corpus && <div className="flex gap-1.5 flex-wrap items-center"><span className="text-[12.5px] text-t3">Corpus</span>
              <select defaultValue="" onChange={e => { if (e.target.value) loadSample(e.target.value); e.target.value = '' }} className={selectCls}>
                <option value="">Load a sample…</option>{corpus.items.map((x: any) => <option key={x.id} value={x.id}>{x.id} · {x.title} ({x.fmt}{x.type ? ` · ${x.type.split(' ')[0]}` : ` · ${x.kind.replace('_', ' ')}`})</option>)}
              </select></div>}
            <div className="grid gap-3 pt-3.5 border-t border-div" style={{ gridTemplateColumns: 'repeat(auto-fit,minmax(170px,1fr))' }}>
              <L t="Source"><select value={source} onChange={e => setSource(e.target.value)} className={selectCls}>{Object.entries(a.saved.sources).filter(([, x]: any) => x.enabled).map(([id, x]: any) => <option key={id} value={id}>{x.name}</option>)}</select></L>
              <L t="Destination"><select value={dest} onChange={e => setDest(e.target.value)} className={selectCls}>{Object.entries(a.saved.destinations).map(([id, x]: any) => <option key={id} value={id}>{x.name} · {x.risk}</option>)}</select></L>
              <L t="Content type"><select value={fmt} onChange={e => setFmt(e.target.value)} className={selectCls}>{FMT.map(f => <option key={f} value={f}>{f === 'auto' ? 'Auto-detect' : f}</option>)}</select></L>
              <L t="Agent task"><input value={task || d.task || ''} onChange={e => setTask(e.target.value)} className={inputCls} /></L>
            </div>
            <div className="flex justify-between items-center gap-3 flex-wrap">
              <div className="flex gap-4 flex-wrap"><Toggle on={detonate} onChange={setDetonate} label="Detonate gray zone" /><Toggle on={sentinelOnly} onChange={setSentinelOnly} label="Sentinel only" /></div>
              <Btn primary onClick={run} className="h-[34px] px-4">{busy && <Spinner />}{busy ? 'Scanning…' : tab === 'upload' ? 'Choose files' : 'Run scan'}</Btn>
            </div>
          </div>
        </section>
        <div className="flex flex-col gap-4">
          <Card title="Result">
            {!last ? <div className="px-4 py-7 text-t3 text-center">Run a scan to see the verdict.</div> : (
              <div className="px-4 py-3.5 flex flex-col gap-2.5">
                <div className="flex justify-between items-center gap-2 flex-wrap"><Verdict v={last.verdict} big /><span className="font-mono text-[12.5px] text-t2">risk {Number(last.risk).toFixed(2)} · {last.timings_ms.total} ms · {last.llm_calls} LLM calls</span></div>
                <div className="leading-normal">{last.reason}</div>
                <div className="flex gap-[5px] flex-wrap">{(last.attack_types.length ? last.attack_types : ['none']).map((t: string) => <Badge key={t}>{t}</Badge>)}</div>
                <Btn className="self-start font-medium" onClick={() => a.go(`scan/${last.scan_id}`)}>Open in inspector</Btn>
              </div>
            )}
          </Card>
          <Card title="Request" right={<span className="font-mono text-[12px] text-t3">POST /v1/scan</span>}>
            <pre className="m-0 px-4 py-3 font-mono text-[12px] leading-[1.6] whitespace-pre-wrap break-words text-body">{preview}</pre>
          </Card>
        </div>
      </div>
    </Page>
  )
}

const L = ({ t, children }: { t: string; children: React.ReactNode }) => <label className="flex flex-col gap-[5px]"><span className="text-[12.5px] text-t2">{t}</span>{children}</label>

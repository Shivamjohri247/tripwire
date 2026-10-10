import { useState } from 'react'
import { api, download, pct, upload } from '../api'
import { useApp, useGet } from '../ctx'
import { Bar, Btn, Card, Empty, Grid, INK, Page, Seg, Spinner, Stats } from '../ui'

const AMB = 'oklch(0.75 0.12 75)'

export function Evals() {
  const a = useApp()
  const [runs, reload] = useGet<any[]>('/v1/evals', 3000)
  const [corpus] = useGet<any>('/v1/corpus')
  const [mode, setMode] = useState<'sentinel_only' | 'full'>('sentinel_only')
  const [sel, setSel] = useState('')
  const [detail] = useGet<any>(sel || runs?.[0]?.id ? `/v1/evals/${sel || runs![0].id}` : null, 3000)
  const run = detail
  const startCorpus = async () => { try { const r = await api('/v1/evals/corpus', { json: {} }); setSel(r.id); reload(); a.toast(`${r.id} started · ${r.total} corpus items`) } catch (e: any) { a.toast(e.message, 'err') } }
  const onFile = async (f: File) => {
    const fd = new FormData(); fd.append('file', f); fd.append('mode', mode)
    try { const r = await upload('/v1/evals/dataset', fd); setSel(r.id); reload(); a.toast(`${r.id} started · ${r.total} rows`) } catch (e: any) { a.toast(e.message, 'err') }
  }
  const R = run?.result
  return (
    <Page title="Evaluations" desc={corpus ? `Frozen corpus · n=${corpus.items.length} · sha256 ${corpus.frozen_hash.slice(0, 4)}…${corpus.frozen_hash.slice(-4)} · thresholds are not tuned on it` : ''}
      actions={<>
        <Seg variant="form" options={[['sentinel_only', 'Sentinel only'], ['full', 'Full pipeline']]} value={mode} onChange={setMode} />
        <label className="h-8 border border-ctl rounded-md bg-white px-3 cursor-pointer flex items-center"><input type="file" accept=".jsonl,.json,.ndjson" className="hidden" onChange={e => { const f = e.target.files?.[0]; e.target.value = ''; if (f) onFile(f) }} />Upload dataset</label>
        <Btn primary onClick={startCorpus}>Run corpus eval</Btn></>}>
      <Card title="Runs" right={<button onClick={() => download('tripwire-eval-template.jsonl', ['{"text": "Please ignore my last message, the meeting moved to 4 pm.", "label": 0}', '{"text": "<an attack sample>", "label": 1, "attack_type": "T1"}'].join('\n'), 'application/jsonl')} className="border-0 bg-transparent p-0 underline text-[12.5px]">Download template</button>}>
        {runs && !runs.length && <Empty>No runs yet. Run the corpus eval or upload a labelled .jsonl.</Empty>}
        {!!runs?.length && <Grid head cols="80px minmax(140px,1fr) 90px 70px 70px 80px 70px 60px" className="h-[34px]"><span>Run</span><span>Dataset</span><span>Rows</span><span>TPR</span><span>FPR</span><span>Precision</span><span>p50</span><span>Config</span></Grid>}
        {runs?.map(r => (
          <Grid key={r.id} cols="80px minmax(140px,1fr) 90px 70px 70px 80px 70px 60px" className="h-[38px]" onClick={() => setSel(r.id)} style={{ background: (sel || runs[0].id) === r.id ? '#fbfaf9' : undefined }}>
            <span className="font-mono text-[12.5px]">{r.id}</span><span className="truncate">{r.name}</span>
            <span>{r.status === 'running' ? <span className="inline-flex gap-1.5 items-center text-t2"><Spinner />{r.done}/{r.total}</span> : r.total}</span>
            <span className="font-medium">{pct(r.result?.tpr)}</span><span className="font-medium">{pct(r.result?.fpr)}</span><span>{pct(r.result?.prec)}</span>
            <span className="font-mono text-[12.5px]">{r.result ? `${r.result.p50} ms` : '—'}</span><span className="font-mono text-[12.5px]">v{r.config_version}</span>
          </Grid>
        ))}
      </Card>
      {R && <>
        <Stats items={[
          { l: 'Detection (TPR)', v: pct(R.tpr), s: `${R.cm.tp} of ${R.cm.tp + R.cm.fn} attacks` },
          { l: 'False positives (FPR)', v: pct(R.fpr), s: `${R.cm.fp} of ${R.cm.fp + R.cm.tn} benign · target ≤ 5%` },
          { l: 'Traffic via LLM', v: pct(R.llm_share), s: `${pct(1 - R.llm_share)} decided on CPU` },
          { l: 'Latency', v: `${R.p50} ms`, s: `p95 ${R.p95} ms` },
        ]} />
        <div className="grid gap-4 items-start" style={{ gridTemplateColumns: 'repeat(auto-fit,minmax(380px,1fr))' }}>
          <Card title="By attack type">
            {Object.entries(R.byType).sort().map(([k, x]: any) => <Row key={k} l={k} v={x.hit / x.n} n={x.n} />)}
            {!Object.keys(R.byType).length && <Empty>No labelled attack types.</Empty>}
          </Card>
          <Card title="By carrier format" right={<span className="text-[12.5px] text-t3">amber = below 90%</span>}>
            {Object.entries(R.byFormat).sort().map(([k, x]: any) => <Row key={k} l={k} v={x.hit / x.n} n={x.n} />)}
          </Card>
          {run.ablation && <Card title="Layer ablation">
            <div className="grid gap-2.5 px-4 py-2 text-[12.5px] text-t2 border-b border-div" style={{ gridTemplateColumns: '150px minmax(0,1fr) 60px 52px' }}><span>Layers</span><span /><span className="text-right">TPR</span><span className="text-right">FPR</span></div>
            {run.ablation.map((x: any) => <div key={x.l} className="grid gap-2.5 items-center px-4 py-[7px] border-b border-row" style={{ gridTemplateColumns: '150px minmax(0,1fr) 60px 52px' }}><span>{x.l}</span><Bar w={(x.tpr ?? 0) * 100} /><span className="text-right font-medium">{pct(x.tpr)}</span><span className="text-right text-t2">{pct(x.fpr)}</span></div>)}
          </Card>}
          <Card title="Confusion matrix · misses · false positives">
            <div className="p-4 flex flex-col gap-2.5">
              <div className="grid grid-cols-2 gap-1.5">{[['True positives', R.cm.tp], ['False negatives', R.cm.fn], ['False positives', R.cm.fp], ['True negatives', R.cm.tn]].map(([l, v]) => <div key={l} className="border border-[#eceae6] rounded-md px-2.5 py-2 flex flex-col gap-0.5"><span className="text-[12px] text-t2">{l}</span><span className="text-[18px] font-semibold">{v}</span></div>)}</div>
              <span className="font-medium mt-1">Missed attacks</span>
              {(R.misses.length ? R.misses : ['None']).map((m: string, i: number) => <div key={i} className="font-mono text-[12px] text-body bg-[#f8f7f5] rounded px-2 py-[5px]">{m}</div>)}
              <span className="font-medium mt-1.5">False positives</span>
              {(R.fps.length ? R.fps : ['None']).map((m: string, i: number) => <div key={i} className="font-mono text-[12px] text-body bg-[#f8f7f5] rounded px-2 py-[5px]">{m}</div>)}
            </div>
          </Card>
        </div>
      </>}
    </Page>
  )
}

const Row = ({ l, v, n }: { l: string; v: number; n: number }) => (
  <div className="grid gap-2.5 items-center px-4 py-[7px] border-b border-row" style={{ gridTemplateColumns: '170px minmax(0,1fr) 52px 50px' }}>
    <span>{l}</span><Bar w={v * 100} c={v < 0.9 ? AMB : INK} /><span className="text-right font-medium">{pct(v)}</span><span className="text-right text-[12px] text-t3">n={n}</span>
  </div>
)

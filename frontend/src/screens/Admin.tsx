import { useState } from 'react'
import { ago, api } from '../api'
import { useApp, useGet } from '../ctx'
import { Badge, Btn, Card, Chips, diffCfg, Empty, Grid, inputCls, LinkBtn, Page, selectCls } from '../ui'

const SCOPES: [string, string][] = [['scan', 'scan'], ['toolcall', 'toolcall'], ['read', 'read'], ['admin', 'admin']]
const EVENTS: [string, string][] = [['QUARANTINE', 'QUARANTINE'], ['ESCALATE', 'ESCALATE'], ['SANITIZE', 'SANITIZE'], ['bypass', 'bypass'], ['config_published', 'config_published']]

export function Keys() {
  const a = useApp()
  const [keys, reloadKeys] = useGet<any[]>('/v1/keys')
  const [hooks, reloadHooks] = useGet<any[]>('/v1/webhooks')
  const [name, setName] = useState('')
  const [scopes, setScopes] = useState<string[]>(['scan', 'toolcall'])
  const [expiry, setExpiry] = useState('90')
  const [secret, setSecret] = useState('')
  const [url, setUrl] = useState('')
  const [events, setEvents] = useState<string[]>(['QUARANTINE', 'ESCALATE'])
  const err = (e: any) => a.toast(e.message, 'err')
  const createKey = async () => {
    try { const r = await api('/v1/keys', { json: { name, scopes, expiry } }); setSecret(r.secret); setName(''); reloadKeys() } catch (e) { err(e) }
  }
  const revoke = async (id: string) => { try { await api(`/v1/keys/${id}/revoke`, { method: 'POST' }); reloadKeys(); a.toast(`${id} revoked`) } catch (e) { err(e) } }
  const addHook = async () => { try { await api('/v1/webhooks', { json: { url, events } }); setUrl(''); reloadHooks() } catch (e) { err(e) } }
  const delHook = async (id: string) => { try { await api(`/v1/webhooks/${id}`, { method: 'DELETE' }); reloadHooks() } catch (e) { err(e) } }
  const testHook = async (id: string) => { try { const r = await api(`/v1/webhooks/${id}/test`, { method: 'POST' }); reloadHooks(); a.toast(`Delivered · ${r.last}`) } catch (e) { err(e) } }
  return (
    <Page title="API keys & webhooks" desc="Issue keys for agents that call /v1/scan and /v1/toolcall, and push verdict events to your SIEM.">
      <Card title="API keys">
        <div className="p-4 flex gap-2 items-center flex-wrap border-b border-div">
          <input value={name} onChange={e => setName(e.target.value)} placeholder="Key name, e.g. rm-copilot-prod" className={`${inputCls} flex-1 min-w-[200px]`} />
          <Chips options={SCOPES} value={scopes} onChange={setScopes} />
          <select value={expiry} onChange={e => setExpiry(e.target.value)} className={selectCls}>{['30', '90', '365', 'never'].map(x => <option key={x} value={x}>{x === 'never' ? 'No expiry' : `${x} days`}</option>)}</select>
          <Btn primary onClick={createKey} disabled={!name.trim() || !scopes.length}>Create key</Btn>
        </div>
        {secret && <div className="px-4 py-3 border-b border-div flex gap-2.5 items-center flex-wrap bg-[#fbfaf9]">
          <span className="text-[12.5px] text-t2">Copy now, it is not shown again:</span><code className="font-mono text-[12.5px] break-all">{secret}</code>
          <Btn small onClick={() => { navigator.clipboard?.writeText(secret); a.toast('Copied') }}>Copy</Btn><LinkBtn onClick={() => setSecret('')}>Dismiss</LinkBtn>
        </div>}
        {keys && !keys.length && <Empty>No keys yet.</Empty>}
        {!!keys?.length && <Grid head cols="minmax(140px,1fr) 150px minmax(120px,1fr) 80px 100px 80px"><span>Name</span><span>Key</span><span>Scopes</span><span>Expiry</span><span>Created</span><span /></Grid>}
        {keys?.map(k => (
          <Grid key={k.id} cols="minmax(140px,1fr) 150px minmax(120px,1fr) 80px 100px 80px" className="h-[40px]" style={{ opacity: k.status === 'revoked' ? 0.5 : 1 }}>
            <span className="font-medium truncate">{k.name}</span><span className="font-mono text-[12px]">{k.prefix}</span>
            <span className="flex gap-1 flex-wrap">{k.scopes.map((s: string) => <Badge key={s}>{s}</Badge>)}</span>
            <span className="text-t2">{k.expiry === 'never' ? 'never' : `${k.expiry} d`}</span><span className="text-t2">{ago(k.created_at)}</span>
            <span className="text-right">{k.status === 'revoked' ? <span className="text-t3 text-[12.5px]">revoked</span> : <LinkBtn danger onClick={() => revoke(k.id)}>Revoke</LinkBtn>}</span>
          </Grid>
        ))}
      </Card>
      <Card title="Webhooks">
        <div className="p-4 flex gap-2 items-center flex-wrap border-b border-div">
          <input value={url} onChange={e => setUrl(e.target.value)} placeholder="https://siem.example.com/hooks/tripwire" className={`${inputCls} flex-1 min-w-[240px] font-mono text-[12.5px]`} />
          <Chips options={EVENTS} value={events} onChange={setEvents} />
          <Btn primary onClick={addHook} disabled={!url || !events.length}>Add webhook</Btn>
        </div>
        {hooks && !hooks.length && <Empty>No webhooks.</Empty>}
        {hooks?.map(h => (
          <Grid key={h.id} cols="minmax(200px,1fr) minmax(160px,1fr) 120px 110px" className="h-[40px]">
            <span className="font-mono text-[12px] truncate">{h.url}</span>
            <span className="flex gap-1 flex-wrap">{h.events.map((e: string) => <Badge key={e}>{e}</Badge>)}</span>
            <span className="text-[12.5px] text-t2">last: {h.last}</span>
            <span className="flex gap-3 justify-end"><LinkBtn onClick={() => testHook(h.id)}>Test</LinkBtn><LinkBtn danger onClick={() => delHook(h.id)}>Delete</LinkBtn></span>
          </Grid>
        ))}
      </Card>
    </Page>
  )
}

export function History() {
  const a = useApp()
  const [vs, reload] = useGet<any[]>('/v1/config/versions')
  const [open, setOpen] = useState<number | null>(null)
  const list = [...(vs || [])].reverse()
  const rollback = async (v: any) => {
    try {
      const r = await api('/v1/config/publish', { json: { config: v.snap, note: `Rollback to v${v.v}` } })
      await a.reloadConfig(); reload(); a.toast(`Rolled back · published as v${r.version}`)
    } catch (e: any) { a.toast(e.message, 'err') }
  }
  return (
    <Page title="Config history" desc="Every publish is an immutable version. Scans record the version they ran under; rollback publishes an old snapshot as a new version.">
      <Card>
        {vs && !vs.length && <Empty>No versions.</Empty>}
        {list.map((v, i) => {
          const prev = list[i + 1]
          const d = prev ? diffCfg(prev.snap, v.snap) : []
          return (
            <div key={v.v} className="border-b border-row">
              <Grid cols="70px minmax(0,1fr) 120px 110px 140px" className="h-[42px]" onClick={() => setOpen(open === v.v ? null : v.v)}>
                <span className="font-mono font-medium">v{v.v}</span><span className="truncate">{v.note}</span>
                <span className="text-t2">{v.by}</span><span className="text-t2">{ago(v.at)}</span>
                <span className="flex gap-3 justify-end items-center">{v.v === a.version ? <Badge>live</Badge> : <LinkBtn onClick={() => rollback(v)}>Roll back</LinkBtn>}<span className="text-t3 text-[12.5px]">{prev ? `${d.length} change${d.length === 1 ? '' : 's'}` : 'seed'}</span></span>
              </Grid>
              {open === v.v && !!d.length && <div className="px-4 pb-3">{d.slice(0, 40).map(x => (
                <div key={x.path} className="grid gap-2.5 py-[5px] font-mono text-[12px]" style={{ gridTemplateColumns: 'minmax(150px,1fr) minmax(0,1fr) minmax(0,1fr)' }}>
                  <span className="break-all">{x.path}</span><span className="break-all" style={{ color: 'oklch(0.45 0.15 28)' }}>{x.before.slice(0, 60)}</span><span className="break-all" style={{ color: 'oklch(0.4 0.1 155)' }}>{x.after.slice(0, 60)}</span>
                </div>))}{d.length > 40 && <div className="text-[12.5px] text-t3">and {d.length - 40} more</div>}</div>}
            </div>
          )
        })}
      </Card>
    </Page>
  )
}

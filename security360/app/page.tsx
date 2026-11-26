import {consoleUrl,loadReports,samples,type Report} from './data'
import {Overview} from './overview'

import {WorkspaceNav,views} from './workspace-nav'
const modules = [
  ['Website','Web application assessment','/web'],['Linux','Host and service assessment','/pc'],
  ['Windows','Host and service assessment','/pc'],['Network','Approved subnet inventory','/admin/network'],
  ['Active Directory','Directory assessment planned','']
]
export default async function Page({searchParams}:{searchParams:Promise<Record<string,string|undefined>>}) {
  const params = await searchParams
  const view = views.find(v=>v===params.view) || 'Overview'
  const demo = params.mode==='sample'
  const link = (v:string) => '?view='+encodeURIComponent(v)+(demo?'&mode=sample':'')
  let reports:Report[] = [], error=''
  try { reports = demo ? samples : await loadReports() }
  catch(e) { error = e instanceof Error && e.message.startsWith('Sign in') ? e.message : 'Unable to reach the scanner. Check the backend address and refresh.' }
  const target = (r:Report)=>r.url||r.host||'Unknown target'
  const findings = reports.flatMap(r=>(r.findings||[]).map(f=>({...f,asset:target(r)})))
  const assets = [...new Set(reports.map(target))]
  const reportList = <section><h2>Assessment reports</h2>{reports.length?reports.map(r=><div className="row" key={r.kind+r.scan_id}><div><strong>{target(r)}</strong><small>{r.kind} assessment</small></div><span>{r.findings?.length||0} findings</span>{demo?<span>Sample</span>:<a href={consoleUrl+(r.kind==='Host'?'/report/':'/web-report/')+encodeURIComponent(r.scan_id)+'/html'}>Open report ↗</a>}</div>):<p>No reports available.</p>}</section>
  return <div className="shell"><WorkspaceNav view={view} link={link} demo={demo}/><main>
    <div className="title"><div><div className="eyebrow">Security operations <span>/</span> {demo?'Sample workspace':'Internal workspace'}</div><h1>{view==='Overview'?'Security overview':view}</h1></div>
    {view==='Overview'&&<div className="actions"><a href={link('Reports')}>View reports</a><a href={link('Scans')}>＋ New scan</a></div>}</div>
  {error&&<p role="alert" className="notice">{error} <a href={consoleUrl+'/login'}>Open scanner sign-in ↗</a></p>}
  {view==='Overview'&&<Overview reports={reports} demo={demo} scope={['Host','Website'].includes(params.scope||'')?params.scope!:'All'} link={link} error={error}/>}
  {view==='Reports'&&reportList}
  {view==='Assets'&&<section><h2>Assets in scan reports</h2>{assets.map(a=><div className="row" key={a}><strong>{a}</strong><span>{reports.filter(r=>target(r)===a).length} reports</span></div>)}{!assets.length&&<p>No assets available.</p>}</section>}
  {view==='Findings'&&<section><h2>Findings and remediation</h2>{findings.map((f,i)=><details key={i}><summary>{f.severity||'Unrated'} · {f.description||f.cve_id||'Finding'}</summary><p>{f.asset}</p><p>{typeof f.fix==='string'?f.fix:'Review the assessment report for remediation guidance.'}</p></details>)}{!findings.length&&<p>No findings available.</p>}</section>}
  {view==='Scans'&&<section><h2>Assessment modules</h2>{modules.map(([name,desc,path])=><div className="row" key={name}><div><strong>{name}</strong><small>{desc}</small></div>{path?<a href={consoleUrl+path}>Open scanner ↗</a>:<span>Planned</span>}</div>)}</section>}
  {view==='Scanners'&&<section><h2>Scanner connection</h2><p>Configured FastAPI backend</p><code>{consoleUrl}</code><p>{demo?'Sample data selected':error?'Connection requires attention':'Report APIs responding'}</p><small>Remote agent enrollment is planned.</small></section>}
  {view==='Settings'&&<section><h2>Workspace administration</h2>{[['Accounts','/admin/users'],['Clients','/clients'],['Scan tokens','/tokens']].map(([name,path])=><div className="row" key={name}><strong>{name}</strong><a href={consoleUrl+path}>Manage ↗</a></div>)}</section>}
  </main></div>
}

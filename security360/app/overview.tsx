import type {Report} from './data'

const severity = ['Critical','High','Medium','Low']
const colors = ['#c84255','#c47726','#3278ba','#5a8790']
const target = (r:Report)=>r.url || r.host || 'Unknown target'
const rank = (s?:string)=> {
  const index = severity.findIndex(x=>x.toLowerCase()===s?.toLowerCase())
  return index < 0 ? 4 : index
}
const day = (r:Report)=>r.created_at && Number.isFinite(Date.parse(r.created_at))
  ? new Date(r.created_at).toISOString().slice(0,10) : ''

function Trend({reports}:{reports:Report[]}) {
  const daily = new Map<string,number[]>()
  for(const r of reports){
    const date = day(r)
    if(!date) continue
    const totals = daily.get(date) ?? [0,0,0,0,0]
    for(const f of r.findings??[]) totals[rank(f.severity)]++
    daily.set(date,totals)
  }
  const points = [...daily].sort(([a],[b])=>a.localeCompare(b)).slice(-8)
  const max=Math.max(1,...points.flatMap(([,n])=>n.slice(0,3)))
  return <section><h2>Vulnerability trend</h2><small>Findings per assessment day · UTC</small>
    <div className="legend">{severity.slice(0,3).map((s,i)=><span key={s}><i style={{background:colors[i]}}/>{s}</span>)}</div>
    {points.length<2?<p>At least two dated assessment days are needed to show a trend.</p>:<>
      <svg className="trend" viewBox="0 0 500 112" role="img" aria-label={points.map(([d,n])=>d+': '+n.slice(0,3).join('/')+' critical/high/medium').join('; ')}>
        {[12,52,92].map(y=><line key={y} x1="24" x2="492" y1={y} y2={y} stroke="#e3e9ef"/>)}
        <text x="2" y="16">{max}</text><text x="2" y="95">0</text>
        {severity.slice(0,3).map((s,i)=><polyline key={s} fill="none" stroke={colors[i]} strokeWidth="2.5" strokeDasharray={['','8 3','3 2'][i]} points={points.map(([,n],j)=>(24+468*j/(points.length-1))+','+(92-80*n[i]/max)).join(' ')}/>)}
      </svg><div className="dates"><span>{displayDay(points[0][0])}</span><span>{displayDay(points[points.length-1][0])}</span></div></>}
  </section>
}

export function Overview({reports,demo,scope,link,error}:{reports:Report[];demo:boolean;scope:string;link:(s:string)=>string;error:string}){
  const rows = reports.filter(r=>r.kind===scope || scope==='All')
  const findings = rows.flatMap(r=>(r.findings??[]).map(f=>({...f,asset:target(r)}))).sort((a,b)=>rank(a.severity)-rank(b.severity))
  const counts = severity.map((_,i)=>findings.filter(f=>rank(f.severity)===i).length)
  const metrics = [
    ['Reported assets',new Set(rows.map(target)).size,'Distinct report targets','▣'],
    ['Reported findings',findings.length,'Across selected assessments','⚑'],
    ['Critical & high',counts[0]+counts[1],'Priority for review','↑'],
    ['Remediation rate','—','Verified fixes not tracked','✓']
  ]
  return <><div className="toolbar"><span className="filter-title">Assessment type</span><div className="filters" role="group" aria-label="Assessment type">{['All','Host','Website'].map(s=><a key={s} aria-current={s===scope?'true':undefined} href={link('Overview')+'&scope='+s}>{s==='All'?'All assessments':s}</a>)}</div></div>
    <div className="metrics">{metrics.map(([label,n,caption])=><section key={label}><small>{label}</small><b>{error?'—':n}</b><small>{caption}</small></section>)}</div>
    {!error&&<div className="panels"><Trend reports={rows}/><section><h2>Findings by severity</h2><small>{findings.length} findings in selected assessments</small>{severity.map((s,i)=><div className="bar" key={s}><span>{s}</span><div className="track"><i style={{width:(100*counts[i]/Math.max(1,findings.length))+'%',background:colors[i]}}/></div><b>{counts[i]}</b></div>)}{findings.length>counts.reduce((a,b)=>a+b,0)&&<small>Unrated: {findings.length-counts.reduce((a,b)=>a+b,0)}</small>}</section>
    <section><a className="panel-link" href={link('Findings')}>All findings →</a><h2>Priority findings</h2><small>Highest reported severity first</small>{findings.slice(0,5).map((f,i)=><div className="row" key={i}><div><strong>{f.description||f.cve_id||'Finding'}</strong><small>{f.asset}</small></div><span className={'badge s'+rank(f.severity)}>{f.severity||'Unrated'}</span></div>)}{!findings.length&&<p>No findings in this selection.</p>}</section>
    <section><a className="panel-link" href={link('Reports')}>History →</a><h2>Recent scan activity</h2><small>Latest available assessment reports</small>{[...rows].sort((a,b)=>(b.created_at||'').localeCompare(a.created_at||'')).slice(0,5).map(r=><div className="row" key={r.kind+r.scan_id}><div><strong>{r.kind} assessment</strong><small>{target(r)}</small></div><small>{day(r)||'Date unavailable'}</small></div>)}{!rows.length&&<p>No reports in this selection.</p>}</section></div>}
  </>
}
const displayDay = (date:string)=>new Intl.DateTimeFormat('en',{month:'short',day:'numeric',year:'numeric',timeZone:'UTC'}).format(new Date(date))

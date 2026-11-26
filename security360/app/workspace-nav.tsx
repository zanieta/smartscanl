const paths = {
  Overview:'M3 3h7v7H3z M14 3h7v7h-7z M3 14h7v7H3z M14 14h7v7h-7z',
  Assets:'M3 4h18v13H3z M8 21h8 M12 17v4',
  Scans:'M3 12h4l3-7 4 14 3-7h4',
  Findings:'M5 21V4c5-4 9 4 15 0v10c-6 4-10-4-15 0',
  Reports:'M5 3h10l4 4v14H5z M14 3v5h5 M8 12h8 M8 16h6',
  Scanners:'M3 4h18v6H3z M3 14h18v6H3z M6 7h1 M6 17h1',
  Settings:'M3 6h8m4 0h6 M3 17h3m4 0h11 M11 3h4v6h-4z M6 14h4v6H6z',
}
export type View = keyof typeof paths
export const views = Object.keys(paths) as View[]
export function WorkspaceNav({view,link,demo}:{view:View;link:(v:string)=>string;demo:boolean}){
  const nav=<nav aria-label="Workspace">{views.map((v,i)=><div key={v}>
    {(i===0||i===5)&&<small>{i===0?'WORKSPACE':'ADMINISTRATION'}</small>}
    <a href={link(v)} aria-current={view===v?'page':undefined}>
      <svg viewBox="0 0 24 24" width="17" height="17" fill="none" stroke="currentColor" strokeWidth="1.65" strokeLinecap="round" strokeLinejoin="round" aria-hidden><path d={paths[v]}/></svg>{v==='Overview'?'Dashboard':v}
    </a></div>)}</nav>
  const mode=<a className="workspace-mode" href={'?view='+view+(demo?'':'&mode=sample')}>{demo?'View live workspace':'View sample workspace'} →</a>
  return <aside><div className="brand"><svg width="30" height="33" viewBox="0 0 30 33" aria-hidden><path fill="#71dfcf" d="M15 1 28 6v10c0 7-6 12-13 16C8 28 2 23 2 16V6z"/><path fill="none" stroke="#102b43" strokeWidth="2.6" d="m8 16 5 5 9-11"/></svg><div>Security360<small>DE-Webnet</small></div></div>
    <div className="desktop-nav">{nav}{mode}</div>
    <details className="mobile-nav"><summary>Menu</summary>{nav}{mode}</details>
  </aside>
}

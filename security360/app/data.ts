import { cookies } from 'next/headers'

export type Finding = {description?: string; severity?: string; cve_id?: string; fix?: string}
export type Report = {scan_id:string; created_at?:string; host?:string; url?:string; findings?:Finding[]; kind:'Host'|'Website'}
export const backend = process.env.SECURITY360_BACKEND_URL || 'http://localhost:8766'
export const consoleUrl = process.env.SECURITY360_CONSOLE_URL || backend
export const samples: Report[] = [
  {created_at:'2026-11-12T09:00:00Z',scan_id:'sample-intranet',kind:'Website',url:'intranet.example',findings:[{description:'Session cookie lacks the Secure attribute',severity:'Medium',fix:'Require HTTPS and set the Secure attribute on the session cookie.'}]},
  {created_at:'2026-11-19T09:00:00Z',scan_id:'sample-files',kind:'Host',host:'files.example',findings:[{description:'Unsupported file service version',severity:'High',fix:'Review vendor support and schedule an upgrade.'}]},
  {created_at:'2026-11-25T09:00:00Z',scan_id:'sample-portal',kind:'Website',url:'portal.example',findings:[]}
]

export async function loadReports():Promise<Report[]> {
  const session = (await cookies()).get('session')?.value
  const groups = await Promise.all((['Host','Website'] as const).map(async kind => {
    const response = await fetch(backend + (kind === 'Host' ? '/api/scans' : '/api/web-scans'),{
      headers: session ? {Cookie:'session='+encodeURIComponent(session)} : {},
      redirect:'manual', cache:'no-store', signal:AbortSignal.timeout(5000)
    })
    if ([401,403].includes(response.status)) throw new Error('Sign in to the scanner to view this workspace.')
    if (!response.ok) throw new Error('Scanner unavailable')
    const {scans} = await response.json()
    if (!Array.isArray(scans)) throw new Error('Invalid response')
    return scans.map((r:Report) => ({...r,kind}))
  }))
  return groups.flat()
}

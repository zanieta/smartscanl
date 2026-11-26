import type { ReactNode } from 'react'
import './style.css'
import './dashboard.css'

export const metadata = { title: 'Security360 | DE-Webnet' }
export default function Layout({ children }: { children: ReactNode }) {
  return <html lang="en"><body>{children}</body></html>
}

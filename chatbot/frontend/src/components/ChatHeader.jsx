import { Menu, PanelRightOpen, Settings2 } from 'lucide-react'
import Brand from './Brand.jsx'

export default function ChatHeader({ status, model, sidebarOpen, securityOpen, onMenu, onSettings, onSecurity }) {
  const online = Boolean(status.firewall && status.ollama)
  return (
    <header className="header-glass relative z-10 flex h-[70px] shrink-0 items-center justify-between gap-3 px-4 sm:px-7">
      <div className="flex min-w-0 items-center gap-3">
        <button type="button" className="icon-button lg:hidden" aria-label="Open navigation" aria-controls="orbit-sidebar" aria-expanded={sidebarOpen} onClick={onMenu}><Menu size={20} /></button>
        <Brand compact />
        <span className="hidden h-5 w-px bg-[var(--border)] sm:block" />
        <span className="hidden items-center gap-2 text-[11px] font-medium text-[var(--muted)] sm:flex">
          <span className={'status-dot ' + (online ? 'online' : 'offline')} />
          Local AI <span className="text-[var(--muted)]">•</span> {online ? 'Online' : 'Offline'}
        </span>
      </div>
      <div className="flex items-center gap-2">
        <button type="button" className="header-pill hidden max-w-[175px] items-center gap-2 rounded-xl px-3 py-2 text-[11px] font-medium sm:flex" onClick={onSettings} aria-label="Choose AI model and settings">
          <Settings2 size={15} className="shrink-0 text-[var(--accent)]" /><span className="truncate">{model || 'Choose model'}</span>
        </button>
        <button type="button" className="icon-button sm:hidden" onClick={onSettings} aria-label="Model and settings"><Settings2 size={18} /></button>
        <button type="button" className="icon-button xl:hidden" onClick={onSecurity} aria-label="Open security status" aria-expanded={securityOpen}><PanelRightOpen size={18} /></button>
      </div>
    </header>
  )
}

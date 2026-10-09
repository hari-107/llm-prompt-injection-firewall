import { useEffect, useMemo, useState } from 'react'
import { CircleHelp, Ellipsis, MessageSquare, Plus, Search, Settings2, Trash2, X } from 'lucide-react'
import Brand from './Brand.jsx'
import UserProfile from './UserProfile.jsx'
import { groupConversations } from '../lib.js'

export default function Sidebar({ items, activeId, onNew, onSelect, onDelete, onSettings, onHelp, open, onClose }) {
  const [query, setQuery] = useState('')
  const [menuId, setMenuId] = useState(null)
  const groups = useMemo(() => groupConversations(items.filter(item => item.title.toLowerCase().includes(query.trim().toLowerCase()))), [items, query])

  useEffect(() => {
    const closeMenu = event => { if (!event.target.closest('[data-conversation-menu]')) setMenuId(null) }
    document.addEventListener('click', closeMenu)
    return () => document.removeEventListener('click', closeMenu)
  }, [])

  return (
    <>
      {open && <button type="button" className="fixed inset-0 z-30 bg-[#02090dbb] lg:hidden" aria-label="Close navigation" onClick={onClose} />}
      <aside id="orbit-sidebar" className={'sidebar-shell fixed inset-y-0 left-0 z-40 flex w-[282px] shrink-0 flex-col p-4 transition-transform duration-200 lg:relative lg:translate-x-0 lg:visible ' + (open ? 'translate-x-0 visible' : '-translate-x-full invisible')}>
        <div className="mb-7 flex items-center justify-between px-1 pt-1">
          <Brand />
          <button className="icon-button lg:hidden" type="button" aria-label="Close navigation" onClick={onClose}><X size={18} /></button>
        </div>
        <button type="button" onClick={onNew} className="new-chat-button mb-5 flex h-11 items-center justify-center gap-2 rounded-xl text-[13px] font-semibold">
          <Plus size={17} strokeWidth={2.2} /> New Chat
        </button>
        <label className="search-field mb-5 flex h-10 items-center gap-2 rounded-xl px-3">
          <Search size={15} className="shrink-0 text-[var(--muted)]" />
          <input value={query} onChange={event => setQuery(event.target.value)} placeholder="Search conversations" className="min-w-0 flex-1 bg-transparent text-[12px] text-[var(--text)] outline-none placeholder:text-[var(--muted)]" aria-label="Search conversations" />
          {query && <button type="button" onClick={() => setQuery('')} aria-label="Clear search"><X size={13} /></button>}
        </label>
        <nav className="min-h-0 flex-1 space-y-5 overflow-y-auto pr-1" aria-label="Conversation history">
          {groups.length ? groups.map(group => (
            <section key={group.label}>
              <h2 className="mb-2 px-2 text-[10px] font-semibold uppercase tracking-[.14em] text-[var(--muted)]">{group.label}</h2>
              <div className="space-y-1">
                {group.items.map(item => (
                  <div key={item.id} className={'conversation-row group relative flex min-h-10 items-center rounded-xl ' + (activeId === item.id ? 'selected' : '')}>
                    <button type="button" className="flex min-w-0 flex-1 items-center gap-2.5 px-2.5 py-2 text-left" onClick={() => { onSelect(item); onClose() }} aria-current={activeId === item.id ? 'page' : undefined}>
                      <MessageSquare size={15} className="shrink-0 text-[var(--muted)]" />
                      <span className="min-w-0 flex-1 truncate text-[12px] font-medium text-[var(--text)]">{item.title}</span>
                    </button>
                    <div data-conversation-menu className="relative pr-1">
                      <button type="button" className="menu-trigger icon-button size-7" aria-label={'More options for ' + item.title} aria-expanded={menuId === item.id} onClick={() => setMenuId(menuId === item.id ? null : item.id)}><Ellipsis size={16} /></button>
                      {menuId === item.id && (
                        <div className="conversation-menu absolute right-0 top-8 z-50 min-w-40 rounded-xl p-1 shadow-xl">
                          {item.demo ? <span className="block px-3 py-2 text-[11px] text-[var(--muted)]">Example conversation</span> : <button type="button" className="flex w-full items-center gap-2 rounded-lg px-3 py-2 text-left text-[12px] text-[var(--danger)] hover:bg-[var(--hover)]" onClick={() => { setMenuId(null); onDelete(item) }}><Trash2 size={14} /> Delete chat</button>}
                        </div>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            </section>
          )) : <p className="px-2 py-4 text-[12px] text-[var(--muted)]">No conversations found.</p>}
        </nav>
        <div className="mt-4 border-t border-[var(--border)] pt-3">
          <button type="button" onClick={onSettings} className="sidebar-action"><Settings2 size={16} /> Settings</button>
          <button type="button" onClick={onHelp} className="sidebar-action"><CircleHelp size={16} /> Help</button>
          <div className="mt-3 border-t border-[var(--border)] pt-2"><UserProfile onClick={onSettings} /></div>
        </div>
      </aside>
    </>
  )
}

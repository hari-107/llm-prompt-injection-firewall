import { useEffect, useRef } from 'react'
import { CircleHelp, Keyboard, Moon, Settings2, Sun, X } from 'lucide-react'

export default function SettingsPanel({ open, tab, onTab, onClose, status, model, onModel, theme, onTheme }) {
  const closeRef = useRef(null)
  const panelRef = useRef(null)
  const previousFocus = useRef(null)
  useEffect(() => {
    if (!open) return
    previousFocus.current = document.activeElement
    closeRef.current?.focus()
    const onKey = event => {
      if (event.key === 'Escape') onClose()
      if (event.key !== 'Tab') return
      const focusable = [...panelRef.current.querySelectorAll('button:not([disabled]), select:not([disabled]), [href]')]
      if (!focusable.length) return
      const first = focusable[0], last = focusable.at(-1)
      if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus() }
      else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus() }
    }
    document.addEventListener('keydown', onKey)
    return () => { document.removeEventListener('keydown', onKey); previousFocus.current?.focus?.() }
  }, [open])
  if (!open) return null
  return (
    <div className="fixed inset-0 z-[70] flex justify-end bg-[#02090dcc]" onMouseDown={event => { if (event.target === event.currentTarget) onClose() }}>
      <section ref={panelRef} className="settings-panel flex h-full w-full max-w-[400px] flex-col p-6 shadow-2xl" role="dialog" aria-modal="true" aria-label="Orbit settings and help">
        <div className="mb-7 flex items-center justify-between">
          <div><p className="text-[10px] font-bold uppercase tracking-[.18em] text-[var(--accent)]">Orbit</p><h2 className="mt-1 text-[21px] font-semibold tracking-[-.04em] text-[var(--text)]">{tab === 'help' ? 'Help' : 'Settings'}</h2></div>
          <button ref={closeRef} type="button" className="icon-button" onClick={onClose} aria-label="Close panel"><X size={19} /></button>
        </div>
        <div className="mb-7 flex gap-2 border-b border-[var(--border)] pb-3">
          <button type="button" onClick={() => onTab('settings')} className={'tab-button ' + (tab === 'settings' ? 'active' : '')}><Settings2 size={15} /> Settings</button>
          <button type="button" onClick={() => onTab('help')} className={'tab-button ' + (tab === 'help' ? 'active' : '')}><CircleHelp size={15} /> Help</button>
        </div>
        {tab === 'settings' ? (
          <div className="space-y-7">
            <div>
              <label htmlFor="model-select" className="settings-label">Local model</label>
              <p className="mb-3 text-[11px] leading-5 text-[var(--muted)]">Choose an installed Ollama model for new replies.</p>
              <select id="model-select" value={model} onChange={event => onModel(event.target.value)} className="field w-full rounded-xl px-3 py-2.5 text-[12px]">
                {status.models?.length ? status.models.map(name => <option value={name} key={name}>{name}</option>) : <option value="">No model available</option>}
              </select>
            </div>
            <div>
              <p className="settings-label">Appearance</p>
              <div className="mt-3 grid grid-cols-2 gap-2">
                <button type="button" className={'appearance-choice ' + (theme === 'dark' ? 'active' : '')} onClick={() => onTheme('dark')} aria-pressed={theme === 'dark'}><Moon size={17} /> Dark</button>
                <button type="button" className={'appearance-choice ' + (theme === 'light' ? 'active' : '')} onClick={() => onTheme('light')} aria-pressed={theme === 'light'}><Sun size={17} /> Light</button>
              </div>
            </div>
            <div className="rounded-xl border border-[var(--border)] p-4 text-[11px] leading-5 text-[var(--muted)]">Chats are saved in this chatbot's local database for this browser session. Feedback buttons are saved in this browser only.</div>
          </div>
        ) : (
          <div className="space-y-6 text-[12px] leading-6 text-[var(--muted)]">
            <p>Orbit uses a local model and checks each request and completed reply with the firewall. If either service is unavailable, a reply cannot be completed.</p>
            <div><p className="settings-label mb-2">Keyboard shortcuts</p><p className="flex items-center gap-2"><Keyboard size={15} /> Enter to send; Shift + Enter for a new line.</p><p className="mt-2">Ctrl/Cmd + K starts a new chat. Escape closes panels.</p></div>
            <div><p className="settings-label mb-2">Attachments and voice</p><p>Text attachments are added to your message before the firewall checks it. Voice transcription needs a separately configured local speech model and is unavailable in this build.</p></div>
          </div>
        )}
      </section>
    </div>
  )
}

import { Check, CircleHelp, Cpu, LockKeyhole, ShieldCheck } from 'lucide-react'

export default function SecurityPanel({ status, compact = false, onClose }) {
  const modelReady = Boolean(status.ollama)
  const firewallReady = Boolean(status.firewall)
  return (
    <aside className={compact ? 'security-drawer fixed inset-y-0 right-0 z-50 flex w-[min(330px,90vw)] flex-col p-5' : 'security-shell hidden w-[270px] shrink-0 flex-col p-5 xl:flex'} aria-label="Security and connection status">
      <div className="mb-7 flex items-center justify-between">
        <div><p className="text-[10px] font-bold uppercase tracking-[.18em] text-[var(--muted)]">Session status</p><h2 className="mt-1 text-[16px] font-semibold text-[var(--text)]">Private by design</h2></div>
        {compact && <button type="button" className="icon-button" onClick={onClose} aria-label="Close security panel">×</button>}
      </div>
      <div className="security-highlight rounded-2xl p-4">
        <span className="mb-4 inline-flex size-9 items-center justify-center rounded-xl bg-[var(--accent-soft)] text-[var(--accent)]"><LockKeyhole size={18} /></span>
        <p className="text-[13px] font-semibold text-[var(--text)]">Local &amp; Private</p>
        <p className="mt-1.5 text-[11px] leading-5 text-[var(--muted)]">Your conversation is processed locally.</p>
      </div>
      <div className="mt-7">
        <p className="mb-3 text-[10px] font-bold uppercase tracking-[.16em] text-[var(--muted)]">Connections</p>
        <div className="space-y-3">
          <div className="status-row"><span className="status-row-icon"><Cpu size={16} /></span><span className="flex-1"><strong>Local model</strong><small>Ollama on this device</small></span><span className={'status-dot ' + (modelReady ? 'online' : 'offline')} title={modelReady ? 'Online' : 'Offline'} /></div>
          <div className="status-row"><span className="status-row-icon"><ShieldCheck size={16} /></span><span className="flex-1"><strong>Firewall</strong><small>Checks requests and replies</small></span><span className={'status-dot ' + (firewallReady ? 'online' : 'offline')} title={firewallReady ? 'Online' : 'Offline'} /></div>
        </div>
      </div>
      <div className="mt-8 border-t border-[var(--border)] pt-6">
        <p className="mb-3 text-[10px] font-bold uppercase tracking-[.16em] text-[var(--muted)]">How it works</p>
        <div className="space-y-4 text-[11px] leading-5 text-[var(--muted)]">
          <p className="flex gap-2.5"><Check size={14} className="mt-0.5 shrink-0 text-[var(--accent)]" /> Your message is checked by the local firewall.</p>
          <p className="flex gap-2.5"><Check size={14} className="mt-0.5 shrink-0 text-[var(--accent)]" /> An installed model generates the reply.</p>
          <p className="flex gap-2.5"><Check size={14} className="mt-0.5 shrink-0 text-[var(--accent)]" /> The reply is checked before display.</p>
        </div>
      </div>
      <div className="mt-auto rounded-xl border border-[var(--border)] p-3 text-[10px] leading-4 text-[var(--muted)]"><CircleHelp size={14} className="mb-2 text-[var(--accent)]" />AI can be inaccurate. Review important answers before using them.</div>
    </aside>
  )
}

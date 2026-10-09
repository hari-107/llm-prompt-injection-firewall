import { ChevronUp, UserRound } from 'lucide-react'

export default function UserProfile({ onClick }) {
  return (
    <button type="button" onClick={onClick} className="profile-button flex w-full items-center gap-3 p-2 text-left" aria-label="Open local workspace settings">
      <span className="grid size-9 shrink-0 place-items-center rounded-xl bg-[var(--accent-soft)] text-[var(--accent)]"><UserRound size={17} /></span>
      <span className="min-w-0 flex-1">
        <span className="block truncate text-[12px] font-semibold text-[var(--text)]">Local workspace</span>
        <span className="block text-[10px] text-[var(--muted)]">On this device</span>
      </span>
      <ChevronUp size={15} className="text-[var(--muted)]" />
    </button>
  )
}

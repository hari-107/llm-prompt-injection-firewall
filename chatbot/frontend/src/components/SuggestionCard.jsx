import { ArrowUpRight } from 'lucide-react'

export default function SuggestionCard({ icon: Icon, title, detail, prompt, onSelect }) {
  return (
    <button type="button" onClick={() => onSelect(prompt)} className="suggestion-card group flex min-h-[96px] items-start gap-4 p-4 text-left">
      <span className="suggestion-icon"><Icon size={19} strokeWidth={1.8} /></span>
      <span className="min-w-0 flex-1">
        <span className="block text-[13px] font-semibold leading-5 text-[var(--text)]">{title}</span>
        <span className="mt-1 block text-[11px] leading-4 text-[var(--muted)]">{detail}</span>
      </span>
      <ArrowUpRight size={16} className="mt-1 shrink-0 text-[var(--muted)] opacity-0 transition-opacity group-hover:opacity-100 group-focus-visible:opacity-100" />
    </button>
  )
}

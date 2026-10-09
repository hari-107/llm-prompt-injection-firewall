export function OrbitMark({ size = 38, className = '' }) {
  return (
    <span className={'brand-mark ' + className} style={{ width: size, height: size }} aria-hidden="true">
      <svg viewBox="0 0 48 48" fill="none">
        <ellipse className="orbit-mark-track" cx="24" cy="24" rx="18" ry="8.5" transform="rotate(-28 24 24)" stroke="currentColor" strokeWidth="2.2" />
        <circle cx="24" cy="24" r="8" fill="currentColor" fillOpacity=".16" />
        <path d="M24 17.5 25.7 22.3 30.5 24l-4.8 1.7L24 30.5l-1.7-4.8L17.5 24l4.8-1.7L24 17.5Z" fill="currentColor" />
        <circle cx="39.3" cy="15.8" r="2.2" fill="currentColor" />
      </svg>
    </span>
  )
}

export default function Brand({ compact = false }) {
  return (
    <div className="flex items-center gap-3">
      <OrbitMark size={compact ? 34 : 40} />
      <div className="flex flex-col leading-tight">
        <span className={'font-semibold tracking-[-.04em] text-[var(--text)] ' + (compact ? 'text-[17px]' : 'text-[19px]')}>Orbit</span>
        {!compact && <span className="mt-0.5 text-[9px] font-bold tracking-[.2em] text-[var(--accent)]">PRIVATE AI</span>}
      </div>
    </div>
  )
}

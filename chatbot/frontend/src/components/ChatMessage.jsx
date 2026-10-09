import { useState } from 'react'
import ReactMarkdown from 'react-markdown'
import remarkGfm from 'remark-gfm'
import { Check, Copy, RotateCcw, ShieldCheck, ThumbsDown, ThumbsUp } from 'lucide-react'
import { OrbitMark } from './Brand.jsx'

function MarkdownContent({ content }) {
  return (
    <div className="markdown">
      <ReactMarkdown remarkPlugins={[remarkGfm]} components={{
        a: ({ href, children }) => <a href={href} target="_blank" rel="noopener noreferrer">{children}</a>,
        pre: ({ children }) => {
          const code = children?.props?.children ?? ''
          const language = children?.props?.className?.replace('language-', '') || 'Code'
          return <div className="code-block"><div className="code-toolbar"><span>{language}</span><button type="button" onClick={() => navigator.clipboard.writeText(String(code)).catch(() => {})}><Copy size={12} /> Copy code</button></div><pre>{children}</pre></div>
        },
      }}>{content}</ReactMarkdown>
    </div>
  )
}

export default function ChatMessage({ message, isLatest, canRegenerate, onRegenerate, feedback, onFeedback }) {
  const [copied, setCopied] = useState(false)
  if (message.role === 'notice') return <div className="chat-entry mx-auto max-w-[840px] px-4"><div className="notice-card rounded-xl p-3 text-[12px] leading-5" role="status">{message.content}</div></div>
  if (message.role === 'user') {
    return (
      <div className="chat-entry mx-auto flex w-full max-w-[840px] justify-end px-4">
        <article className="user-bubble max-w-[min(650px,92%)] rounded-[18px] rounded-tr-[5px] px-4 py-3 text-[13px] leading-6 whitespace-pre-wrap break-words text-[var(--text)]">{message.content}</article>
      </div>
    )
  }
  return (
    <article className="chat-entry mx-auto flex w-full max-w-[840px] items-start gap-3 px-4">
      <OrbitMark size={32} className="message-mark shrink-0" />
      <div className="min-w-0 flex-1 pt-1">
        <div className="mb-3 flex flex-wrap items-center gap-2"><strong className="text-[12px] font-semibold text-[var(--text)]">Orbit</strong>{message.security && !message.pending && <span className="secure-badge inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-[9px] font-semibold"><ShieldCheck size={11} /> Firewall checked</span>}</div>
        {message.pending ? (
          <div className="flex items-center gap-2.5 py-2 text-[12px] text-[var(--muted)]" role="status" aria-live="polite"><span className="thinking-dots"><i /><i /><i /></span>{message.phase || 'Orbit is thinking...'}</div>
        ) : (
          <>
            <MarkdownContent content={message.content} />
            <div className="mt-4 flex flex-wrap items-center gap-1">
              <button type="button" className="message-action" aria-label="Copy response" onClick={async () => { try { await navigator.clipboard.writeText(message.content); setCopied(true); setTimeout(() => setCopied(false), 1600) } catch {} }}>{copied ? <Check size={14} /> : <Copy size={14} />}<span>{copied ? 'Copied' : 'Copy'}</span></button>
              {canRegenerate && isLatest && <button type="button" className="message-action" onClick={onRegenerate} aria-label="Regenerate response"><RotateCcw size={14} /><span>Regenerate</span></button>}
              <span className="mx-1 h-4 w-px bg-[var(--border)]" />
              <button type="button" className={'message-action square ' + (feedback === 'up' ? 'active' : '')} aria-label="Helpful response" aria-pressed={feedback === 'up'} onClick={() => onFeedback(feedback === 'up' ? null : 'up')}><ThumbsUp size={14} /></button>
              <button type="button" className={'message-action square ' + (feedback === 'down' ? 'active' : '')} aria-label="Not helpful response" aria-pressed={feedback === 'down'} onClick={() => onFeedback(feedback === 'down' ? null : 'down')}><ThumbsDown size={14} /></button>
            </div>
          </>
        )}
      </div>
    </article>
  )
}

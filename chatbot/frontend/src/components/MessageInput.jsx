import { useEffect, useRef, useState } from 'react'
import { ArrowUp, Mic, Paperclip, X } from 'lucide-react'

const allowedExtensions = ['.txt', '.md', '.log', '.json', '.csv']

export default function MessageInput({ onSend, busy, onNotice }) {
  const [value, setValue] = useState('')
  const [attachment, setAttachment] = useState(null)
  const [voiceNote, setVoiceNote] = useState(false)
  const textarea = useRef(null)
  const picker = useRef(null)

  useEffect(() => {
    if (!textarea.current) return
    textarea.current.style.height = 'auto'
    textarea.current.style.height = Math.min(textarea.current.scrollHeight, 180) + 'px'
  }, [value])

  async function attach(file) {
    if (!file) return
    const extension = '.' + file.name.split('.').pop().toLowerCase()
    if (!allowedExtensions.includes(extension) || file.size > 24000) {
      onNotice('Choose a TXT, MD, LOG, JSON, or CSV file under 24 KB.')
      return
    }
    try {
      const content = await file.text()
      if (content.includes('\0')) throw new Error('This file does not look like plain text.')
      setAttachment({ name: file.name, content })
    } catch {
      onNotice('This text file could not be read.')
    }
  }

  function submit() {
    const text = value.trim()
    if ((!text && !attachment) || busy) return
    const message = attachment ? [text, 'Attached text file: ' + attachment.name, attachment.content].filter(Boolean).join('\n\n') : text
    if (message.length > 16000) {
      onNotice('The message and attachment must fit within 16,000 characters.')
      return
    }
    onSend(message)
    setValue('')
    setAttachment(null)
    setVoiceNote(false)
    if (picker.current) picker.current.value = ''
  }

  return (
    <div className="composer-wrap shrink-0 px-3 pb-3 pt-3 sm:px-7 sm:pb-5">
      <div className="mx-auto max-w-[840px]">
        <div className="composer-card rounded-[20px] p-3 sm:p-4">
          {attachment && <div className="mb-3 inline-flex max-w-full items-center gap-2 rounded-lg border border-[var(--border)] bg-[var(--hover)] px-2.5 py-1.5 text-[11px] text-[var(--text)]"><Paperclip size={13} /><span className="truncate">{attachment.name}</span><button type="button" onClick={() => setAttachment(null)} aria-label="Remove attachment"><X size={13} /></button></div>}
          <label htmlFor="message-input" className="sr-only">Message Orbit</label>
          <textarea ref={textarea} id="message-input" value={value} maxLength={16000} onChange={event => setValue(event.target.value)} onKeyDown={event => { if (event.key === 'Enter' && !event.shiftKey && !event.nativeEvent.isComposing) { event.preventDefault(); submit() } }} placeholder="Message Orbit..." rows={1} className="block max-h-[180px] min-h-[39px] w-full resize-none bg-transparent px-1 text-[13px] leading-6 text-[var(--text)] outline-none placeholder:text-[var(--muted)]" />
          <div className="mt-2 flex items-center justify-between gap-2">
            <div className="flex items-center gap-1">
              <input ref={picker} type="file" accept=".txt,.md,.log,.json,.csv,text/plain,text/markdown,application/json,text/csv" className="sr-only" onChange={event => attach(event.target.files?.[0])} tabIndex={-1} />
              <button type="button" className="composer-icon" aria-label="Attach a text file" title="Attach a text file" onClick={() => picker.current?.click()}><Paperclip size={17} /></button>
              <div className="relative">
                <button type="button" className="composer-icon" aria-label="Voice input information" aria-expanded={voiceNote} title="Voice input" onClick={() => setVoiceNote(!voiceNote)}><Mic size={17} /></button>
                {voiceNote && <div role="status" className="voice-popover absolute bottom-10 left-0 z-20 w-64 rounded-xl p-3 text-[11px] leading-5">Voice transcription needs a local speech model. It is not configured yet, so this button does not record audio.</div>}
              </div>
              <span className="ml-2 hidden text-[10px] text-[var(--muted)] sm:inline">Text files only · Enter to send</span>
            </div>
            <div className="flex items-center gap-3">
              {value.length > 13000 && <span className="text-[10px] text-[var(--muted)]">{value.length.toLocaleString()}/16,000</span>}
              <button type="button" className="send-button grid size-9 place-items-center rounded-xl" onClick={submit} disabled={busy || (!value.trim() && !attachment)} aria-label="Send message"><ArrowUp size={19} strokeWidth={2.4} /></button>
            </div>
          </div>
        </div>
        <p className="mt-2 text-center text-[10px] leading-4 text-[var(--muted)]">Orbit can make mistakes. Check important details.</p>
      </div>
    </div>
  )
}

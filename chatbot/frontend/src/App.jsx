import { useCallback, useEffect, useRef, useState } from 'react'
import { X } from 'lucide-react'
import Sidebar from './components/Sidebar.jsx'
import ChatHeader from './components/ChatHeader.jsx'
import WelcomeScreen from './components/WelcomeScreen.jsx'
import ChatMessage from './components/ChatMessage.jsx'
import MessageInput from './components/MessageInput.jsx'
import SecurityPanel from './components/SecurityPanel.jsx'
import SettingsPanel from './components/SettingsPanel.jsx'
import { api, demoConversations, streamChat } from './lib.js'

const newId = () => crypto.randomUUID()
const savedTheme = () => { try { return localStorage.getItem('orbit-theme') === 'light' ? 'light' : 'dark' } catch { return 'dark' } }
const savedFeedback = () => { try { return JSON.parse(localStorage.getItem('orbit-feedback') || '{}') } catch { return {} } }

export default function App() {
  const [conversations, setConversations] = useState([])
  const [activeId, setActiveId] = useState(null)
  const [messages, setMessages] = useState([])
  const [status, setStatus] = useState({ firewall: false, ollama: false, models: [], loading: true })
  const [model, setModel] = useState('')
  const [busy, setBusy] = useState(false)
  const [theme, setTheme] = useState(savedTheme)
  const [feedback, setFeedback] = useState(savedFeedback)
  const [sidebarOpen, setSidebarOpen] = useState(false)
  const [settingsOpen, setSettingsOpen] = useState(false)
  const [settingsTab, setSettingsTab] = useState('settings')
  const [securityOpen, setSecurityOpen] = useState(false)
  const [notice, setNotice] = useState('')
  const scrollRef = useRef(null)
  const items = conversations.length ? conversations : demoConversations

  const loadHistory = useCallback(async () => {
    try { setConversations(await api('/api/conversations')) }
    catch { /* The local service may be starting. */ }
  }, [])

  const loadStatus = useCallback(async () => {
    try {
      const current = await api('/api/status')
      setStatus({ ...current, loading: false })
      setModel(previous => {
        if (current.models?.includes(previous)) return previous
        return current.models?.find(name => name === current.model || name === current.model + ':latest') || current.models?.[0] || ''
      })
    } catch { setStatus({ firewall: false, ollama: false, models: [], loading: false }) }
  }, [])

  useEffect(() => {
    loadHistory()
    loadStatus()
    const statusTimer = setInterval(loadStatus, 20000)
    const historyTimer = setInterval(loadHistory, 30000)
    return () => { clearInterval(statusTimer); clearInterval(historyTimer) }
  }, [loadHistory, loadStatus])

  useEffect(() => { document.documentElement.dataset.theme = theme; try { localStorage.setItem('orbit-theme', theme) } catch {} }, [theme])
  useEffect(() => { if (!notice) return; const timer = setTimeout(() => setNotice(''), 5000); return () => clearTimeout(timer) }, [notice])
  useEffect(() => { if (messages.length && scrollRef.current) scrollRef.current.scrollTop = scrollRef.current.scrollHeight }, [messages])
  useEffect(() => {
    const onKey = event => {
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'k') { event.preventDefault(); newChat() }
      if (event.key === 'Escape') { setSidebarOpen(false); setSecurityOpen(false) }
    }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  })

  function newChat() {
    if (busy) return
    setActiveId(null)
    setMessages([])
    setSidebarOpen(false)
    setSettingsOpen(false)
    setSecurityOpen(false)
    document.getElementById('message-input')?.focus()
  }

  async function selectConversation(item) {
    if (busy) return
    if (item.demo) {
      setActiveId(item.id)
      setMessages(item.messages.map(turn => ({ ...turn, id: newId(), demo: true })))
      return
    }
    try {
      const data = await api('/api/conversations/' + encodeURIComponent(item.id))
      setActiveId(data.id)
      setMessages((data.messages || []).map(turn => ({ ...turn, id: newId() })))
    } catch (error) { setNotice(error.message) }
  }

  async function deleteConversation(item) {
    if (item.demo || !window.confirm('Delete this conversation from this device?')) return
    try {
      await api('/api/conversations/' + encodeURIComponent(item.id), { method: 'DELETE' })
      if (activeId === item.id) { setActiveId(null); setMessages([]) }
      await loadHistory()
      setNotice('Conversation deleted.')
    } catch (error) { setNotice(error.message) }
  }

  async function sendMessage(content) {
    if (busy || !content.trim()) return
    const conversationId = activeId?.startsWith('demo:') ? null : activeId
    const base = activeId?.startsWith('demo:') ? [] : messages
    const pendingId = newId()
    setMessages([...base, { id: newId(), role: 'user', content }, { id: pendingId, role: 'assistant', pending: true, phase: 'Orbit is thinking...' }])
    if (!conversationId) setActiveId(null)
    setBusy(true)
    try {
      let completed = false
      await streamChat({ message: content, conversation_id: conversationId, model: model || undefined }, (event, data) => {
        if (event === 'phase') {
          const label = data.stage === 'model' ? 'Orbit is thinking...' : data.label
          setMessages(current => current.map(turn => turn.id === pendingId ? { ...turn, phase: label } : turn))
        }
        if (event === 'blocked') {
          completed = true
          setMessages(current => current.map(turn => turn.id === pendingId ? { id: pendingId, role: 'notice', content: data.message || 'The firewall blocked this request.' } : turn))
        }
        if (event === 'done') {
          completed = true
          setActiveId(data.conversation_id)
          setMessages(current => current.map(turn => turn.id === pendingId ? { id: pendingId, role: 'assistant', content: data.text, security: data.security } : turn))
        }
        if (event === 'error') throw new Error(data.message || 'The reply could not be completed.')
      })
      if (completed) await loadHistory()
    } catch (error) {
      setMessages(current => current.map(turn => turn.id === pendingId ? { id: pendingId, role: 'notice', content: error.message || 'The reply could not be completed.' } : turn))
      setNotice(error.message || 'The reply could not be completed.')
    } finally { setBusy(false) }
  }

  async function regenerate() {
    if (busy || !activeId || activeId.startsWith('demo:')) return
    const previous = messages.at(-1)
    if (previous?.role !== 'assistant' || previous.pending) return
    setBusy(true)
    setMessages(current => current.map(turn => turn.id === previous.id ? { ...turn, pending: true, phase: 'Orbit is thinking...' } : turn))
    try {
      await streamChat({ conversation_id: activeId, regenerate: true, model: model || undefined }, (event, data) => {
        if (event === 'phase') {
          const label = data.stage === 'model' ? 'Orbit is thinking...' : data.label
          setMessages(current => current.map(turn => turn.id === previous.id ? { ...turn, phase: label } : turn))
        }
        if (event === 'done') setMessages(current => current.map(turn => turn.id === previous.id ? { ...turn, pending: false, content: data.text, security: data.security } : turn))
        if (event === 'blocked' || event === 'error') throw new Error(data.message || 'The reply could not be regenerated.')
      })
      await loadHistory()
    } catch (error) {
      setMessages(current => current.map(turn => turn.id === previous.id ? previous : turn))
      setNotice(error.message || 'The reply could not be regenerated.')
    } finally { setBusy(false) }
  }

  function rate(key, value) {
    const next = { ...feedback, [key]: value }
    setFeedback(next)
    try { localStorage.setItem('orbit-feedback', JSON.stringify(next)) } catch {}
  }

  function openPanel(tab) { setSettingsTab(tab); setSettingsOpen(true); setSidebarOpen(false) }

  return (
    <div className="app-shell flex h-dvh min-h-[500px] overflow-hidden bg-[var(--bg)]">
      <Sidebar items={items} activeId={activeId} onNew={newChat} onSelect={selectConversation} onDelete={deleteConversation} onSettings={() => openPanel('settings')} onHelp={() => openPanel('help')} open={sidebarOpen} onClose={() => setSidebarOpen(false)} />
      <main className="flex min-w-0 flex-1 flex-col">
        <ChatHeader status={status} model={model} sidebarOpen={sidebarOpen} securityOpen={securityOpen} onMenu={() => setSidebarOpen(true)} onSettings={() => openPanel('settings')} onSecurity={() => setSecurityOpen(true)} />
        <div ref={scrollRef} className="chat-scroll min-h-0 flex-1 overflow-y-auto" aria-live="polite">
          {messages.length ? (
            <div className="mx-auto flex w-full max-w-[900px] flex-col gap-8 px-1 py-8 sm:gap-10 sm:px-5 sm:py-10">
              {activeId?.startsWith('demo:') && <p className="mx-auto rounded-full border border-[var(--border)] px-3 py-1 text-[10px] text-[var(--muted)]">Example conversation · Sending starts a new chat</p>}
              {messages.map((turn, index) => <ChatMessage key={turn.id} message={turn} isLatest={index === messages.length - 1} canRegenerate={!busy && !turn.demo && !activeId?.startsWith('demo:')} onRegenerate={regenerate} feedback={feedback[activeId + ':' + index] || null} onFeedback={value => rate(activeId + ':' + index, value)} />)}
            </div>
          ) : <WelcomeScreen onSelect={sendMessage} />}
        </div>
        <MessageInput onSend={sendMessage} busy={busy} onNotice={setNotice} />
      </main>
      <SecurityPanel status={status} />
      {securityOpen && <div className="fixed inset-0 z-[49] bg-[#02090dcc]" onClick={() => setSecurityOpen(false)}><div onClick={event => event.stopPropagation()}><SecurityPanel status={status} compact onClose={() => setSecurityOpen(false)} /></div></div>}
      <SettingsPanel open={settingsOpen} tab={settingsTab} onTab={setSettingsTab} onClose={() => setSettingsOpen(false)} status={status} model={model} onModel={setModel} theme={theme} onTheme={setTheme} />
      {notice && <div className="toast fixed bottom-28 left-1/2 z-[80] flex max-w-[min(420px,calc(100%-24px))] -translate-x-1/2 items-center gap-3 rounded-xl px-4 py-3 text-[12px] shadow-xl" role="status"><span className="flex-1">{notice}</span><button type="button" onClick={() => setNotice('')} aria-label="Dismiss notice"><X size={14} /></button></div>}
    </div>
  )
}

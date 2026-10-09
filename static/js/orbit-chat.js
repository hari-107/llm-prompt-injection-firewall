(() => {
  const form = document.getElementById('orbit-form');
  if (!form) return;

  const input = document.getElementById('orbit-prompt');
  const send = document.getElementById('orbit-send');
  const messages = document.getElementById('orbit-messages');
  const inspector = document.getElementById('orbit-inspector-content');
  const welcome = document.getElementById('orbit-welcome');
  const initialResult = document.getElementById('orbit-initial-result');
  let busy = false;

  const el = (tag, className, content) => {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (content !== undefined) node.textContent = content;
    return node;
  };

  function scrollToLatest() {
    messages.scrollTo({ top: messages.scrollHeight, behavior: 'smooth' });
  }

  function addMessage(kind, content, typing = false) {
    const row = el('div', `orbit-message orbit-message-${kind}`);
    const column = el('div');
    const body = el('div', 'orbit-message-body');
    if (kind === 'assistant') {
      const avatar = el('div', 'orbit-message-avatar');
      const icon = el('i', 'bi bi-stars');
      avatar.append(icon);
      row.append(avatar);
    }
    if (typing) {
      const dots = el('div', 'orbit-typing');
      dots.setAttribute('aria-label', 'Orbit is inspecting');
      for (let index = 0; index < 3; index++) dots.append(el('span'));
      body.append(dots);
    } else {
      body.textContent = content;
    }
    column.append(body, el('span', 'orbit-message-label', kind === 'user' ? 'You' : 'Orbit'));
    row.append(column);
    messages.append(row);
    scrollToLatest();
    return row;
  }

  function verdictCopy(result) {
    const action = result.action;
    const level = result.risk?.level || 'unknown';
    const count = result.rule_matches?.length || 0;
    const lead = {
      allow: 'This prompt looks safe to pass through.',
      warn: 'This prompt needs a closer look before use.',
      sanitize: 'Potentially unsafe content was found and can be sanitized.',
      block: 'This prompt should be blocked from reaching the model.'
    }[action] || 'Inspection complete.';
    const detail = count ? ` ${count} rule${count === 1 ? '' : 's'} matched.` : ' No detection rules matched.';
    return `${lead}\n\n${level.charAt(0).toUpperCase() + level.slice(1)} risk · Score ${result.risk?.score ?? '—'}.${detail}`;
  }

  function renderInspector(result) {
    inspector.replaceChildren();
    const wrap = el('div', 'orbit-verdict');
    const banner = el('div', `orbit-verdict-banner ${result.action}`);
    banner.append(el('span', 'orbit-verdict-label', 'Recommended action'));
    banner.append(el('div', 'orbit-verdict-action', result.action));
    banner.append(el('div', 'orbit-verdict-note', result.action === 'block' ? 'The firewall identified a high-risk instruction.' : 'Based on the latest prompt inspection.'));
    wrap.append(banner);

    const stats = [
      ['Risk level', result.risk?.level || 'Unknown'],
      ['Risk score', String(result.risk?.score ?? '—')],
      ['Scan time', `${result.response_time_ms ?? '—'} ms`]
    ];
    for (const [label, value] of stats) {
      const row = el('div', 'orbit-verdict-stat');
      row.append(el('span', '', label), el('strong', '', value));
      wrap.append(row);
    }

    const section = el('div', 'orbit-verdict-section');
    section.append(el('h3', '', 'Matched rules'));
    const matches = result.rule_matches || [];
    if (matches.length) {
      for (const match of matches) {
        const rule = el('div', 'orbit-rule');
        rule.append(el('strong', '', match.rule_id || match.category || 'Detection'));
        rule.append(el('p', '', match.description || 'Potentially unsafe content detected.'));
        section.append(rule);
      }
    } else {
      section.append(el('p', 'orbit-verdict-empty', 'No rules matched this prompt.'));
    }
    wrap.append(section);

    if (result.obfuscation_flags?.length) {
      const flags = el('div', 'orbit-verdict-section');
      flags.append(el('h3', '', 'Obfuscation signals'));
      flags.append(el('p', 'orbit-verdict-empty', result.obfuscation_flags.join(', ')));
      wrap.append(flags);
    }
    if (result.sanitized_text) {
      const sanitized = el('div', 'orbit-verdict-section');
      sanitized.append(el('h3', '', 'Sanitized text'));
      sanitized.append(el('div', 'orbit-rule', result.sanitized_text));
      wrap.append(sanitized);
    }
    inspector.append(wrap);
  }

  function resizeInput() {
    input.style.height = 'auto';
    input.style.height = `${Math.min(input.scrollHeight, 130)}px`;
  }

  async function submitPrompt() {
    const prompt = input.value.trim();
    if (!prompt || busy) return;
    busy = true;
    send.disabled = true;
    welcome?.remove();
    addMessage('user', prompt);
    input.value = '';
    resizeInput();
    const pending = addMessage('assistant', '', true);

    try {
      const data = new FormData(form);
      data.set('prompt', prompt);
      const response = await fetch(form.action || window.location.href, {
        method: 'POST',
        body: data,
        credentials: 'same-origin',
        headers: { Accept: 'application/json' }
      });
      const payload = await response.json();
      if (!response.ok || !payload.result) throw new Error(payload.error || 'Inspection failed. Please try again.');
      pending.remove();
      addMessage('assistant', verdictCopy(payload.result));
      renderInspector(payload.result);
    } catch (error) {
      pending.remove();
      addMessage('assistant', error.message || 'Inspection failed. Please try again.');
    } finally {
      busy = false;
      send.disabled = false;
      input.focus();
    }
  }

  form.addEventListener('submit', event => {
    event.preventDefault();
    submitPrompt();
  });
  input.addEventListener('input', resizeInput);
  input.addEventListener('keydown', event => {
    if (event.key === 'Enter' && !event.shiftKey && !event.isComposing) {
      event.preventDefault();
      submitPrompt();
    }
  });
  document.querySelectorAll('.orbit-suggestion').forEach(button => {
    button.addEventListener('click', () => {
      input.value = button.dataset.prompt;
      resizeInput();
      submitPrompt();
    });
  });
  document.getElementById('orbit-clear').addEventListener('click', () => {
    if (busy) return;
    window.location.href = form.action || window.location.pathname;
  });

  if (initialResult) {
    welcome?.remove();
    renderInspector(JSON.parse(initialResult.textContent));
    scrollToLatest();
  }
})();

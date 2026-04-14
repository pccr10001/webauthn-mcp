/**
 * WebAuthn Proxy - Popup Script
 */

// ── State ────────────────────────────────────────────────────────────────────
let settings = {};
let tokens = [];
let activeCredentialTokenId = null;
let toastTimer = null;

// ── Bootstrap ────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', async () => {
  await loadSettings();
  checkConnection();
  await loadTokens();
  wireEvents();
});

function wireEvents() {
  // Settings
  document.getElementById('saveBtn').addEventListener('click', onSave);
  document.getElementById('testBtn').addEventListener('click', checkConnection);
  document.getElementById('enableToggle').addEventListener('change', onToggle);

  // Tokens
  document.getElementById('refreshBtn').addEventListener('click', () => loadTokens());
  document.getElementById('createTokenBtn').addEventListener('click', showCreateForm);
  document.getElementById('cancelCreateBtn').addEventListener('click', hideCreateForm);
  document.getElementById('confirmCreateBtn').addEventListener('click', createToken);
  document.getElementById('newTokenName').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') createToken();
    if (e.key === 'Escape') hideCreateForm();
  });

  // Credentials panel
  document.getElementById('refreshCredsBtn').addEventListener('click', refreshCredentials);
}

// ── Messaging ────────────────────────────────────────────────────────────────
function msg(payload) {
  return new Promise((resolve, reject) => {
    chrome.runtime.sendMessage(payload, (response) => {
      if (chrome.runtime.lastError) {
        reject(new Error(chrome.runtime.lastError.message));
      } else {
        resolve(response);
      }
    });
  });
}

// ── Toast ────────────────────────────────────────────────────────────────────
function toast(text, type = '') {
  const el = document.getElementById('toast');
  clearTimeout(toastTimer);
  el.textContent = text;
  el.className = `toast ${type} show`;
  toastTimer = setTimeout(() => { el.className = 'toast'; }, 2600);
}

// ── HTML escaping ────────────────────────────────────────────────────────────
function esc(s) {
  return String(s ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function truncate(s, n) {
  s = String(s ?? '');
  return s.length > n ? s.slice(0, n) + '…' : s;
}

// ── Settings ─────────────────────────────────────────────────────────────────
async function loadSettings() {
  const res = await msg({ type: 'GET_SETTINGS' });
  settings = res.data;
  document.getElementById('enableToggle').checked = settings.enabled;
  document.getElementById('serverUrl').value = settings.serverUrl || '';
  document.getElementById('apiKey').value = settings.apiKey || '';
}

async function onSave() {
  const btn = document.getElementById('saveBtn');
  btn.disabled = true;
  try {
    settings.serverUrl = document.getElementById('serverUrl').value.trim();
    settings.apiKey = document.getElementById('apiKey').value.trim();
    await msg({ type: 'SAVE_SETTINGS', settings });
    toast('Settings saved', 'success');
    checkConnection();
    await loadTokens();
  } catch (err) {
    toast(err.message, 'error');
  } finally {
    btn.disabled = false;
  }
}

async function onToggle(e) {
  settings.enabled = e.target.checked;
  try {
    await msg({ type: 'SAVE_SETTINGS', settings });
    toast(settings.enabled ? 'Proxy enabled' : 'Proxy disabled', 'success');
  } catch (err) {
    toast(err.message, 'error');
  }
}

// ── Connection test ───────────────────────────────────────────────────────────
async function checkConnection() {
  const dot = document.getElementById('statusDot');
  dot.className = 'status-dot checking';
  try {
    const res = await msg({ type: 'TEST_CONNECTION' });
    dot.className = res.success ? 'status-dot ok' : 'status-dot error';
    dot.title = res.success ? 'Connected' : (res.error || 'Unreachable');
  } catch (err) {
    dot.className = 'status-dot error';
    dot.title = err.message;
  }
}

// ── Token list ────────────────────────────────────────────────────────────────
async function loadTokens() {
  const list = document.getElementById('tokenList');
  list.innerHTML = '<div class="empty-state">Loading…</div>';
  try {
    const res = await msg({ type: 'LIST_TOKENS' });
    if (!res.success) throw new Error(res.error);
    tokens = res.data || [];
    renderTokenList();
  } catch (err) {
    list.innerHTML = `<div class="empty-state">${esc(err.message)}</div>`;
  }
}

function renderTokenList() {
  const list = document.getElementById('tokenList');
  list.innerHTML = '';

  // "System WebAuthn" (no-proxy) option
  const systemItem = makeTokenItem(
    null,
    'System WebAuthn',
    "Pass through to the browser's native authenticator"
  );
  list.appendChild(systemItem);

  if (tokens.length === 0) {
    const empty = document.createElement('div');
    empty.className = 'empty-state';
    empty.style.paddingTop = '8px';
    empty.textContent = 'No tokens. Create one below.';
    list.appendChild(empty);
    return;
  }

  for (const token of tokens) {
    const name = token.name
      ? truncate(token.name, 28)
      : truncate(token.id, 12);
    const creds = token.credential_count || 0;
    const meta = `${creds} credential${creds !== 1 ? 's' : ''}\u2002·\u2002ID: ${token.id.slice(0, 8)}`;
    const item = makeTokenItem(token.id, name, meta, token.id);
    list.appendChild(item);
  }
}

function makeTokenItem(id, name, meta, fullId) {
  const isActive = settings.activeTokenId === id;
  const item = document.createElement('div');
  item.className = 'token-item' + (isActive ? ' active' : '');
  item.dataset.id = id ?? '';

  const radioId = `radio-${id ?? 'system'}`;

  item.innerHTML = `
    <input type="radio" name="activeToken" id="${radioId}" value="${esc(id ?? '')}" ${isActive ? 'checked' : ''}>
    <div class="token-info">
      <div class="token-name" title="${esc(fullId ?? name)}">${esc(name)}</div>
      <div class="token-meta">${esc(meta)}</div>
    </div>
    <div class="token-actions">
      ${id ? `<button class="action-btn creds-btn" title="View credentials">Creds</button>` : ''}
      ${id ? `<button class="action-btn delete del-btn" title="Delete token">Delete</button>` : ''}
    </div>
  `;

  // Click anywhere on row to select
  item.addEventListener('click', (e) => {
    if (e.target.tagName === 'BUTTON') return;
    selectToken(id);
  });
  item.querySelector('input').addEventListener('change', () => selectToken(id));

  if (id) {
    item.querySelector('.creds-btn').addEventListener('click', (e) => {
      e.stopPropagation();
      const token = tokens.find((t) => t.id === id);
      const displayName = token?.name
        ? truncate(token.name, 20)
        : id.slice(0, 8);
      showCredentials(id, displayName);
    });

    item.querySelector('.del-btn').addEventListener('click', (e) => {
      e.stopPropagation();
      deleteToken(id);
    });
  }

  return item;
}

async function selectToken(id) {
  settings.activeTokenId = id || null;
  try {
    await msg({ type: 'SAVE_SETTINGS', settings });
  } catch (err) {
    toast(err.message, 'error');
    return;
  }

  // Update radio + active class
  document.querySelectorAll('.token-item').forEach((el) => {
    const isActive = el.dataset.id === (id ?? '');
    el.classList.toggle('active', isActive);
    const radio = el.querySelector('input[type="radio"]');
    if (radio) radio.checked = isActive;
  });

  if (id) {
    const token = tokens.find((t) => t.id === id);
    const name = token?.name ? `"${token.name}"` : id.slice(0, 8);
    toast(`Active token: ${name}`, 'success');
  } else {
    toast('Using system WebAuthn');
    document.getElementById('credentialSection').classList.add('hidden');
    activeCredentialTokenId = null;
  }
}

async function deleteToken(id) {
  if (!confirm('Delete this token and all its credentials?')) return;
  try {
    const res = await msg({ type: 'DELETE_TOKEN', tokenId: id });
    if (!res.success) throw new Error(res.error);
    if (settings.activeTokenId === id) {
      settings.activeTokenId = null;
      await msg({ type: 'SAVE_SETTINGS', settings });
    }
    if (activeCredentialTokenId === id) {
      document.getElementById('credentialSection').classList.add('hidden');
      activeCredentialTokenId = null;
    }
    toast('Token deleted', 'success');
    await loadTokens();
  } catch (err) {
    toast(err.message, 'error');
  }
}

// ── Create token ──────────────────────────────────────────────────────────────
function showCreateForm() {
  document.getElementById('createTokenForm').classList.remove('hidden');
  document.getElementById('createTokenBtn').classList.add('hidden');
  document.getElementById('newTokenName').value = '';
  document.getElementById('newTokenName').focus();
}

function hideCreateForm() {
  document.getElementById('createTokenForm').classList.add('hidden');
  document.getElementById('createTokenBtn').classList.remove('hidden');
}

async function createToken() {
  const nameInput = document.getElementById('newTokenName');
  const name = nameInput.value.trim();
  const btn = document.getElementById('confirmCreateBtn');
  btn.disabled = true;
  try {
    const res = await msg({ type: 'CREATE_TOKEN', name });
    if (!res.success) throw new Error(res.error);
    hideCreateForm();
    toast('Token created', 'success');
    await loadTokens();
    // Auto-select the new token
    await selectToken(res.data.id);
  } catch (err) {
    toast(err.message, 'error');
  } finally {
    btn.disabled = false;
  }
}

// ── Credentials panel ─────────────────────────────────────────────────────────
async function showCredentials(tokenId, tokenName) {
  activeCredentialTokenId = tokenId;
  document.getElementById('credentialTitle').textContent =
    `Credentials — ${tokenName}`;
  document.getElementById('credentialSection').classList.remove('hidden');
  document.getElementById('credentialList').innerHTML =
    '<div class="empty-state">Loading…</div>';
  await refreshCredentials();
}

async function refreshCredentials() {
  if (!activeCredentialTokenId) return;
  const list = document.getElementById('credentialList');
  try {
    const res = await msg({
      type: 'LIST_CREDENTIALS',
      tokenId: activeCredentialTokenId,
    });
    if (!res.success) throw new Error(res.error);
    renderCredentialList(res.data || []);
  } catch (err) {
    list.innerHTML = `<div class="empty-state">${esc(err.message)}</div>`;
  }
}

function renderCredentialList(creds) {
  const list = document.getElementById('credentialList');
  if (creds.length === 0) {
    list.innerHTML = '<div class="empty-state">No credentials yet</div>';
    return;
  }
  list.innerHTML = '';
  for (const cred of creds) {
    const item = document.createElement('div');
    item.className = 'cred-item';
    const user = esc(cred.user_name || cred.user_display_name || '—');
    const rk = cred.resident_key ? ' · resident' : '';
    const shortId = cred.credential_id.slice(0, 14) + '…';

    item.innerHTML = `
      <div class="cred-info">
        <div class="cred-rp" title="${esc(cred.rp_id)}">${esc(cred.rp_id)}</div>
        <div class="cred-meta" title="${esc(cred.credential_id)}">
          ${user}${rk} · ctr ${cred.counter} · ${esc(shortId)}
        </div>
      </div>
      <button class="action-btn delete del-cred-btn" title="Delete credential">Delete</button>
    `;

    item.querySelector('.del-cred-btn').addEventListener('click', () => {
      deleteCredential(activeCredentialTokenId, cred.credential_id);
    });

    list.appendChild(item);
  }
}

async function deleteCredential(tokenId, credId) {
  if (!confirm('Delete this credential?')) return;
  try {
    const res = await msg({ type: 'DELETE_CREDENTIAL', tokenId, credId });
    if (!res.success) throw new Error(res.error);
    toast('Credential deleted', 'success');
    await Promise.all([refreshCredentials(), loadTokens()]);
  } catch (err) {
    toast(err.message, 'error');
  }
}

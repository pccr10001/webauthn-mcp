/**
 * WebAuthn Proxy - Credential Selector
 *
 * Opened as a popup window by the service worker when navigator.credentials.get()
 * is intercepted. Lets the user choose which passkey to use for authentication,
 * and optionally delete passkeys (with confirmation).
 */

const urlParams = new URLSearchParams(location.search);
const requestId = urlParams.get('requestId');

let tokenId = null;
let credentials = [];

// ── Helpers ──────────────────────────────────────────────────────────────────

function esc(s) {
  return String(s ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function msg(payload) {
  return new Promise((resolve, reject) => {
    chrome.runtime.sendMessage(payload, (res) => {
      if (chrome.runtime.lastError) {
        reject(new Error(chrome.runtime.lastError.message));
      } else {
        resolve(res);
      }
    });
  });
}

// ── Init ─────────────────────────────────────────────────────────────────────

async function init() {
  document.getElementById('cancelBtn').addEventListener('click', cancel);

  if (!requestId) {
    showError('Invalid request ID');
    return;
  }

  try {
    const res = await msg({ type: 'GET_CREDENTIAL_SELECTION', requestId });

    if (!res || !res.success) {
      showError(res?.error || 'Request not found or expired');
      return;
    }

    tokenId = res.data.tokenId;
    credentials = res.data.credentials || [];

    const rpId = res.data.rpId;
    if (rpId) {
      document.getElementById('rpId').textContent = rpId;
      document.getElementById('rpBanner').classList.remove('hidden');
    }

    renderCredentials();
  } catch (err) {
    showError(err.message);
  }
}

// ── Render ────────────────────────────────────────────────────────────────────

function renderCredentials() {
  const list = document.getElementById('credList');

  if (credentials.length === 0) {
    list.innerHTML = '<div class="empty-state">No matching passkeys found</div>';
    return;
  }

  list.innerHTML = '';
  for (const cred of credentials) {
    list.appendChild(makeCredItem(cred));
  }
}

function makeCredItem(cred) {
  const div = document.createElement('div');
  div.className = 'cred-item';
  div.dataset.credId = cred.credential_id;

  const userName = cred.user_name || cred.user_display_name || '';
  const userDisplay = esc(userName || '(unknown user)');
  const rpIdText = esc(cred.rp_id || '');
  const shortId = cred.credential_id.slice(0, 16) + '…';
  const counter = `ctr ${cred.counter}`;
  const residentBadge = cred.resident_key
    ? ' <span class="badge">resident</span>'
    : '';

  div.innerHTML = `
    <div class="cred-icon">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8">
        <circle cx="8" cy="15" r="4"/>
        <path d="M12 15h9M17 12v6M21 15h-3"/>
      </svg>
    </div>
    <div class="cred-info">
      <div class="cred-user">${userDisplay}</div>
      <div class="cred-rp" title="${rpIdText}">${rpIdText}</div>
      <div class="cred-meta" title="${esc(cred.credential_id)}">${esc(shortId)} &middot; ${esc(counter)}${residentBadge}</div>
    </div>
    <div class="cred-actions">
      <button class="btn btn-primary btn-sm use-btn">Use</button>
      <button class="action-btn delete del-btn" title="Delete this passkey">✕</button>
    </div>
  `;

  div.querySelector('.use-btn').addEventListener('click', () => {
    selectCredential(cred.credential_id);
  });

  div.querySelector('.del-btn').addEventListener('click', () => {
    const label = userName ? `"${userName}"` : 'this passkey';
    deleteCredential(cred.credential_id, div, label, cred.rp_id || '');
  });

  return div;
}

// ── Actions ───────────────────────────────────────────────────────────────────

async function selectCredential(credId) {
  try {
    await msg({ type: 'CREDENTIAL_SELECTED', requestId, credentialId: credId });
    window.close();
  } catch (err) {
    showError(err.message);
  }
}

async function deleteCredential(credId, itemEl, label, rpId) {
  const confirmed = confirm(
    `Delete passkey ${label} for ${rpId || 'this site'}?\n\nThis cannot be undone.`
  );
  if (!confirmed) return;

  const useBtn = itemEl.querySelector('.use-btn');
  const delBtn = itemEl.querySelector('.del-btn');
  useBtn.disabled = true;
  delBtn.disabled = true;

  try {
    const res = await msg({ type: 'DELETE_CREDENTIAL', tokenId, credId });
    if (!res.success) throw new Error(res.error || 'Delete failed');

    itemEl.remove();
    credentials = credentials.filter((c) => c.credential_id !== credId);

    if (credentials.length === 0) {
      document.getElementById('credList').innerHTML =
        '<div class="empty-state">No passkeys remaining</div>';
    }
  } catch (err) {
    useBtn.disabled = false;
    delBtn.disabled = false;
    showInlineError(itemEl, err.message);
  }
}

async function cancel() {
  try {
    await msg({ type: 'CREDENTIAL_CANCELLED', requestId });
  } catch (_) {
    // Ignore — window is closing anyway
  }
  window.close();
}

// ── Error display ─────────────────────────────────────────────────────────────

function showError(message) {
  document.getElementById('credList').innerHTML =
    `<div class="empty-state error">${esc(message)}</div>`;
}

function showInlineError(el, message) {
  let errEl = el.querySelector('.inline-error');
  if (!errEl) {
    errEl = document.createElement('div');
    errEl.className = 'inline-error';
    el.appendChild(errEl);
  }
  errEl.textContent = message;
  setTimeout(() => errEl?.remove(), 3000);
}

// ── Start ─────────────────────────────────────────────────────────────────────

init();

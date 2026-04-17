/**
 * WebAuthn Proxy - Background Service Worker
 *
 * Handles all communication between content scripts, popup, and the
 * webauthn-mcp HTTP server.
 */

const DEFAULT_SETTINGS = {
  serverUrl: 'http://localhost:8080',
  apiKey: '',
  activeTokenId: null,
  enabled: true,
};

// ── Pending credential selections ────────────────────────────────────────────
//
// When a WEBAUTHN_GET is intercepted, the service worker opens a selector
// popup window and stores a pending Promise here (keyed by a random requestId).
// The selector page resolves/rejects the promise via CREDENTIAL_SELECTED or
// CREDENTIAL_CANCELLED messages. Closing the popup window without selecting
// is treated as a cancellation via chrome.windows.onRemoved.
//
// Map<requestId, { resolve, reject, windowId, tokenId, credentials, rpId }>

const pendingSelections = new Map();

chrome.windows.onRemoved.addListener((windowId) => {
  for (const [requestId, entry] of pendingSelections.entries()) {
    if (entry.windowId === windowId) {
      pendingSelections.delete(requestId);
      entry.reject(
        new DOMException('User cancelled passkey selection', 'NotAllowedError')
      );
      break;
    }
  }
});

// ── Storage helpers ──────────────────────────────────────────────────────────

async function getSettings() {
  const result = await chrome.storage.local.get('settings');
  return Object.assign({}, DEFAULT_SETTINGS, result.settings || {});
}

async function saveSettings(settings) {
  await chrome.storage.local.set({ settings });
}

// ── HTTP client ──────────────────────────────────────────────────────────────

async function apiRequest(settings, method, path, body) {
  const url = settings.serverUrl.replace(/\/$/, '') + path;
  const headers = { 'Content-Type': 'application/json' };
  if (settings.apiKey) {
    headers['X-API-Key'] = settings.apiKey;
  }

  let response;
  try {
    response = await fetch(url, {
      method,
      headers,
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
  } catch (err) {
    throw new Error(`Cannot reach server: ${err.message}`);
  }

  if (response.status === 204) return null;

  const text = await response.text();
  let json;
  try {
    json = JSON.parse(text);
  } catch {
    throw new Error(`Server returned non-JSON response (${response.status})`);
  }

  if (!response.ok) {
    const msg = json.message || json.error || `HTTP ${response.status}`;
    const err = new Error(msg);
    err.statusCode = response.status;
    err.serverError = json.error;
    throw err;
  }

  return json;
}

// ── Message router ───────────────────────────────────────────────────────────

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  handleMessage(message)
    .then(sendResponse)
    .catch((err) =>
      sendResponse({ success: false, error: err.message || String(err) })
    );
  return true; // keep channel open for async response
});

async function handleMessage(msg) {
  const settings = await getSettings();

  switch (msg.type) {
    // ── WebAuthn intercept calls ─────────────────────────────────────────────
    case 'WEBAUTHN_CREATE':
      return handleCreate(settings, msg);

    case 'WEBAUTHN_GET':
      return handleGet(settings, msg);

    case 'UVPAA_CHECK':
      return {
        available: settings.enabled && settings.activeTokenId !== null,
      };

    // ── Settings management ──────────────────────────────────────────────────
    case 'GET_SETTINGS':
      return { success: true, data: settings };

    case 'SAVE_SETTINGS': {
      const merged = Object.assign({}, DEFAULT_SETTINGS, msg.settings);
      await saveSettings(merged);
      return { success: true };
    }

    // ── Token management ─────────────────────────────────────────────────────
    case 'LIST_TOKENS': {
      const data = await apiRequest(settings, 'GET', '/api/token');
      return { success: true, data: data || [] };
    }

    case 'CREATE_TOKEN': {
      const data = await apiRequest(settings, 'POST', '/api/token', {
        name: msg.name || '',
      });
      return { success: true, data };
    }

    case 'DELETE_TOKEN': {
      await apiRequest(settings, 'DELETE', `/api/token/${msg.tokenId}`);
      return { success: true };
    }

    // ── Credential management ────────────────────────────────────────────────
    case 'LIST_CREDENTIALS': {
      const data = await apiRequest(
        settings,
        'GET',
        `/api/token/${msg.tokenId}/credentials`
      );
      return { success: true, data: data || [] };
    }

    case 'DELETE_CREDENTIAL': {
      await apiRequest(
        settings,
        'DELETE',
        `/api/token/${msg.tokenId}/credentials/${msg.credId}`
      );
      return { success: true };
    }

    // ── Credential selector (used by selector popup) ──────────────────────────
    case 'GET_CREDENTIAL_SELECTION': {
      const entry = pendingSelections.get(msg.requestId);
      if (!entry) {
        return { success: false, error: 'Request not found or expired' };
      }
      return {
        success: true,
        data: {
          tokenId: entry.tokenId,
          credentials: entry.credentials,
          rpId: entry.rpId,
        },
      };
    }

    case 'CREDENTIAL_SELECTED': {
      const entry = pendingSelections.get(msg.requestId);
      if (!entry) {
        return { success: false, error: 'Request not found or expired' };
      }
      pendingSelections.delete(msg.requestId);
      entry.resolve(msg.credentialId);
      return { success: true };
    }

    case 'CREDENTIAL_CANCELLED': {
      const entry = pendingSelections.get(msg.requestId);
      if (!entry) {
        return { success: false, error: 'Request not found or expired' };
      }
      pendingSelections.delete(msg.requestId);
      entry.reject(
        new DOMException('User cancelled passkey selection', 'NotAllowedError')
      );
      return { success: true };
    }

    // ── Connection test ──────────────────────────────────────────────────────
    case 'TEST_CONNECTION': {
      try {
        const url = settings.serverUrl.replace(/\/$/, '') + '/health';
        const res = await fetch(url, { method: 'GET' });
        const ok = res.ok;
        return { success: ok, error: ok ? undefined : `HTTP ${res.status}` };
      } catch (err) {
        return { success: false, error: err.message };
      }
    }

    default:
      return { success: false, error: `Unknown message type: ${msg.type}` };
  }
}

// ── WebAuthn handler: navigator.credentials.create ──────────────────────────

async function handleCreate(settings, msg) {
  if (!settings.enabled) {
    return { passthrough: true };
  }
  if (!settings.activeTokenId) {
    return { passthrough: true };
  }

  const opts = msg.options;
  const authenticatorSelection = opts.authenticatorSelection || {};
  const residentKey =
    authenticatorSelection.residentKey ||
    (authenticatorSelection.requireResidentKey === true ? 'required' : 'discouraged');

  const registerRequest = {
    challenge: opts.challenge,
    rp: {
      id: opts.rp.id,
      name: opts.rp.name,
    },
    user: {
      id: opts.user.id,
      name: opts.user.name,
      displayName: opts.user.displayName,
    },
    attestation: opts.attestation || 'none',
    residentKey,
  };

  const overrides = {
    origin: msg.origin,
  };

  const result = await apiRequest(
    settings,
    'POST',
    `/api/token/${settings.activeTokenId}/register`,
    { request: registerRequest, overrides }
  );

  return { success: true, data: result.response };
}

// ── WebAuthn handler: navigator.credentials.get ─────────────────────────────

async function handleGet(settings, msg) {
  if (!settings.enabled) {
    return { passthrough: true };
  }
  if (!settings.activeTokenId) {
    return { passthrough: true };
  }

  const opts = msg.options;

  // Fetch all credentials stored in this token
  let allCreds = [];
  try {
    const credResult = await apiRequest(
      settings,
      'GET',
      `/api/token/${settings.activeTokenId}/credentials`
    );
    allCreds = credResult || [];
  } catch (_) {
    // If credential list is unavailable, fall through to direct authenticate
  }

  // Narrow to credentials matching the RP ID
  let relevantCreds = opts.rpId
    ? allCreds.filter((c) => c.rp_id === opts.rpId)
    : allCreds;

  // Further narrow by allowCredentials IDs when the site specifies them.
  // If ID-based filtering yields no results (e.g. format mismatch), keep the
  // rpId-filtered list so the user still sees candidates.
  if (opts.allowCredentials && opts.allowCredentials.length > 0) {
    const allowedIds = new Set(opts.allowCredentials.map((c) => c.id));
    const byId = relevantCreds.filter((c) => allowedIds.has(c.credential_id));
    if (byId.length > 0) {
      relevantCreds = byId;
    }
  }

  // Show selector popup when there are credentials to choose from
  let selectedCredentialId = null;

  if (relevantCreds.length > 0) {
    try {
      selectedCredentialId = await showCredentialSelector(
        settings.activeTokenId,
        relevantCreds,
        opts.rpId || null
      );
    } catch (err) {
      // User cancelled or window was closed — surface as NotAllowedError
      throw err;
    }
  }

  // Build authenticate request, restricting to the chosen credential if one
  // was selected, otherwise pass the original allowCredentials list
  const authenticateRequest = {
    challenge: opts.challenge,
    rpId: opts.rpId,
    allowCredentials: selectedCredentialId
      ? [{ type: 'public-key', id: selectedCredentialId }]
      : opts.allowCredentials || [],
    userVerification: opts.userVerification || 'preferred',
  };

  const overrides = {
    origin: msg.origin,
  };

  try {
    const result = await apiRequest(
      settings,
      'POST',
      `/api/token/${settings.activeTokenId}/authenticate`,
      { request: authenticateRequest, overrides }
    );
    return { success: true, data: result.response };
  } catch (err) {
    // If the token has no matching credential, fall through to system WebAuthn
    if (
      err.statusCode === 404 &&
      err.serverError === 'credential_not_found'
    ) {
      return { passthrough: true };
    }
    throw err;
  }
}

// ── Credential selector popup ────────────────────────────────────────────────

function showCredentialSelector(tokenId, credentials, rpId) {
  return new Promise((resolve, reject) => {
    const requestId =
      Date.now().toString(36) + Math.random().toString(36).slice(2);

    pendingSelections.set(requestId, {
      resolve,
      reject,
      windowId: null,
      tokenId,
      credentials,
      rpId,
    });

    const url =
      chrome.runtime.getURL('selector/selector.html') +
      '?requestId=' +
      encodeURIComponent(requestId);

    chrome.windows.create(
      { url, type: 'popup', width: 400, height: 480, focused: true },
      (win) => {
        if (chrome.runtime.lastError || !win) {
          pendingSelections.delete(requestId);
          reject(new Error('Failed to open credential selector'));
          return;
        }
        const entry = pendingSelections.get(requestId);
        if (entry) entry.windowId = win.id;
      }
    );
  });
}

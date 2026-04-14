/**
 * WebAuthn Proxy - Page-level interceptor
 *
 * Injected into every page to override navigator.credentials.create/get
 * and route calls through the webauthn-mcp server.
 *
 * Communication:
 *   Page → Content Script: window.postMessage({ source: 'WEBAUTHN_PROXY_REQUEST', ... })
 *   Content Script → Page: window.postMessage({ source: 'WEBAUTHN_PROXY_RESPONSE', ... })
 */
(function () {
  if (window.__webauthnProxyInjected) return;
  window.__webauthnProxyInjected = true;

  const originalCreate = navigator.credentials.create.bind(navigator.credentials);
  const originalGet = navigator.credentials.get.bind(navigator.credentials);

  // Pending requests: id -> { resolve, reject, callOriginal }
  const pending = new Map();

  // ── Encoding helpers ───────────────────────────────────────────────────────

  function bufferToBase64url(value) {
    if (!value) return null;
    const bytes =
      value instanceof ArrayBuffer
        ? new Uint8Array(value)
        : ArrayBuffer.isView(value)
        ? new Uint8Array(value.buffer, value.byteOffset, value.byteLength)
        : new Uint8Array(value);
    let str = '';
    for (const b of bytes) str += String.fromCharCode(b);
    return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  }

  function base64urlToBuffer(str) {
    if (!str) return null;
    const base64 = str.replace(/-/g, '+').replace(/_/g, '/');
    const padded = base64 + '='.repeat((4 - (base64.length % 4)) % 4);
    const raw = atob(padded);
    const buf = new Uint8Array(raw.length);
    for (let i = 0; i < raw.length; i++) buf[i] = raw.charCodeAt(i);
    return buf.buffer;
  }

  // ── Serializers (ArrayBuffer → base64url for transit) ─────────────────────

  function serializeCreateOptions(options) {
    const pko = options.publicKey;
    return {
      challenge: bufferToBase64url(pko.challenge),
      rp: { id: pko.rp.id || location.hostname, name: pko.rp.name },
      user: {
        id: bufferToBase64url(pko.user.id),
        name: pko.user.name,
        displayName: pko.user.displayName,
      },
      pubKeyCredParams: pko.pubKeyCredParams,
      timeout: pko.timeout,
      excludeCredentials: (pko.excludeCredentials || []).map((c) => ({
        type: c.type,
        id: bufferToBase64url(c.id),
        transports: c.transports,
      })),
      authenticatorSelection: pko.authenticatorSelection,
      attestation: pko.attestation || 'none',
      extensions: pko.extensions,
    };
  }

  function serializeGetOptions(options) {
    const pko = options.publicKey;
    return {
      challenge: bufferToBase64url(pko.challenge),
      rpId: pko.rpId || location.hostname,
      allowCredentials: (pko.allowCredentials || []).map((c) => ({
        type: c.type,
        id: bufferToBase64url(c.id),
        transports: c.transports,
      })),
      userVerification: pko.userVerification,
      timeout: pko.timeout,
      extensions: pko.extensions,
    };
  }

  // ── Response builders (server JSON → PublicKeyCredential-like objects) ─────

  function buildRegistrationCredential(serverResp) {
    const r = serverResp.response;
    return {
      id: serverResp.id,
      rawId: base64urlToBuffer(serverResp.rawId),
      type: serverResp.type || 'public-key',
      authenticatorAttachment: serverResp.authenticatorAttachment || 'platform',
      clientExtensionResults: serverResp.clientExtensionResults || {},
      getClientExtensionResults() {
        return this.clientExtensionResults;
      },
      response: {
        clientDataJSON: base64urlToBuffer(r.clientDataJSON),
        attestationObject: base64urlToBuffer(r.attestationObject),
        getTransports() {
          return r.transports || ['internal'];
        },
        getPublicKey() {
          return r.publicKey ? base64urlToBuffer(r.publicKey) : null;
        },
        getPublicKeyAlgorithm() {
          return r.publicKeyAlgorithm != null ? r.publicKeyAlgorithm : -7;
        },
        getAuthenticatorData() {
          return r.authenticatorData ? base64urlToBuffer(r.authenticatorData) : null;
        },
      },
    };
  }

  function buildAuthenticationCredential(serverResp) {
    const r = serverResp.response;
    return {
      id: serverResp.id,
      rawId: base64urlToBuffer(serverResp.rawId),
      type: serverResp.type || 'public-key',
      authenticatorAttachment: serverResp.authenticatorAttachment || 'platform',
      clientExtensionResults: serverResp.clientExtensionResults || {},
      getClientExtensionResults() {
        return this.clientExtensionResults;
      },
      response: {
        clientDataJSON: base64urlToBuffer(r.clientDataJSON),
        authenticatorData: base64urlToBuffer(r.authenticatorData),
        signature: base64urlToBuffer(r.signature),
        userHandle: r.userHandle ? base64urlToBuffer(r.userHandle) : null,
      },
    };
  }

  // ── Message bus ────────────────────────────────────────────────────────────

  window.addEventListener('message', (event) => {
    if (event.source !== window) return;
    if (!event.data || event.data.source !== 'WEBAUTHN_PROXY_RESPONSE') return;

    const { id, success, data, error, passthrough } = event.data;
    const entry = pending.get(id);
    if (!entry) return;
    pending.delete(id);

    if (passthrough) {
      // Extension is disabled or no token selected — call original
      entry.callOriginal();
      return;
    }

    if (success) {
      entry.resolve(data);
    } else {
      entry.reject(new DOMException(error || 'WebAuthn proxy operation failed', 'NotAllowedError'));
    }
  });

  function sendRequest(type, serializedOptions, originalFn, originalArgs) {
    return new Promise((resolve, reject) => {
      const id =
        Date.now().toString(36) + Math.random().toString(36).slice(2);

      const timer = setTimeout(() => {
        if (pending.has(id)) {
          pending.delete(id);
          reject(new DOMException('WebAuthn proxy request timed out', 'TimeoutError'));
        }
      }, 120000);

      pending.set(id, {
        resolve(data) {
          clearTimeout(timer);
          resolve(data);
        },
        reject(err) {
          clearTimeout(timer);
          reject(err);
        },
        callOriginal() {
          clearTimeout(timer);
          originalFn(...originalArgs).then(resolve).catch(reject);
        },
      });

      window.postMessage(
        {
          source: 'WEBAUTHN_PROXY_REQUEST',
          type,
          id,
          options: serializedOptions,
          origin: location.origin,
        },
        '*'
      );
    });
  }

  // ── API overrides ──────────────────────────────────────────────────────────

  navigator.credentials.create = function (options) {
    if (!options || !options.publicKey) {
      return originalCreate(options);
    }
    return sendRequest(
      'create',
      serializeCreateOptions(options),
      originalCreate,
      [options]
    ).then(buildRegistrationCredential);
  };

  navigator.credentials.get = function (options) {
    if (!options || !options.publicKey) {
      return originalGet(options);
    }
    return sendRequest(
      'get',
      serializeGetOptions(options),
      originalGet,
      [options]
    ).then(buildAuthenticationCredential);
  };

  // Keep isUserVerifyingPlatformAuthenticatorAvailable in sync
  const originalIsUVPAA =
    PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable?.bind(
      PublicKeyCredential
    );
  if (originalIsUVPAA) {
    PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable =
      async function () {
        // Ask content script whether a token is active
        return new Promise((resolve) => {
          const id =
            Date.now().toString(36) + Math.random().toString(36).slice(2);
          const timer = setTimeout(() => {
            window.removeEventListener('message', handler);
            originalIsUVPAA().then(resolve);
          }, 1000);

          function handler(event) {
            if (
              event.source !== window ||
              !event.data ||
              event.data.source !== 'WEBAUTHN_PROXY_UVPAA_RESPONSE' ||
              event.data.id !== id
            )
              return;
            clearTimeout(timer);
            window.removeEventListener('message', handler);
            resolve(event.data.available);
          }
          window.addEventListener('message', handler);
          window.postMessage(
            { source: 'WEBAUTHN_PROXY_UVPAA', id },
            '*'
          );
        });
      };
  }

  console.debug('[WebAuthn Proxy] Interceptor active on', location.origin);
})();

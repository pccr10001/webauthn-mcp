/**
 * WebAuthn Proxy - Content Script
 *
 * Runs at document_start in every frame.
 * 1. Injects webauthn-intercept.js into the page's JS context.
 * 2. Relays WebAuthn messages between the injected script and the background.
 */
(function () {
  // ── Inject the page-level interceptor ──────────────────────────────────────
  const script = document.createElement('script');
  script.src = chrome.runtime.getURL('inject/webauthn-intercept.js');
  script.onload = () => script.remove();
  (document.head || document.documentElement).appendChild(script);

  // ── Helpers ────────────────────────────────────────────────────────────────

  function replyToPage(id, payload) {
    window.postMessage(
      Object.assign({ source: 'WEBAUTHN_PROXY_RESPONSE', id }, payload),
      '*'
    );
  }

  function sendToBackground(msg) {
    return new Promise((resolve, reject) => {
      try {
        chrome.runtime.sendMessage(msg, (response) => {
          if (chrome.runtime.lastError) {
            reject(new Error(chrome.runtime.lastError.message));
          } else {
            resolve(response);
          }
        });
      } catch (err) {
        reject(err);
      }
    });
  }

  // ── Listen for messages from the injected script ───────────────────────────

  window.addEventListener('message', async (event) => {
    if (event.source !== window || !event.data) return;

    const { source, id } = event.data;

    // WebAuthn create / get ──────────────────────────────────────────────────
    if (source === 'WEBAUTHN_PROXY_REQUEST') {
      const { type, options, origin } = event.data;
      try {
        const response = await sendToBackground({
          type: type === 'create' ? 'WEBAUTHN_CREATE' : 'WEBAUTHN_GET',
          options,
          origin,
        });
        replyToPage(id, response);
      } catch (err) {
        replyToPage(id, { success: false, error: err.message });
      }
      return;
    }

    // isUserVerifyingPlatformAuthenticatorAvailable ──────────────────────────
    if (source === 'WEBAUTHN_PROXY_UVPAA') {
      try {
        const response = await sendToBackground({ type: 'UVPAA_CHECK' });
        window.postMessage(
          {
            source: 'WEBAUTHN_PROXY_UVPAA_RESPONSE',
            id,
            available: response.available,
          },
          '*'
        );
      } catch {
        window.postMessage(
          { source: 'WEBAUTHN_PROXY_UVPAA_RESPONSE', id, available: false },
          '*'
        );
      }
    }
  });
})();

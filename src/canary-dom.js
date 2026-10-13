/**
 * CanaryDOM v1.0.0
 * Zero-dependency client-side deception & integrity monitoring engine.
 * Detects DOM scrapers, malicious extensions, and DOM-XSS exfiltration.
 */
(function (global) {
  'use strict';

  const CanaryDOM = (function () {
    const config = {
      telemetryEndpoint: '/api/v1/security/canary-telemetry',
      appId: 'production-web-app',
      trapPrefix: '__honey_',
      enableTamperResistance: true
    };

    let alertQueue = [];
    let isInitialized = false;

    // Cryptographic Session Signature (Ephemeral)
    const sessionNonce = crypto.randomUUID ? crypto.randomUUID() : Math.random().toString(36).substring(2);

    /**
     * Dispatch structured threat telemetry to the backend endpoint.
     */
    function dispatchAlert(eventType, severity, details) {
      const payload = {
        timestamp: new Date().toISOString(),
        sessionNonce: sessionNonce,
        appId: config.appId,
        eventType: eventType,
        severity: severity, // LOW, MEDIUM, HIGH, CRITICAL
        url: window.location.href,
        referrer: document.referrer,
        details: details,
        userAgent: navigator.userAgent
      };

      alertQueue.push(payload);

      // Console security marker for debugging
      console.warn(`[CanaryDOM ALERT] [${severity}] ${eventType}:`, details);

      // Dispatch non-blocking telemetry via Beacon API
      if (navigator.sendBeacon) {
        const blob = new Blob([JSON.stringify(payload)], { type: 'application/json' });
        navigator.sendBeacon(config.telemetryEndpoint, blob);
      } else {
        fetch(config.telemetryEndpoint, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload),
          keepalive: true
        }).catch(() => {});
      }

      // Dispatch synthetic event for internal app handlers
      window.dispatchEvent(new CustomEvent('canary:alert', { detail: payload }));
    }

    /**
     * TRAP 1: Decoy DOM Honey-Inputs
     * Injects invisible fake inputs (API keys, session tokens, card numbers).
     * Triggers when automated scrapers or extensions dump input values.
     */
    function initializeHoneyDOM() {
      const honeyFieldNames = ['auth_token', 'stripe_key', 'admin_session', 'user_password_decoy'];

      honeyFieldNames.forEach((name) => {
        const input = document.createElement('input');
        input.type = 'text';
        input.name = `${config.trapPrefix}${name}`;
        input.id = `${config.trapPrefix}${name}`;
        input.value = `canary_${btoa(name)}_${sessionNonce.slice(0, 8)}`;
        
        // CSS stealth: Accessible to scrapers/extensions, completely hidden from humans
        Object.assign(input.style, {
          position: 'absolute',
          opacity: '0.0001',
          pointerEvents: 'none',
          left: '-9999px',
          top: '-9999px',
          width: '1px',
          height: '1px'
        });

        input.setAttribute('autocomplete', 'off');
        input.setAttribute('tabindex', '-1');
        input.setAttribute('data-canary', 'true');

        // Trap 1A: Reading or modifying the honeypot value via DOM accessors
        let trackedValue = input.value;
        Object.defineProperty(input, 'value', {
          get: function () {
            dispatchAlert('HONEY_INPUT_READ', 'HIGH', {
              field: name,
              stack: new Error().stack
            });
            return trackedValue;
          },
          set: function (val) {
            dispatchAlert('HONEY_INPUT_MUTATE', 'CRITICAL', {
              field: name,
              attemptedValue: val,
              stack: new Error().stack
            });
            trackedValue = val;
          }
        });

        // Trap 1B: Focus / click triggers (typical of automated form autofill scrapers)
        input.addEventListener('focus', () => {
          dispatchAlert('HONEY_INPUT_FOCUSED', 'MEDIUM', { field: name });
        });

        document.documentElement.appendChild(input);
      });
    }

    /**
     * TRAP 2: Proxy Traps on Global Decoy Objects
     * Detects scripts scanning the global window scope for secrets or session tokens.
     */
    function initializeHoneyGlobals() {
      const decoyGlobals = ['__API_CONFIG__', 'adminSessionContext', 'jwt_payload_cache'];

      decoyGlobals.forEach((globalKey) => {
        const trapTarget = {
          secret: `live_tok_${sessionNonce}`,
          privileges: ['SYSTEM_ADMIN', 'READ_ALL'],
          internalEndpoint: 'https://internal.auth-mesh.corp/vault'
        };

        const proxyHandler = {
          get: function (target, prop, receiver) {
            if (typeof prop === 'string' && prop !== 'toJSON') {
              dispatchAlert('GLOBAL_HONEYTOKEN_ACCESS', 'HIGH', {
                targetGlobal: globalKey,
                accessedProperty: prop,
                stack: new Error().stack
              });
            }
            return Reflect.get(target, prop, receiver);
          },
          set: function (target, prop, value, receiver) {
            dispatchAlert('GLOBAL_HONEYTOKEN_OVERWRITE', 'CRITICAL', {
              targetGlobal: globalKey,
              property: prop,
              newValueType: typeof value,
              stack: new Error().stack
            });
            return Reflect.set(target, prop, value, receiver);
          }
        };

        Object.defineProperty(window, globalKey, {
          value: new Proxy(trapTarget, proxyHandler),
          writable: false,
          configurable: false,
          enumerable: false
        });
      });
    }

    /**
     * TRAP 3: LocalStorage & SessionStorage Canary Monitor
     * Injects fake stored credentials and detects exfiltration attempts.
     */
    function initializeStorageCanaries() {
      const canaryStorageKey = 'oauth_client_secret_canary';
      const fakeSecret = `sec_live_${sessionNonce.substring(0, 12)}`;

      localStorage.setItem(canaryStorageKey, fakeSecret);

      const originalGetItem = localStorage.getItem.bind(localStorage);
      localStorage.getItem = function (key) {
        if (key === canaryStorageKey) {
          dispatchAlert('LOCALSTORAGE_CANARY_READ', 'HIGH', {
            key: key,
            stack: new Error().stack
          });
        }
        return originalGetItem(key);
      };

      // Watch across iframes or tabs via the StorageEvent
      window.addEventListener('storage', (event) => {
        if (event.key === canaryStorageKey) {
          dispatchAlert('LOCALSTORAGE_CANARY_CROSS_CONTEXT_TAMPER', 'CRITICAL', {
            oldValue: event.oldValue,
            newValue: event.newValue,
            url: event.url
          });
        }
      });
    }

    /**
     * TRAP 4: DOM Mutation & Script Injection Monitor
     * Flags dynamic `<script>` or `<iframe>` insertions matching Magecart / supply-chain behaviors.
     */
    function initializeMutationObserver() {
      const observer = new MutationObserver((mutations) => {
        mutations.forEach((mutation) => {
          mutation.addedNodes.forEach((node) => {
            if (node.nodeType === Node.ELEMENT_NODE) {
              const tagName = node.tagName.toLowerCase();
              if (tagName === 'script') {
                const src = node.getAttribute('src') || '[INLINE SCRIPT]';
                dispatchAlert('SUSPICIOUS_SCRIPT_INJECTION', 'HIGH', {
                  scriptSource: src,
                  inlineContentLength: node.textContent ? node.textContent.length : 0,
                  parent: node.parentElement ? node.parentElement.tagName : 'NONE'
                });
              } else if (tagName === 'iframe') {
                dispatchAlert('DYNAMIC_IFRAME_INJECTION', 'MEDIUM', {
                  src: node.getAttribute('src') || 'about:blank',
                  id: node.id
                });
              }
            }
          });
        });
      });

      observer.observe(document.documentElement, {
        childList: true,
        subtree: true
      });
    }

    /**
     * Initialization routine.
     */
    function init(userConfig = {}) {
      if (isInitialized) return;
      Object.assign(config, userConfig);

      if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', () => {
          initializeHoneyDOM();
          initializeHoneyGlobals();
          initializeStorageCanaries();
          initializeMutationObserver();
        });
      } else {
        initializeHoneyDOM();
        initializeHoneyGlobals();
        initializeStorageCanaries();
        initializeMutationObserver();
      }

      isInitialized = true;
    }

    return Object.freeze({
      init: init,
      getAlertQueue: function () { return [...alertQueue]; },
      getNonce: function () { return sessionNonce; }
    });
  })();

  global.CanaryDOM = CanaryDOM;
})(window);
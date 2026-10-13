/**
 * Basic headless verification runner
 * Run via: node test/canary.test.js
 */
const assert = require('assert');

// Mock browser primitives
global.window = global;
global.document = {
  readyState: 'complete',
  addEventListener: () => {},
  documentElement: { appendChild: () => {} },
  createElement: () => ({
    style: {},
    setAttribute: () => {},
    addEventListener: () => {}
  })
};
global.navigator = { userAgent: 'Node-Test-Runner', sendBeacon: () => true };
global.crypto = { randomUUID: () => '123e4567-e89b-12d3-a456-426614174000' };
global.localStorage = {
  setItem: () => {},
  getItem: (k) => k
};
global.MutationObserver = class {
  observe() {}
};
global.CustomEvent = class {
  constructor(name, opts) { this.detail = opts.detail; }
};
global.dispatchEvent = () => true;

// Load engine
require('../src/canary-dom.js');

CanaryDOM.init({ appId: 'unit-test' });

// Test 1: Global Honeytoken Proxy Trap
assert.ok(window.__API_CONFIG__, "Honey global should exist");
const secret = window.__API_CONFIG__.secret;
assert.ok(secret.startsWith('live_tok_'), "Should yield decoy token");

const queue = CanaryDOM.getAlertQueue();
assert.strictEqual(queue.length, 1, "Alert queue should record the unauthorized access");
assert.strictEqual(queue[0].eventType, 'GLOBAL_HONEYTOKEN_ACCESS', "Event type must match trap");

console.log("All CanaryDOM unit assertions passed successfully.");
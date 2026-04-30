// JSON-RPC plumbing for a smoldot Chain. Maintains:
//   - request-id counter and pendingRequests Map for request/response correlation
//   - per-subscription queues for notifications
//   - a single background loop pulling from chain.nextJsonRpcResponse()
//
// Adapted from examples/statement-chat/main.js (PR #3143).
export class SmoldotRpc {
  constructor(chain, { onUnexpected } = {}) {
    this.chain = chain;
    this.nextId = 1;
    this.pending = new Map();
    this.subs = new Map(); // subscriptionId -> { queue: [], waiters: [], closed }
    this.onUnexpected = onUnexpected ?? (() => {});
    this.stopped = false;
    this.loop = this.#run();
  }

  async request(method, params) {
    const id = String(this.nextId++);
    const body = JSON.stringify({ jsonrpc: "2.0", id, method, params });
    const promise = new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
    });
    this.chain.sendJsonRpc(body);
    return promise;
  }

  // Subscribe and return { id, next: () => Promise<value | null> }.
  // `next()` resolves with the next notification payload, or `null` once the
  // subscription is closed.
  async subscribe(subscribeMethod, params) {
    const id = await this.request(subscribeMethod, params);
    const sub = { queue: [], waiters: [], closed: false };
    this.subs.set(id, sub);
    return {
      id,
      next: () => {
        if (sub.queue.length > 0) return Promise.resolve(sub.queue.shift());
        if (sub.closed) return Promise.resolve(null);
        return new Promise((resolve) => sub.waiters.push(resolve));
      },
      close: () => this.#closeSub(id),
    };
  }

  async unsubscribe(unsubscribeMethod, subscriptionId) {
    try {
      await this.request(unsubscribeMethod, [subscriptionId]);
    } finally {
      this.#closeSub(subscriptionId);
    }
  }

  #closeSub(id) {
    const sub = this.subs.get(id);
    if (!sub || sub.closed) return;
    sub.closed = true;
    for (const w of sub.waiters) w(null);
    sub.waiters.length = 0;
    this.subs.delete(id);
  }

  stop() {
    this.stopped = true;
    for (const { reject } of this.pending.values()) {
      reject(new Error("RPC client stopped"));
    }
    this.pending.clear();
    for (const id of [...this.subs.keys()]) this.#closeSub(id);
  }

  async #run() {
    while (!this.stopped) {
      let raw;
      try {
        raw = await this.chain.nextJsonRpcResponse();
      } catch (e) {
        if (!this.stopped) this.onUnexpected(e);
        return;
      }
      let msg;
      try {
        msg = JSON.parse(raw);
      } catch (e) {
        this.onUnexpected(new Error(`bad JSON-RPC payload: ${e.message}`));
        continue;
      }

      if (msg.id !== undefined) {
        const pending = this.pending.get(msg.id);
        if (!pending) {
          this.onUnexpected(new Error(`response for unknown id ${msg.id}`));
          continue;
        }
        this.pending.delete(msg.id);
        if (msg.error) pending.reject(new Error(`JSON-RPC error: ${msg.error.message}`));
        else pending.resolve(msg.result);
        continue;
      }

      if (msg.method && msg.params?.subscription !== undefined) {
        const sub = this.subs.get(msg.params.subscription);
        if (!sub) continue; // stray notification (likely after unsubscribe)
        const payload = msg.params.result;
        if (sub.waiters.length > 0) sub.waiters.shift()(payload);
        else sub.queue.push(payload);
        continue;
      }

      this.onUnexpected(new Error(`unrecognized JSON-RPC message: ${raw}`));
    }
  }
}

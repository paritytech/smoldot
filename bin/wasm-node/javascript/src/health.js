// Smoldot
// Copyright (C) 2019-2021  Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

// Creates a new health checker.
//
// The role of the health checker is to report to the user the health of a smoldot chain.
//
// In order to use it, start by creating a health checker, and call `setSendJsonRpc` to set the
// way to send a JSON-RPC request to a chain. The health checker is disabled by default. Use
// `start()` in order to start the health checks. The `start()` function must be passed a callback called
// when an update to the health of the node is available.
//
// In order to send a JSON-RPC request to the chain, you **must** use the `sendJsonRpc` function
// of the health checker. The health checker rewrites the `id` of the requests it receives.
//
// When the chain send a JSON-RPC response, it must be passed to `responsePassThrough()`. This
// function intercepts the responses destined to the requests that have been emitted by the health
// checker and returns `null`. If the response doesn't concern the health checker, the response is
// simply returned by the function.
//
// # How it works
//
// The health checker periodically calls the `system_health` JSON-RPC call in order to determine
// the health of the chain.
//
// In addition to this, as long as the health check reports that `isSyncing` is `true`, the
// health checker also maintains a subscription to new best blocks and to runtime version changes
// using `chain_subscribeNewHeads` and `state_subscribeRuntimeVersion`.
// Whenever a new block or runtime version is notified, a health check is performed immediately
// in order to determine whether `isSyncing` has changed to `false`.
//
// Thanks to this subscription, the latency of the report of the switch from `isSyncing: true` to
// `isSyncing: false` is usually very low. It is, however, not completely robust: if the runtime
// version isn't modified after the chain has finished syncing, then it will take until the next
// best block to detect to end of the syncing.
//
export function healthChecker() {
    // `null` if health checker is not started.
    let checker = null;
    let sendJsonRpc = null;

    return {
        setSendJsonRpc: (cb) => {
            sendJsonRpc = cb;
        },

        start: (healthCallback) => {
            if (checker !== null)
                throw new Error("Can't start the health checker multiple times in parallel");
            if (!sendJsonRpc)
                throw new Error("setSendJsonRpc must be called before starting the health checks");

            checker = {
                healthCallback,
                currentHealthCheckId: null,
                currentHealthTimeout: null,
                currentBestSubunsubRequestId: null,
                currentBestSubscriptionId: null,
                currentRuntimeSubunsubRequestId: null,
                currentRuntimeSubscriptionId: null,
                isSyncing: false,
                nextRequestId: 0,

                sendJsonRpc: function (request) {
                    // Replace the `id` in the request to prefix the request ID with `extern:`.
                    let parsedRequest;
                    try {
                        parsedRequest = JSON.parse(request);
                    } catch (err) {
                        return;
                    };

                    if (parsedRequest.id) {
                        const newId = 'extern:' + JSON.stringify(parsedRequest.id);
                        parsedRequest.id = newId;
                    }

                    sendJsonRpc(JSON.stringify(parsedRequest));
                },

                responsePassThrough: function (jsonRpcResponse) {
                    let parsedResponse;
                    try {
                        parsedResponse = JSON.parse(jsonRpcResponse);
                    } catch (err) {
                        return jsonRpcResponse;
                    };

                    // Check whether response is a response to `system_health`.
                    if (parsedResponse.id && this.currentHealthCheckId == parsedResponse.id) {
                        this.currentHealthCheckId = null;

                        // Check whether query was successful. It is possible for queries to fail for
                        // various reasons, such as the client being overloaded.
                        if (!parsedResponse.result) {
                            this.update();
                            return null;
                        }

                        this.healthCallback(parsedResponse.result);
                        this.isSyncing = parsedResponse.result.isSyncing;
                        this.update();
                        return null;
                    }

                    // Check whether response is a response to the best block subscription or
                    // unsubscription.
                    if (parsedResponse.id && this.currentBestSubunsubRequestId == parsedResponse.id) {
                        this.currentBestSubunsubRequestId = null;

                        // Check whether query was successful. It is possible for queries to fail for
                        // various reasons, such as the client being overloaded.
                        if (!parsedResponse.result) {
                            this.update();
                            return null;
                        }

                        if (this.currentBestSubscriptionId)
                            this.currentBestSubscriptionId = null;
                        else
                            this.currentBestSubscriptionId = parsedResponse.result;

                        this.update();
                        return null;
                    }

                    // Check whether response is a response to the runtime version subscription or
                    // unsubscription.
                    if (parsedResponse.id && this.currentRuntimeSubunsubRequestId == parsedResponse.id) {
                        this.currentRuntimeSubunsubRequestId = null;

                        // Check whether query was successful. It is possible for queries to fail for
                        // various reasons, such as the client being overloaded.
                        if (!parsedResponse.result) {
                            this.update();
                            return null;
                        }

                        if (this.currentRuntimeSubscriptionId)
                            this.currentRuntimeSubscriptionId = null;
                        else
                            this.currentRuntimeSubscriptionId = parsedResponse.result;

                        this.update();
                        return null;
                    }

                    // Check whether response is a notification to a subscription.
                    if (parsedResponse.params && (
                        (this.currentBestSubscriptionId &&
                            parsedResponse.params.subscription == this.currentBestSubscriptionId)
                        ||
                        (this.currentRuntimeSubscriptionId &&
                            parsedResponse.params.subscription == this.currentRuntimeSubscriptionId)
                    )) {
                        // Note that after a successful subscription, a notification containing
                        // the current best block is always returned. Considering that a
                        // subscription is performed in response to a health check, calling
                        // `startHealthCheck()` here will lead to a second health check.
                        // It might seem redundant to perform two health checks in a quick
                        // succession, but doing so doesn't lead to any problem, and it is
                        // actually possible for the health to have changed in between as the
                        // current best block might have been updated during the subscription
                        // request.
                        this.startHealthCheck();
                        this.update();
                        return null;
                    }

                    // Response doesn't concern us.
                    if (parsedResponse.id) {
                        // Need to remove the `extern:` prefix.
                        if (!parsedResponse.id.startsWith('extern:'))
                            throw new Error('State inconsistency in health checker');
                        const newId = JSON.parse(parsedResponse.id.slice('extern:'.length));
                        parsedResponse.id = newId;
                    }

                    return JSON.stringify(parsedResponse);
                },

                update: function () {
                    if (!this.currentHealthTimeout) {
                        this.currentHealthTimeout = setTimeout(() => {
                            this.currentHealthTimeout = null;
                            this.startHealthCheck();
                        }, 10000);
                    }

                    if (this.isSyncing && !this.currentBestSubscriptionId && !this.currentBestSubunsubRequestId)
                        this.startBestSubscription();
                    if (this.isSyncing && !this.currentRuntimeSubscriptionId && !this.currentRuntimeSubunsubRequestId)
                        this.startRuntimeSubscription();
                    if (!this.isSyncing && this.currentBestSubscriptionId && !this.currentBestSubunsubRequestId)
                        this.endBestSubscription();
                    if (!this.isSyncing && this.currentRuntimeSubscriptionId && !this.currentRuntimeSubunsubRequestId)
                        this.endRuntimeSubscription();
                },

                startHealthCheck: function () {
                    if (this.currentHealthCheckId)
                        throw new Error('Internal error in health checker');
                    if (this.currentHealthTimeout) {
                        clearTimeout(this.currentHealthTimeout);
                        this.currentHealthTimeout = null;
                    }
                    this.currentHealthCheckId = "health-checker:" + this.nextRequestId;
                    this.nextRequestId += 1;
                    sendJsonRpc(JSON.stringify({
                        jsonrpc: "2.0",
                        id: this.currentHealthCheckId,
                        method: 'system_health',
                        params: [],
                    }));
                },

                startBestSubscription: function () {
                    if (this.currentBestSubunsubRequestId || this.currentBestSubscriptionId)
                        throw new Error('Internal error in health checker');
                    this.currentBestSubunsubRequestId = "health-checker:" + this.nextRequestId;
                    this.nextRequestId += 1;
                    sendJsonRpc(JSON.stringify({
                        jsonrpc: "2.0",
                        id: this.currentBestSubunsubRequestId,
                        method: 'chain_subscribeNewHeads',
                        params: [],
                    }));
                },

                endBestSubscription: function () {
                    if (this.currentBestSubunsubRequestId || !this.currentBestSubscriptionId)
                        throw new Error('Internal error in health checker');
                    this.currentBestSubunsubRequestId = "health-checker:" + this.nextRequestId;
                    this.nextRequestId += 1;
                    sendJsonRpc(JSON.stringify({
                        jsonrpc: "2.0",
                        id: this.currentBestSubunsubRequestId,
                        method: 'chain_unsubscribeNewHeads',
                        params: [this.currentBestSubscriptionId],
                    }));
                },

                startRuntimeSubscription: function () {
                    if (this.currentRuntimeSubunsubRequestId || this.currentRuntimeSubscriptionId)
                        throw new Error('Internal error in health checker');
                    this.currentRuntimeSubunsubRequestId = "health-checker:" + this.nextRequestId;
                    this.nextRequestId += 1;
                    sendJsonRpc(JSON.stringify({
                        jsonrpc: "2.0",
                        id: this.currentRuntimeSubunsubRequestId,
                        method: 'state_subscribeRuntimeVersion',
                        params: [],
                    }));
                },

                endRuntimeSubscription: function () {
                    if (this.currentRuntimeSubunsubRequestId || !this.currentRuntimeSubscriptionId)
                        throw new Error('Internal error in health checker');
                    this.currentRuntimeSubunsubRequestId = "health-checker:" + this.nextRequestId;
                    this.nextRequestId += 1;
                    sendJsonRpc(JSON.stringify({
                        jsonrpc: "2.0",
                        id: this.currentRuntimeSubunsubRequestId,
                        method: 'state_unsubscribeRuntimeVersion',
                        params: [this.currentRuntimeSubscriptionId],
                    }));
                },

                destroy: function () {
                    if (this.currentHealthTimeout) {
                        clearTimeout(this.currentHealthTimeout);
                        this.currentHealthTimeout = null;
                    }
                }
            };

            checker.startHealthCheck();
        },
        stop: () => {
            if (checker === null)
                return; // Already stopped.
            checker.destroy();
            checker = null;
        },
        sendJsonRpc: (request) => {
            if (!sendJsonRpc)
                throw new Error("setSendJsonRpc must be called before sending requests");
            if (checker === null)
                sendJsonRpc(request);
            else
                checker.sendJsonRpc(request);
        },
        responsePassThrough: (jsonRpcResponse) => {
            if (checker === null)
                return jsonRpcResponse;
            return checker.responsePassThrough(jsonRpcResponse);
        },
    };
}

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

import randombytes from 'randombytes';

// Creates a new health checker.
//
// The role of the health checker is to report to the user the health of a smoldot chain.
//
// In order to use it, start by creating a health checker. The health checker is disabled by
// default. Use `start()` in order to start the health checks. The `start()` function must be
// passed a function that the health checker can use to send JSON-RPC requests to the chain, and
// a callback called when an update to the health of the node is available.
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
// health checker also maintains a subscription to new best blocks using `chain_subscribeNewHeads`.
// Whenever a new block is notified, a health check is performed immediately in order to determine
// whether `isSyncing` has changed to `false`.
//
// Thanks to this subscription, the latency of the report of the switch from `isSyncing: true` to
// `isSyncing: false` is very low.
//
export function healthChecker() {
    // `null` if health checker is not started.
    let checker = null;

    return {
        start: (sendJsonRpc, healthCallback) => {
            if (checker !== null)
                throw new Error("Can't start the health checker multiple times in parallel");

            checker = {
                healthCallback,
                currentHealthCheckId: null,
                currentHealthTimeout: null,
                currentSubunsubRequestId: null,
                currentSubscriptionId: null,
                isSyncing: false,

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

                    // Check whether response is a response to the subscription or unsubscription.
                    if (parsedResponse.id && this.currentSubunsubRequestId == parsedResponse.id) {
                        this.currentSubunsubRequestId = null;

                        // Check whether query was successful. It is possible for queries to fail for
                        // various reasons, such as the client being overloaded.
                        if (!parsedResponse.result) {
                            this.update();
                            return null;
                        }

                        if (this.currentSubscriptionId)
                            this.currentSubscriptionId = null;
                        else
                            this.currentSubscriptionId = parsedResponse.result;

                        this.update();
                        return null;
                    }

                    // Check whether response is a notification to a subscription.
                    if (parsedResponse.params && this.currentSubscriptionId &&
                        parsedResponse.params.subscription == this.currentSubscriptionId) {
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
                    return jsonRpcResponse;
                },

                update: function () {
                    if (!this.currentHealthTimeout) {
                        this.currentHealthTimeout = setTimeout(() => {
                            this.currentHealthTimeout = null;
                            this.startHealthCheck();
                        }, 10000);
                    }

                    if (this.isSyncing && !this.currentSubscriptionId && !this.currentSubunsubRequestId)
                        this.startSubscription();
                    if (!this.isSyncing && this.currentSubscriptionId && !this.currentSubunsubRequestId)
                        this.endSubscription();
                },

                startHealthCheck: function () {
                    if (this.currentHealthCheckId)
                        throw new Error('Internal error in health checker');
                    if (this.currentHealthTimeout)
                        clearTimeout(this.currentHealthTimeout);
                    this.currentHealthCheckId = randombytes(32).toString('base64');
                    sendJsonRpc(JSON.stringify({
                        jsonrpc: "2.0",
                        id: this.currentHealthCheckId,
                        method: 'system_health',
                        params: [],
                    }));
                },

                startSubscription: function () {
                    if (this.currentSubunsubRequestId || this.currentSubscriptionId)
                        throw new Error('Internal error in health checker');
                    this.currentSubunsubRequestId = randombytes(32).toString('base64');
                    sendJsonRpc(JSON.stringify({
                        jsonrpc: "2.0",
                        id: this.currentSubunsubRequestId,
                        method: 'chain_subscribeNewHeads',
                        params: [],
                    }));
                },

                endSubscription: function () {
                    if (this.currentSubunsubRequestId || !this.currentSubscriptionId)
                        throw new Error('Internal error in health checker');
                    this.currentSubunsubRequestId = randombytes(32).toString('base64');
                    sendJsonRpc(JSON.stringify({
                        jsonrpc: "2.0",
                        id: this.currentSubunsubRequestId,
                        method: 'chain_unsubscribeNewHeads',
                        params: [this.currentSubscriptionId],
                    }));
                },

                destroy: function () {
                    if (this.currentHealthTimeout)
                        clearTimeout(this.currentHealthTimeout);
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
        responsePassThrough: (jsonRpcResponse) => {
            if (checker === null)
                return jsonRpcResponse;
            return checker.responsePassThrough(jsonRpcResponse);
        },
    };
}

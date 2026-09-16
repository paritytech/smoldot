// Smoldot
// Copyright (C) 2019-2022  Parity Technologies (UK) Ltd.
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

/// <reference lib="dom" />

import { Client, ClientOptionsWithBytecode } from './public-types.js'
import { start as innerStart, Connection, ConnectionConfig } from './internals/client.js'

export {
    AddChainError,
    AddChainOptions,
    AlreadyDestroyedError,
    Chain,
    Client,
    ClientOptions,
    ClientOptionsWithBytecode,
    SmoldotBytecode,
    CrashError,
    JsonRpcDisabledError,
    QueueFullError,
    LogCallback
} from './public-types.js';

/**
 * Initializes a new client. This is a pre-requisite to connecting to a blockchain.
 *
 * Can never fail.
 *
 * @param options Configuration of the client.
 */
export function startWithBytecode(options: ClientOptionsWithBytecode): Client {
    options.forbidTcp = true;

    // Browsers only expose the WebRTC API on `Window`, it doesn't exist in worker global
    // scopes, and consequently there is no way to open WebRTC connections from here.
    if (typeof RTCPeerConnection === 'undefined')
        options.forbidWebRtc = true;

    // When in a secure context, browsers refuse to open non-secure WebSocket connections to
    // non-localhost. There is an exception if the page is localhost, in which case all connections
    // are allowed.
    // Detecting this ahead of time is better for the overall health of the client, as it will
    // avoid storing in memory addresses that it knows it can't connect to.
    // The condition below is a hint, and false-positives or false-negatives are not fundamentally
    // an issue.
    if ((typeof isSecureContext === 'boolean' && isSecureContext) && typeof location !== 'undefined') {
        const hostname = location.hostname;
        if (hostname !== 'localhost' && hostname !== '127.0.0.1' && hostname !== '[::1]' && hostname !== '::1') {
            options.forbidNonLocalWs = true;
        }
    }

    return innerStart(options, options.bytecode, {
        performanceNow: () => {
            return performance.now()
        },
        getRandomValues: (buffer) => {
            const crypto = globalThis.crypto;
            if (!crypto)
                throw new Error('randomness not available');

            // Browsers have this completely undocumented behavior (it's not even part of a spec)
            // that for some reason `getRandomValues` can't be called on arrayviews back by
            // `SharedArrayBuffer`s and they throw an exception if you try.
            if (buffer.buffer instanceof ArrayBuffer)
                crypto.getRandomValues(buffer);
            else {
                const tmpArray = new Uint8Array(buffer.length);
                crypto.getRandomValues(tmpArray);
                buffer.set(tmpArray);
            }
        },
        connect: (config) => {
            return connect(config)
        }
    })
}

/**
 * Tries to open a new connection using the given configuration.
 *
 * @see Connection
 * @throws any If the multiaddress couldn't be parsed or contains an invalid protocol.
 */
export function connect(config: ConnectionConfig): Connection {
    if (config.address.ty === "webtransport") {
        return connectWebTransport(config);
    } else if (config.address.ty === "websocket") {
        // Even though the WHATWG specification (<https://websockets.spec.whatwg.org/#dom-websocket-websocket>)
        // doesn't mention it, `new WebSocket` can throw an exception if the URL is forbidden
        // for security reasons. We absord this exception as soon as it is thrown.
        // `connection` can be either a `WebSocket` object (the normal case), or a string
        // indicating an error message that must be propagated with `onConnectionReset` as soon
        // as possible, or `null` if the API user considers the connection as reset.
        let connection: WebSocket | string | null;
        try {
            connection = new WebSocket(config.address.url);
        } catch (error) {
            connection = error instanceof Error ? error.toString() : "Exception thrown by new WebSocket";
        }

        const bufferedAmountCheck = { quenedUnreportedBytes: 0, nextTimeout: 10 };
        const checkBufferedAmount = () => {
            if (!(connection instanceof WebSocket))
                return;
            if (connection.readyState != 1)
                return;
            // Note that we might expect `bufferedAmount` to always be <= the sum of the lengths
            // of all the data that has been sent, but that might not be the case. For this
            // reason, we use `bufferedAmount` as a hint rather than a correct value.
            const bufferedAmount = connection.bufferedAmount;
            let wasSent = bufferedAmountCheck.quenedUnreportedBytes - bufferedAmount;
            if (wasSent < 0) wasSent = 0;
            bufferedAmountCheck.quenedUnreportedBytes -= wasSent;
            if (bufferedAmountCheck.quenedUnreportedBytes != 0) {
                setTimeout(checkBufferedAmount, bufferedAmountCheck.nextTimeout);
                bufferedAmountCheck.nextTimeout *= 2;
                if (bufferedAmountCheck.nextTimeout > 500)
                    bufferedAmountCheck.nextTimeout = 500;
            }
            // Note: it is important to call `onWritableBytes` at the very end, as it might
            // trigger a call to `send`.
            if (wasSent != 0)
                config.onWritableBytes(wasSent);
        };

        if (connection instanceof WebSocket) {
            connection.binaryType = 'arraybuffer';

            connection.onopen = () => {
                config.onWritableBytes(1024 * 1024);
            };
            connection.onclose = (event) => {
                const message = "Error code " + event.code + (!!event.reason ? (": " + event.reason) : "");
                config.onConnectionReset(message);
            };
            connection.onmessage = (msg) => {
                config.onMessage(new Uint8Array(msg.data as ArrayBuffer));
            };
        } else {
            setTimeout(() => {
                if (connection && !(connection instanceof WebSocket)) {
                    config.onConnectionReset(connection);
                    connection = null;
                }
            }, 1)
        }

        return {
            reset: (): void => {
                if (connection instanceof WebSocket) {
                    connection.onopen = null;
                    connection.onclose = null;
                    connection.onmessage = null;
                    connection.onerror = null;

                    // According to the WebSocket specification, calling `close()` when a WebSocket
                    // isn't fully opened yet is completely legal and seemingly a normal thing to
                    // do (see <https://websockets.spec.whatwg.org/#dom-websocket-close>).
                    // Unfortunately, browsers print a warning in the console if you do that. To
                    // avoid these warnings, we only call `close()` if the connection is fully
                    // opened. According to <https://websockets.spec.whatwg.org/#garbage-collection>,
                    // removing all the event listeners will cause the WebSocket to be garbage
                    // collected, which should have the same effect as `close()`.
                    if (connection.readyState == WebSocket.OPEN)
                        connection.close();
                }

                connection = null;
            },

            send: (data: Array<Uint8Array>): void => {
                if (bufferedAmountCheck.quenedUnreportedBytes == 0) {
                    bufferedAmountCheck.nextTimeout = 10;
                    setTimeout(checkBufferedAmount, 10);
                }
                for (const buffer of data) {
                    bufferedAmountCheck.quenedUnreportedBytes += buffer.length;
                }
                (connection as WebSocket).send(new Blob(data));
            },

            closeSend: (): void => { throw new Error('Wrong connection type') },
            openOutSubstream: () => { throw new Error('Wrong connection type') }
        };
    } else if (config.address.ty === "webrtc") {
        // Browsers only expose the WebRTC API on `Window`.
        // When running in a worker, opening a WebRTC connection is impossible.
        // Instead of throwing an exception (which would crash the entire client),
        // report the connection as reset so that smoldot moves on to other
        // addresses.
        //
        // Note: `startWithBytecode` sets `forbidWebRtc` in that situation, making
        // this code path unreachable, but better be defensive.
        if (typeof RTCPeerConnection === 'undefined') {
            let cancelled = false;
            setTimeout(() => {
                if (!cancelled)
                    config.onConnectionReset('RTCPeerConnection is not available in this environment');
            }, 1);
            return {
                reset: (): void => { cancelled = true; },
                send: (): void => { throw new Error('Connection is closed') },
                closeSend: (): void => { throw new Error('Connection is closed') },
                openOutSubstream: () => { throw new Error('Connection is closed') },
            };
        }

        const { targetPort, ipVersion, targetIp, remoteTlsCertificateSha256 } =
            config.address;

        const state: {
            // Note that `pc` can be the connection, but also null or undefined.
            // `undefined` means "certificate generation in progress", while `null` means "opening must
            // be cancelled".
            // While it would be better to use for example a string instead of `null`, using `null` lets
            // us use the `!` operator more easily and leads to more readable code.
            pc: RTCPeerConnection | null | undefined,
            // Contains the data channels that are open and have been reported to smoldot.
            dataChannels: Map<number, { channel: RTCDataChannel, bufferedBytes: number }>,
            // Identifier to attribute to the next substream. Only for API purposes.
            nextStreamId: number,
            // Set to `true` before any outbound substream is open. Used to detect when the first
            // substream is opened.
            isFirstOutSubstream: boolean,
        } = {
            pc: undefined,
            dataChannels: new Map(),
            nextStreamId: 0,
            isFirstOutSubstream: true,
        };

        // Kills all the JavaScript objects (the connection and all its substreams), ensuring that no
        // callback will be called again. Doesn't report anything to smoldot, as this should be done
        // by the caller.
        const killAllJs = () => {
            // The `RTCPeerConnection` is created pretty quickly. It is however still possible for
            // smoldot to cancel the opening, in which case `pc` will still be undefined.
            if (!state.pc) {
                console.assert(state.dataChannels.size === 0, "substreams exist while pc is undef")
                state.pc = null;
                return
            }

            state.pc!.onconnectionstatechange = null;
            state.pc!.onnegotiationneeded = null;
            state.pc!.ondatachannel = null;

            for (const channel of Array.from(state.dataChannels.values())) {
                channel.channel.onopen = null;
                channel.channel.onerror = null;
                channel.channel.onclose = null;
                channel.channel.onbufferedamountlow = null;
                channel.channel.onmessage = null;
            }
            state.dataChannels.clear();

            state.pc!.close();  // Not necessarily necessary, but it doesn't hurt to do so.
        };

        // Function that configures a newly-opened channel and adds it to the map. Used for both
        // inbound and outbound substreams.
        const addChannel = (dataChannel: RTCDataChannel, direction: 'inbound' | 'outbound') => {
            const streamId = state.nextStreamId;
            state.nextStreamId += 1;
            dataChannel.binaryType = 'arraybuffer';

            let isOpen = { value: false };

            dataChannel.onopen = () => {
                // Guard against the `open` event firing more than once for the same channel.
                // Reporting the same stream id twice would make smoldot panic (observed in
                // production as "same stream_id used multiple times in
                // connection_stream_opened").
                console.assert(!isOpen.value, "substream opened twice")
                if (isOpen.value)
                    return;
                isOpen.value = true;
                config.onStreamOpened(streamId, direction);
                // The callback may synchronously reject and remove this channel.
                if (state.dataChannels.has(streamId))
                    config.onWritableBytes(65536, streamId);
            };

            dataChannel.onerror = dataChannel.onclose = (event) => {
                // Note that Firefox doesn't support <https://developer.mozilla.org/en-US/docs/Web/API/RTCErrorEvent>.
                const message = (event instanceof RTCErrorEvent) ? event.error.toString() : "RTCDataChannel closed";

                if (!isOpen.value) {
                    // Substream wasn't opened yet and thus has failed to open. The API has no
                    // mechanism to report substream openings failures. We could try opening it
                    // again, but given that it's unlikely to succeed, we simply opt to kill the
                    // entire connection.
                    killAllJs();
                    // Note that the event doesn't give any additional reason for the failure.
                    config.onConnectionReset("data channel failed to open: " + message);
                } else {
                    // Substream was open and is now closed. Normal situation.
                    dataChannel.onopen = null;
                    dataChannel.onerror = null;
                    dataChannel.onclose = null;
                    dataChannel.onbufferedamountlow = null;
                    dataChannel.onmessage = null;
                    state.dataChannels.delete(streamId);
                    config.onStreamReset(streamId, message);
                }
            };

            dataChannel.onbufferedamountlow = () => {
                const channel = state.dataChannels.get(streamId)!;
                const val = channel.bufferedBytes;
                channel.bufferedBytes = 0;
                config.onWritableBytes(val, streamId);
            };

            dataChannel.onmessage = (m) => {
                // The `data` field is an `ArrayBuffer`.
                config.onMessage(new Uint8Array(m.data), streamId);
            }

            state.dataChannels.set(streamId, { channel: dataChannel, bufferedBytes: 0 });
        }

        // It is possible for the browser to use multiple different certificates.
        // In order for our local certificate to be deterministic, we need to generate it manually and
        // set it explicitly as part of the configuration.
        // According to <https://w3c.github.io/webrtc-pc/#dom-rtcpeerconnection-generatecertificate>,
        // browsers are guaranteed to support `{ name: "ECDSA", namedCurve: "P-256" }`.
        RTCPeerConnection.generateCertificate({ name: "ECDSA", namedCurve: "P-256", hash: "SHA-256" } as EcKeyGenParams).then(async (localCertificate) => {
            if (state.pc === null)
                return;

            // Due to <https://bugzilla.mozilla.org/show_bug.cgi?id=1659672>, connections from
            // Firefox to a localhost WebRTC server always fails. Since this bug has been opened
            // for three years at the time of writing, it is unlikely to be fixed in the short
            // term. In order to provider better user feedback, we straight up refuse connecting
            // and stop the connection.
            // Note that this is just a hint. Failing to detect this will lead to the WebRTC
            // handshake  timing out.
            // TODO: eventually remove this if the Firefox bug is fixed
            if ((targetIp == 'localhost' || targetIp == '127.0.0.1' || targetIp == '::1') && navigator.userAgent.indexOf('Firefox') !== -1) {
                killAllJs();
                config.onConnectionReset("Firefox can't connect to a localhost WebRTC server");
                return;
            }

            // Create a new WebRTC connection.
            state.pc = new RTCPeerConnection({ certificates: [localCertificate] });

            // We need to build the multihash corresponding to the local certificate.
            // While there exists a `RTCPeerConnection.getFingerprints` function, Firefox notably
            // doesn't support it.
            // See <https://developer.mozilla.org/en-US/docs/Web/API/RTCCertificate#browser_compatibility>
            // An alternative to `getFingerprints` is to ask the browser to generate an SDP offer and
            // extract from fingerprint from it. Because we explicitly provide a certificate, we have
            // the guarantee that the list of certificates will always be the same whenever an SDP offer
            // is generated by the browser. However, while this alternative does work on Firefox, it
            // doesn't on Chrome, as the SDP offer is for some reason missing the fingerprints.
            // Therefore, our strategy is to use `getFingerprints` when it is available (i.e. every
            // browser except Firefox), and parse the SDP offer when it is not (i.e. Firefox). In the
            // future, only `getFingerprints` would be used.
            let localTlsCertificateHex: string | undefined;
            if (localCertificate.getFingerprints as any) {
                for (const { algorithm, value } of localCertificate.getFingerprints()) {
                    if (algorithm === 'sha-256') {
                        localTlsCertificateHex = value!
                        break;
                    }
                }
            } else {
                const localSdpOffer = await state.pc.createOffer();
                // Note that this regex is not strict. The browser isn't a malicious actor, and the
                // objective of this regex is not to detect invalid input.
                const localSdpOfferFingerprintMatch = localSdpOffer.sdp!.match(/a(\s*)=(\s*)fingerprint:(\s*)(sha|SHA)-256(\s*)(([a-fA-F0-9]{2}(:)*){32})/);
                if (localSdpOfferFingerprintMatch) {
                    localTlsCertificateHex = localSdpOfferFingerprintMatch[6]!;
                }
            }
            if (localTlsCertificateHex === undefined) {
                // Because we've already returned from the `connect` function at this point, we pretend
                // that the connection has failed to open.
                config.onConnectionReset('Failed to obtain the browser certificate fingerprint');
                return;
            }

            let localTlsCertificateSha256 = new Uint8Array(32);
            localTlsCertificateSha256.set(localTlsCertificateHex!.split(':').map((s) => parseInt(s, 16)), 0);

            // `onconnectionstatechange` is used to detect when the connection has closed or has failed
            // to open.
            // Note that smoldot will think that the connection is open even when it is still opening.
            // Therefore we don't care about events concerning the fact that the connection is now fully
            // open.
            state.pc.onconnectionstatechange = (_event) => {
                if (state.pc!.connectionState == "closed" || state.pc!.connectionState == "disconnected" || state.pc!.connectionState == "failed") {
                    killAllJs();
                    config.onConnectionReset("WebRTC state transitioned to " + state.pc!.connectionState);
                }
            };

            state.pc.onnegotiationneeded = async (_event) => {
                // Create a new offer and set it as local description.
                let sdpOffer = (await state.pc!.createOffer()).sdp!;
                // We check that the locally-generated SDP offer has a data channel with the UDP
                // protocol. If that isn't the case, the connection will likely fail.
                if (sdpOffer.match(/^m=application(\s+)(\d+)(\s+)UDP\/DTLS\/SCTP(\s+)webrtc-datachannel$/m) === null) {
                    console.error("Local offer doesn't contain UDP data channel. WebRTC connections will likely fail. Please report this issue.");
                }
                // According to the libp2p WebRTC spec, the ufrag and pwd are the same
                // randomly-generated string on both sides, and must be prefixed with
                // `libp2p-webrtc-v1:`. We modify the local description to ensure that.
                // While we could randomly generate a new string, we just grab the one that the
                // browser has generated, in order to make sure that it respects the constraints
                // of the ICE protocol.
                const browserGeneratedPwd = sdpOffer.match(/^a=ice-pwd:(.+)$/m)?.at(1);
                if (browserGeneratedPwd === undefined) {
                    console.error("Failed to set ufrag to pwd. WebRTC connections will likely fail. Please report this issue.");
                }
                const ufragPwd = "libp2p+webrtc+v1/" + browserGeneratedPwd;
                sdpOffer = sdpOffer.replace(/^a=ice-ufrag.*$/m, 'a=ice-ufrag:' + ufragPwd);
                sdpOffer = sdpOffer.replace(/^a=ice-pwd.*$/m, 'a=ice-pwd:' + ufragPwd);
                await state.pc!.setLocalDescription({ type: 'offer', sdp: sdpOffer });

                // Transform certificate hash into fingerprint (upper-hex; each byte separated by ":").
                const fingerprint = Array.from(remoteTlsCertificateSha256).map((n) => ("0" + n.toString(16)).slice(-2).toUpperCase()).join(':');

                // Note that the trailing line feed is important, as otherwise Chrome
                // fails to parse the payload.
                const remoteSdp =
                    // Version of the SDP protocol. Always 0. (RFC8866)
                    "v=0" + "\n" +
                    // Identifies the creator of the SDP document. We are allowed to use dummy values
                    // (`-` and `0.0.0.0`) to remain anonymous, which we do. Note that "IN" means
                    // "Internet" (and not "input"). (RFC8866)
                    "o=- 0 0 IN IP" + ipVersion + " " + targetIp + "\n" +
                    // Name for the session. We are allowed to pass a dummy `-`. (RFC8866)
                    "s=-" + "\n" +
                    // Start and end of the validity of the session. `0 0` means that the session never
                    // expires. (RFC8866)
                    "t=0 0" + "\n" +
                    // A lite implementation is only appropriate for devices that will
                    // always be connected to the public Internet and have a public
                    // IP address at which it can receive packets from any
                    // correspondent.  ICE will not function when a lite implementation
                    // is placed behind a NAT (RFC8445).
                    "a=ice-lite" + "\n" +
                    // A `m=` line describes a request to establish a certain protocol.
                    // The protocol in this line (i.e. `TCP/DTLS/SCTP` or `UDP/DTLS/SCTP`) must always be
                    // the same as the one in the offer. We know that this is true because checked above.
                    // The `<fmt>` component must always be `webrtc-datachannel` for WebRTC.
                    // The rest of the SDP payload adds attributes to this specific media stream.
                    // RFCs: 8839, 8866, 8841
                    "m=application " + String(targetPort) + " " + "UDP/DTLS/SCTP webrtc-datachannel" + "\n" +
                    // Indicates the IP address of the remote.
                    // Note that "IN" means "Internet" (and not "input").
                    "c=IN IP" + ipVersion + " " + targetIp + "\n" +
                    // Media ID - uniquely identifies this media stream (RFC9143).
                    "a=mid:0" + "\n" +
                    // Indicates that we are complying with RFC8839 (as oppposed to the legacy RFC5245).
                    "a=ice-options:ice2" + "\n" +
                    // ICE username and password, which are used for establishing and
                    // maintaining the ICE connection. (RFC8839)
                    // These values are set according to the libp2p WebRTC specification.
                    "a=ice-ufrag:" + ufragPwd + "\n" +
                    "a=ice-pwd:" + ufragPwd + "\n" +
                    // Fingerprint of the certificate that the server will use during the TLS
                    // handshake. (RFC8122)
                    // MUST be derived from the certificate used by the answerer (server).
                    "a=fingerprint:sha-256 " + fingerprint + "\n" +
                    // Indicates that the remote DTLS server will only listen for incoming
                    // connections. (RFC5763)
                    // The answerer (server) MUST not be located behind a NAT (RFC6135).
                    "a=setup:passive" + "\n" +
                    // The SCTP port (RFC8841)
                    // Note it's different from the "m=" line port value, which
                    // indicates the port of the underlying transport-layer protocol
                    // (UDP or TCP)
                    "a=sctp-port:5000" + "\n" +
                    // The maximum SCTP user message size (in bytes) (RFC8841)
                    // Setting this field is part of the libp2p spec.
                    "a=max-message-size:16384" + "\n" +
                    // A transport address for a candidate that can be used for connectivity
                    // checks (RFC8839).
                    "a=candidate:1 1 UDP 1 " + targetIp + " " + String(targetPort) + " typ host" + "\n";

                await state.pc!.setRemoteDescription({ type: "answer", sdp: remoteSdp });
            };

            state.pc.ondatachannel = ({ channel }) => {
                // TODO: is the substream maybe already open? according to the Internet it seems that no but it's unclear
                addChannel(channel, 'inbound')
            };

            config.onMultistreamHandshakeInfo({
                handshake: 'webrtc',
                localTlsCertificateSha256,
            });
        });

        return {
            reset: (streamId: number | undefined): void => {
                // If `streamId` is undefined, then the whole connection must be destroyed.
                if (streamId === undefined) {
                    killAllJs();

                } else {
                    // The stream might have already been reset from the JS side, with the
                    // notification still on its way to smoldot.
                    const channel = state.dataChannels.get(streamId);
                    if (channel === undefined)
                        return;
                    channel.channel.onopen = null;
                    channel.channel.onerror = null;
                    channel.channel.onclose = null;
                    channel.channel.onbufferedamountlow = null;
                    channel.channel.onmessage = null;
                    channel.channel.close();
                    state.dataChannels.delete(streamId);
                }
            },

            send: (data: Array<Uint8Array>, streamId: number): void => {
                // The stream might have already been reset from the JS side (entry removed),
                // or the channel might have left the `open` state before its `close` event
                // (which reports the reset) is dispatched; sending would then throw. Dropping
                // the data is fine, as the stream is reset or about to be.
                // See <https://github.com/paritytech/smoldot/issues/3322>.
                const channel = state.dataChannels.get(streamId);
                if (channel === undefined || channel.channel.readyState !== "open")
                    return;
                for (const buffer of data) {
                    channel.bufferedBytes += buffer.length;
                }
                channel.channel.send(new Blob(data));
            },

            closeSend: (): void => { throw new Error('Wrong connection type') },

            openOutSubstream: () => {
                // `openOutSubstream` can only be called after we have called `config.onOpen`,
                // therefore `pc` is guaranteed to be non-null.
                // The browser can however move the connection to `closed` before the
                // `connectionstatechange` event (which reports the reset) is dispatched;
                // `createDataChannel` would then throw. Doing nothing is fine, as the
                // connection is about to be reset anyway.
                // See <https://github.com/paritytech/smoldot/issues/3325>.
                if (state.pc!.signalingState === "closed")
                    return;
                // Note that the label passed to `createDataChannel` is required to be empty as
                // per the libp2p WebRTC specification.
                // TODO: adjusting the options based on the first substream is a bit hacky
                const opts = state.isFirstOutSubstream ? { negotiated: true, id: 0 } : {};
                state.isFirstOutSubstream = false;
                addChannel(state.pc!.createDataChannel("", opts), 'outbound')
            }
        };

    } else {
        // Should never happen, as we tweak the options to refuse connection types that
        // we don't support.
        throw new Error();
    }
}

/** Internal raw transport entry point, exported for the probe and unit tests. */
export function connectWebTransport(config: ConnectionConfig): Connection {
    if (config.address.ty !== 'webtransport')
        throw new Error('Wrong connection type');
    const address = config.address;
    const windowBytes = 64 * 1024;
    type Stream = {
        reader: ReadableStreamBYOBReader,
        writer: WritableStreamDefaultWriter<Uint8Array>,
        live: boolean,
        detached: boolean,
        readDone: boolean,
        writeClosing: boolean,
        credit: number,
        writes: Promise<void>,
        finishRetirement?: () => void,
    };
    let live = true;
    let sessionDetached = false;
    let transport: WebTransport | undefined;
    let incoming: ReadableStreamDefaultReader<WebTransportBidirectionalStream> | undefined;
    let nextStreamId = 0;
    let pendingOpens = 0;
    const retirements = new Set<Promise<void>>();
    const streams = new Map<number, Stream>();
    const message = (error: unknown) => error instanceof Error ? error.message : String(error);

    const disposeStream = (id: number, stream: Stream) => {
        stream.live = false;
        streams.delete(id);
        stream.finishRetirement?.();
        stream.finishRetirement = undefined;
        void stream.writer.abort().catch(() => {}).finally(() => stream.writer.releaseLock());
        if (!stream.readDone)
            void stream.reader.cancel().catch(() => {}).finally(() => stream.reader.releaseLock());
    };
    const stop = (reason?: string) => {
        if (!live) return;
        live = false;
        for (const [id, stream] of streams)
            disposeStream(id, stream);
        if (incoming)
            void incoming.cancel().catch(() => {}).finally(() => incoming?.releaseLock());
        try { transport?.close(); } catch (_) { /* The session may already be closed. */ }
        if (reason !== undefined && !sessionDetached)
            config.onConnectionReset(reason);
    };
    const failStream = (id: number, stream: Stream, error: unknown) => {
        if (!live || sessionDetached || !stream.live || stream.detached) return;
        // Hold the admission slot until the worker has acknowledged the reset.
        stream.live = false;
        void stream.writer.abort().catch(() => {});
        if (!stream.readDone) void stream.reader.cancel().catch(() => {});
        void Promise.resolve(config.onStreamReset(id, message(error))).finally(() => {
            disposeStream(id, stream);
        }).catch(error => stop(message(error)));
    };
    const discard = (stream: WebTransportBidirectionalStream) => {
        void stream.writable.abort().catch(() => {});
        void stream.readable.cancel().catch(() => {});
    };
    const opened = async (raw: WebTransportBidirectionalStream, direction: 'inbound' | 'outbound') => {
        if (!live || sessionDetached) { discard(raw); return; }
        if (streams.size + pendingOpens >= 64) {
            discard(raw); stop('WebTransport stream admission limit reached'); return;
        }
        if (nextStreamId > 0xffffffff) {
            discard(raw);
            stop('WebTransport stream identifier limit reached');
            return;
        }
        const id = nextStreamId++;
        const stream: Stream = {
            reader: raw.readable.getReader({ mode: 'byob' }), writer: raw.writable.getWriter(),
            live: true, detached: false, readDone: false, writeClosing: false,
            credit: windowBytes, writes: Promise.resolve(),
        };
        streams.set(id, stream);
        // STOP_SENDING can reject writer.closed even when no write is pending.
        void stream.writer.closed.catch(error => failStream(id, stream, error));
        await config.onStreamOpened(id, direction);
        if (!live || sessionDetached || !stream.live || stream.detached) return;
        config.onWritableBytes(windowBytes, id);
        void (async () => {
            while (live && stream.live) {
                // WebTransportReceiveStream is a byte stream. BYOB bounds the native
                // read as well as each worker message, regardless of peer write sizes.
                const result = await stream.reader.read(new Uint8Array(65536));
                if (!live || sessionDetached || !stream.live || stream.detached) return;
                if (result.value && result.value.byteLength !== 0)
                    await config.onMessage(result.value, id);
                if (!live || sessionDetached || !stream.live || stream.detached) return;
                if (result.done) {
                    stream.readDone = true;
                    stream.reader.releaseLock();
                    await config.onMessage(new Uint8Array(0), id);
                    return;
                }
            }
        })().catch(error => failStream(id, stream, error));
    };

    // Deferring also makes constructor errors obey the asynchronous reset contract.
    const ready = Promise.resolve().then(async () => {
        if (!live) return;
        config.onMultistreamHandshakeInfo({ handshake: 'webtransport' });
        if (!live) return;
        if (typeof WebTransport === 'undefined')
            throw new Error('WebTransport is not available in this environment');
        if (address.certHashes.length === 0 || address.certHashes.some(hash => hash.length !== 32))
            throw new Error('WebTransport requires SHA-256 certificate hashes');
        const host = address.ip.includes(':') ? '[' + address.ip + ']' : address.ip;
        transport = new WebTransport('https://' + host + ':' + address.port + '/', {
            serverCertificateHashes: address.certHashes.map(hash => ({ algorithm: 'sha-256', value: hash.slice().buffer })),
        });
        void transport.closed.then(() => stop('WebTransport session closed'), error => stop(message(error)));
        await transport.ready;
        if (!live) return;
        incoming = transport.incomingBidirectionalStreams.getReader();
        void (async () => {
            while (live) {
                const result = await incoming!.read();
                if (result.done) {
                    if (live) stop('WebTransport incoming streams closed');
                    return;
                }
                await opened(result.value, 'inbound');
            }
        })().catch(error => stop(message(error)));
    }).catch(error => stop(message(error)));

    return {
        reset: (streamId?: number, graceful = false) => {
            if (graceful && streamId === undefined) {
                sessionDetached = true;
                // Rust has dropped its final handle. Detached writes still own the session
                // until FIN completes, but must never call back into the removed Rust state.
                void Promise.all([...retirements]).then(() => stop());
                return;
            }
            if (graceful && streamId !== undefined) {
                const stream = streams.get(streamId);
                if (stream && stream.readDone && stream.writeClosing) {
                    stream.detached = true;
                    let complete!: () => void;
                    const finished = new Promise<void>(resolve => { complete = resolve; });
                    // A peer that never drains its receive window must not retain a
                    // detached session forever. Normal FIN waits for all queued writes.
                    const timeout = setTimeout(() => disposeStream(streamId, stream), 30000);
                    stream.finishRetirement = () => {
                        clearTimeout(timeout); retirements.delete(finished); complete();
                    };
                    void stream.writes.finally(() => {
                        disposeStream(streamId, stream);
                    }).catch(() => {});
                    retirements.add(finished);
                    return;
                }
            }
            if (streamId === undefined) { stop(); return; }
            const stream = streams.get(streamId);
            if (stream) disposeStream(streamId, stream);
        },
        openOutSubstream: () => {
            if (!live || sessionDetached) return;
            if (streams.size + pendingOpens >= 64) { stop('WebTransport stream admission limit reached'); return; }
            pendingOpens++;
            void ready.then(async () => {
                if (!live || !transport) return;
                const stream = await transport.createBidirectionalStream();
                pendingOpens--;
                await opened(stream, 'outbound');
            }).catch(error => stop(message(error)));
        },
        send: (data: Array<Uint8Array>, streamId?: number) => {
            const stream = streamId === undefined ? undefined : streams.get(streamId);
            if (!live || !stream || !stream.live || stream.writeClosing)
                return;
            const length = data.reduce((sum, bytes) => sum + bytes.length, 0);
            if (length > stream.credit) {
                failStream(streamId!, stream, new Error('WebTransport writable credit exceeded'));
                return;
            }
            if (length === 0) return;
            stream.credit -= length;
            // Own the bytes across async writes (the caller may reuse Wasm memory).
            const bytes = new Uint8Array(length);
            let offset = 0;
            for (const chunk of data) { bytes.set(chunk, offset); offset += chunk.length; }
            stream.writes = stream.writes.then(async () => {
                if (!live || !stream.live) return;
                await stream.writer.ready;
                if (!live || !stream.live) return;
                await stream.writer.write(bytes);
                if (!live || !stream.live || stream.writeClosing) return;
                stream.credit += length;
                config.onWritableBytes(length, streamId);
            }).catch(error => failStream(streamId!, stream, error));
        },
        closeSend: (streamId?: number) => {
            const stream = streamId === undefined ? undefined : streams.get(streamId);
            if (!live || !stream || !stream.live || stream.writeClosing) return;
            stream.writeClosing = true;
            stream.writes = stream.writes.then(async () => {
                if (live && stream.live) await stream.writer.close();
            }).catch(error => failStream(streamId!, stream, error));
        },
    };
}

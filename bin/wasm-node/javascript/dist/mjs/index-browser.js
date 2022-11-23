// Smoldot
// Copyright (C) 2019-2022  Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
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
import { start as innerStart } from './client.js';
import { ConnectionError } from './instance/instance.js';
import { classicDecode, multibaseBase64Decode } from './base64.js';
import { inflate } from 'pako';
export { AddChainError, AlreadyDestroyedError, CrashError, JsonRpcDisabledError, MalformedJsonRpcError, QueueFullError } from './client.js';
/**
 * Initializes a new client. This is a pre-requisite to connecting to a blockchain.
 *
 * Can never fail.
 *
 * @param options Configuration of the client. Defaults to `{}`.
 */
export function start(options) {
    options = options || {};
    return innerStart(options, {
        trustedBase64DecodeAndZlibInflate: (input) => {
            return Promise.resolve(inflate(classicDecode(input)));
        },
        registerShouldPeriodicallyYield: (callback) => {
            const wrappedCallback = () => callback(document.visibilityState === 'visible');
            document.addEventListener('visibilitychange', wrappedCallback);
            return [document.visibilityState === 'visible', () => { document.removeEventListener('visibilitychange', wrappedCallback); }];
        },
        performanceNow: () => {
            return performance.now();
        },
        getRandomValues: (buffer) => {
            const crypto = globalThis.crypto;
            if (!crypto)
                throw new Error('randomness not available');
            crypto.getRandomValues(buffer);
        },
        connect: (config) => {
            return connect(config, (options === null || options === void 0 ? void 0 : options.forbidWs) || false, (options === null || options === void 0 ? void 0 : options.forbidNonLocalWs) || false, (options === null || options === void 0 ? void 0 : options.forbidWss) || false, (options === null || options === void 0 ? void 0 : options.forbidWebRtc) || false);
        }
    });
}
/**
 * Tries to open a new connection using the given configuration.
 *
 * @see Connection
 * @throws {@link ConnectionError} If the multiaddress couldn't be parsed or contains an invalid protocol.
 */
function connect(config, forbidWs, forbidNonLocalWs, forbidWss, forbidWebRTC) {
    // Attempt to parse the multiaddress.
    // TODO: remove support for `/wss` in a long time (https://github.com/paritytech/smoldot/issues/1940)
    const wsParsed = config.address.match(/^\/(ip4|ip6|dns4|dns6|dns)\/(.*?)\/tcp\/(.*?)\/(ws|wss|tls\/ws)$/);
    const webRTCParsed = config.address.match(/^\/(ip4|ip6)\/(.*?)\/udp\/(.*?)\/webrtc\/certhash\/(.*?)$/);
    if (wsParsed != null) {
        let connection;
        const proto = (wsParsed[4] == 'ws') ? 'ws' : 'wss';
        if ((proto == 'ws' && forbidWs) ||
            (proto == 'ws' && wsParsed[2] != 'localhost' && wsParsed[2] != '127.0.0.1' && forbidNonLocalWs) ||
            (proto == 'wss' && forbidWss)) {
            throw new ConnectionError('Connection type not allowed');
        }
        const url = (wsParsed[1] == 'ip6') ?
            (proto + "://[" + wsParsed[2] + "]:" + wsParsed[3]) :
            (proto + "://" + wsParsed[2] + ":" + wsParsed[3]);
        connection = new WebSocket(url);
        connection.binaryType = 'arraybuffer';
        connection.onopen = () => {
            config.onOpen({ type: 'single-stream', handshake: 'multistream-select-noise-yamux' });
        };
        connection.onclose = (event) => {
            const message = "Error code " + event.code + (!!event.reason ? (": " + event.reason) : "");
            config.onConnectionReset(message);
        };
        connection.onmessage = (msg) => {
            config.onMessage(new Uint8Array(msg.data));
        };
        return {
            reset: () => {
                connection.onopen = null;
                connection.onclose = null;
                connection.onmessage = null;
                connection.onerror = null;
                connection.close();
            },
            send: (data) => {
                connection.send(data);
            },
            openOutSubstream: () => { throw new Error('Wrong connection type'); }
        };
    }
    else if (webRTCParsed != null) {
        const targetPort = webRTCParsed[3];
        if (forbidWebRTC || targetPort === '0') {
            throw new ConnectionError('Connection type not allowed');
        }
        const ipVersion = webRTCParsed[1] == 'ip4' ? '4' : '6';
        const targetIp = webRTCParsed[2];
        const remoteCertMultibase = webRTCParsed[4];
        // The payload of `/certhash` is the hash of the self-generated certificate that the
        // server presents.
        // This function throws an exception if the certhash isn't correct. For this reason, this call
        // is performed as part of the parsing of the multiaddr.
        const remoteCertMultihash = multibaseBase64Decode(remoteCertMultibase);
        const remoteCertSha256Hash = multihashToSha256(remoteCertMultihash);
        // TODO: detect localhost for Firefox? https://bugzilla.mozilla.org/show_bug.cgi?id=1659672
        // Note that `pc` can be the connection, but also null or undefined.
        // `undefined` means "certificate generation in progress", while `null` means "opening must
        // be cancelled".
        // While it would be better to use for example a string instead of `null`, using `null` lets
        // us use the `!` operator more easily and leads to more readable code.
        let pc = undefined;
        // Contains the data channels that are open and have been reported to smoldot.
        const dataChannels = new Map();
        // For various reasons explained below, we open a data channel in advance without reporting it
        // to smoldot. This data channel is stored in this variable. Once it is reported to smoldot,
        // it is inserted in `dataChannels`.
        let handshakeDataChannel;
        // Multihash-encoded DTLS certificate of the local node. Unknown as long as it hasn't been
        // generated.
        // TODO: could be merged with `pc` in one variable, and maybe even the other fields as well
        let localTlsCertificateMultihash;
        // Kills all the JavaScript objects (the connection and all its substreams), ensuring that no
        // callback will be called again. Doesn't report anything to smoldot, as this should be done
        // by the caller.
        const killAllJs = () => {
            // The `RTCPeerConnection` is created pretty quickly. It is however still possible for
            // smoldot to cancel the opening, in which case `pc` will still be undefined.
            if (!pc) {
                console.assert(dataChannels.size === 0 && !handshakeDataChannel, "substreams exist while pc is undef");
                pc = null;
                return;
            }
            pc.onconnectionstatechange = null;
            pc.onnegotiationneeded = null;
            pc.ondatachannel = null;
            for (const channel of Array.from(dataChannels.values())) {
                channel.onopen = null;
                channel.onerror = null;
                channel.onclose = null;
                channel.onmessage = null;
            }
            dataChannels.clear();
            if (handshakeDataChannel) {
                handshakeDataChannel.onopen = null;
                handshakeDataChannel.onerror = null;
                handshakeDataChannel.onclose = null;
                handshakeDataChannel.onmessage = null;
            }
            handshakeDataChannel = undefined;
            pc.close(); // Not necessarily necessary, but it doesn't hurt to do so.
        };
        // Function that configures a newly-opened channel and adds it to the map. Used for both
        // inbound and outbound substreams.
        const addChannel = (dataChannel, direction) => {
            const dataChannelId = dataChannel.id;
            dataChannel.binaryType = 'arraybuffer';
            let isOpen = false;
            dataChannel.onopen = () => {
                console.assert(!isOpen, "substream opened twice");
                isOpen = true;
                if (direction === 'first-outbound') {
                    console.assert(dataChannels.size === 0, "dataChannels not empty when opening");
                    console.assert(handshakeDataChannel === dataChannel, "handshake substream mismatch");
                    config.onOpen({
                        type: 'multi-stream',
                        handshake: 'webrtc',
                        // `addChannel` can never be called before the local certificate is generated, so this
                        // value is always defined.
                        localTlsCertificateMultihash: localTlsCertificateMultihash,
                        remoteTlsCertificateMultihash: remoteCertMultihash
                    });
                }
                else {
                    console.assert(direction !== 'outbound' || !handshakeDataChannel, "handshakeDataChannel still defined");
                    config.onStreamOpened(dataChannelId, direction);
                }
            };
            dataChannel.onerror = dataChannel.onclose = (_error) => {
                // A couple of different things could be happening here.
                if (handshakeDataChannel === dataChannel && !isOpen) {
                    // The handshake data channel that we have opened ahead of time failed to open. As this
                    // happens before we have reported the WebRTC connection as a whole as being open, we
                    // need to report that the connection has failed to open.
                    killAllJs();
                    // Note that the event doesn't give any additional reason for the failure.
                    config.onConnectionReset("handshake data channel failed to open");
                }
                else if (handshakeDataChannel === dataChannel) {
                    // The handshake data channel has been closed before we reported it to smoldot. This
                    // isn't really a problem. We just update the state and continue running. If smoldot
                    // requests a substream, another one will be opened. It could be a valid implementation
                    // to also just kill the entire connection, however doing so is a bit too intrusive and
                    // punches through abstraction layers.
                    handshakeDataChannel.onopen = null;
                    handshakeDataChannel.onerror = null;
                    handshakeDataChannel.onclose = null;
                    handshakeDataChannel.onmessage = null;
                    handshakeDataChannel = undefined;
                }
                else if (!isOpen) {
                    // Substream wasn't opened yet and thus has failed to open. The API has no mechanism to
                    // report substream openings failures. We could try opening it again, but given that
                    // it's unlikely to succeed, we simply opt to kill the entire connection.
                    killAllJs();
                    // Note that the event doesn't give any additional reason for the failure.
                    config.onConnectionReset("data channel failed to open");
                }
                else {
                    // Substream was open and is now closed. Normal situation.
                    config.onStreamReset(dataChannelId);
                }
            };
            dataChannel.onmessage = (m) => {
                // The `data` field is an `ArrayBuffer`.
                config.onMessage(new Uint8Array(m.data), dataChannelId);
            };
            if (direction !== 'first-outbound')
                dataChannels.set(dataChannelId, dataChannel);
            else
                handshakeDataChannel = dataChannel;
        };
        // It is possible for the browser to use multiple different certificates.
        // In order for our local certificate to be deterministic, we need to generate it manually and
        // set it explicitly as part of the configuration.
        // According to <https://w3c.github.io/webrtc-pc/#dom-rtcpeerconnection-generatecertificate>,
        // browsers are guaranteed to support `{ name: "ECDSA", namedCurve: "P-256" }`.
        RTCPeerConnection.generateCertificate({ name: "ECDSA", namedCurve: "P-256", hash: "SHA-256" }).then((localCertificate) => __awaiter(this, void 0, void 0, function* () {
            if (pc === null)
                return;
            // Create a new WebRTC connection.
            pc = new RTCPeerConnection({ certificates: [localCertificate] });
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
            let localTlsCertificateHex;
            if (localCertificate.getFingerprints) {
                for (const { algorithm, value } of localCertificate.getFingerprints()) {
                    if (algorithm === 'sha-256') {
                        localTlsCertificateHex = value;
                        break;
                    }
                }
            }
            else {
                const localSdpOffer = yield pc.createOffer();
                // Note that this regex is not strict. The browser isn't a malicious actor, and the
                // objective of this regex is not to detect invalid input.
                const localSdpOfferFingerprintMatch = localSdpOffer.sdp.match(/a(\s*)=(\s*)fingerprint:(\s*)(sha|SHA)-256(\s*)(([a-fA-F0-9]{2}(:)*){32})/);
                if (localSdpOfferFingerprintMatch) {
                    localTlsCertificateHex = localSdpOfferFingerprintMatch[6];
                }
            }
            if (localTlsCertificateHex === undefined) {
                // Because we've already returned from the `connect` function at this point, we pretend
                // that the connection has failed to open.
                config.onConnectionReset('Failed to obtain the browser certificate fingerprint');
                return;
            }
            localTlsCertificateMultihash = new Uint8Array(34);
            localTlsCertificateMultihash.set([0x12, 32], 0);
            localTlsCertificateMultihash.set(localTlsCertificateHex.split(':').map((s) => parseInt(s, 16)), 2);
            // `onconnectionstatechange` is used to detect when the connection has closed or has failed
            // to open.
            // Note that smoldot will think that the connection is open even when it is still opening.
            // Therefore we don't care about events concerning the fact that the connection is now fully
            // open.
            pc.onconnectionstatechange = (_event) => {
                if (pc.connectionState == "closed" || pc.connectionState == "disconnected" || pc.connectionState == "failed") {
                    killAllJs();
                    config.onConnectionReset("WebRTC state transitioned to " + pc.connectionState);
                }
            };
            pc.onnegotiationneeded = (_event) => __awaiter(this, void 0, void 0, function* () {
                var _a;
                // Create a new offer and set it as local description.
                let sdpOffer = (yield pc.createOffer()).sdp;
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
                const browserGeneratedPwd = (_a = sdpOffer.match(/^a=ice-pwd:(.+)$/m)) === null || _a === void 0 ? void 0 : _a.at(1);
                if (browserGeneratedPwd === undefined) {
                    console.error("Failed to set ufrag to pwd. WebRTC connections will likely fail. Please report this issue.");
                }
                const ufragPwd = "libp2p+webrtc+v1/" + browserGeneratedPwd;
                sdpOffer = sdpOffer.replace(/^a=ice-ufrag.*$/m, 'a=ice-ufrag:' + ufragPwd);
                sdpOffer = sdpOffer.replace(/^a=ice-pwd.*$/m, 'a=ice-pwd:' + ufragPwd);
                yield pc.setLocalDescription({ type: 'offer', sdp: sdpOffer });
                // Transform certificate hash into fingerprint (upper-hex; each byte separated by ":").
                const fingerprint = Array.from(remoteCertSha256Hash).map((n) => ("0" + n.toString(16)).slice(-2).toUpperCase()).join(':');
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
                    "m=application " + targetPort + " " + "UDP/DTLS/SCTP webrtc-datachannel" + "\n" +
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
                    "a=max-message-size:16384" + "\n" + // TODO: should this be part of the spec?
                    // A transport address for a candidate that can be used for connectivity
                    // checks (RFC8839).
                    "a=candidate:1 1 UDP 1 " + targetIp + " " + targetPort + " typ host" + "\n";
                yield pc.setRemoteDescription({ type: "answer", sdp: remoteSdp });
            });
            pc.ondatachannel = ({ channel }) => {
                // TODO: is the substream maybe already open? according to the Internet it seems that no but it's unclear
                addChannel(channel, 'inbound');
            };
            // Creating a `RTCPeerConnection` doesn't actually do anything before `createDataChannel` is
            // called. Smoldot's API, however, requires you to treat entire connections as open or
            // closed. We know, according to the libp2p WebRTC specification, that every connection
            // always starts with a substream where a handshake is performed. After we've reported that
            // the connection is open, smoldot will open a substream in order to perform the handshake.
            // Instead of following this API, we open this substream in advance, and will notify smoldot
            // that the connection is open when the substream is open.
            // Note that the label passed to `createDataChannel` is required to be empty as per the
            // libp2p WebRTC specification.
            addChannel(pc.createDataChannel("", { id: 0, negotiated: true }), 'first-outbound');
        }));
        return {
            reset: (streamId) => {
                // If `streamId` is undefined, then the whole connection must be destroyed.
                if (streamId === undefined) {
                    killAllJs();
                }
                else {
                    const channel = dataChannels.get(streamId);
                    channel.onopen = null;
                    channel.onerror = null;
                    channel.onclose = null;
                    channel.onmessage = null;
                    channel.close();
                    dataChannels.delete(streamId);
                }
            },
            send: (data, streamId) => {
                dataChannels.get(streamId).send(data);
            },
            openOutSubstream: () => {
                // `openOutSubstream` can only be called after we have called `config.onOpen`, therefore
                // `pc` is guaranteed to be non-null.
                // As explained above, we open a data channel ahead of time. If this data channel is still
                // there, we report it.
                if (handshakeDataChannel) {
                    // Do this asynchronously because calling callbacks within callbacks is error-prone.
                    (() => __awaiter(this, void 0, void 0, function* () {
                        // We need to check again if `handshakeDataChannel` is still defined, as the
                        // connection might have been closed.
                        if (handshakeDataChannel) {
                            config.onStreamOpened(handshakeDataChannel.id, 'outbound');
                            dataChannels.set(handshakeDataChannel.id, handshakeDataChannel);
                            handshakeDataChannel = undefined;
                        }
                    }))();
                }
                else {
                    // Note that the label passed to `createDataChannel` is required to be empty as per the
                    // libp2p WebRTC specification.
                    addChannel(pc.createDataChannel(""), 'outbound');
                }
            }
        };
    }
    else {
        throw new ConnectionError('Unrecognized multiaddr format');
    }
}
/// Parses a multihash-multibase-encoded string into a SHA256 hash.
///
/// Throws an exception if the multihash algorithm isn't SHA256.
const multihashToSha256 = (certMultihash) => {
    if (certMultihash.length != 34 || certMultihash[0] != 0x12 || certMultihash[1] != 32) {
        throw new Error('Certificate multihash is not SHA-256');
    }
    return new Uint8Array(certMultihash.slice(2));
};

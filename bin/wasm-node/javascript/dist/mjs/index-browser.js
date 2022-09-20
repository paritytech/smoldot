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
export { AddChainError, AlreadyDestroyedError, CrashError, JsonRpcDisabledError } from './client.js';
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
            return connect(config, (options === null || options === void 0 ? void 0 : options.forbidWs) || false, (options === null || options === void 0 ? void 0 : options.forbidNonLocalWs) || false, (options === null || options === void 0 ? void 0 : options.forbidWss) || false, !((options === null || options === void 0 ? void 0 : options.enableExperimentalWebRTC) || false));
        }
    });
}
/**
 * Tries to open a new connection using the given configuration.
 *
 * @see Connection
 * @throws ConnectionError If the multiaddress couldn't be parsed or contains an invalid protocol.
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
            config.onConnectionClose(message);
        };
        connection.onmessage = (msg) => {
            config.onMessage(new Uint8Array(msg.data));
        };
        return {
            close: () => {
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
        let pc = null;
        const dataChannels = new Map();
        // TODO: this system is a complete hack
        let isFirstSubstream = true;
        // The opening of the connection is asynchronous. If smoldot calls `close` in the meanwhile,
        // this variable is set to `true`, and we interrupt the opening.
        let cancelOpening = false;
        // Function that configures a newly-opened channel and adds it to the map. Used for both
        // inbound and outbound substreams.
        const addChannel = (dataChannel, direction) => {
            const dataChannelId = dataChannel.id;
            dataChannel.onopen = () => {
                config.onStreamOpened(dataChannelId, direction);
            };
            dataChannel.onerror = (_error) => {
                config.onStreamClose(dataChannelId);
            };
            dataChannel.onclose = () => {
                config.onStreamClose(dataChannelId);
            };
            dataChannel.onmessage = (m) => {
                // The `data` field is an `ArrayBuffer`.
                config.onMessage(new Uint8Array(m.data), dataChannelId);
            };
            dataChannels.set(dataChannelId, dataChannel);
        };
        // It is possible for the browser to use multiple different certificates.
        // In order for our local certificate to be deterministic, we need to generate it manually and
        // set it explicitly as part of the configuration.
        // According to <https://w3c.github.io/webrtc-pc/#dom-rtcpeerconnection-generatecertificate>,
        // browsers are guaranteed to support `{ name: "ECDSA", namedCurve: "P-256" }`.
        RTCPeerConnection.generateCertificate({ name: "ECDSA", namedCurve: "P-256", hash: "SHA-256" }).then((localCertificate) => {
            if (cancelOpening)
                return;
            // We need to build the multihash corresponding to the local certificate.
            let localTlsCertificateMultihash = null;
            for (const { algorithm, value } of localCertificate.getFingerprints()) {
                if (algorithm === 'sha-256') {
                    localTlsCertificateMultihash = new Uint8Array(34);
                    localTlsCertificateMultihash.set([0x12, 32], 0);
                    localTlsCertificateMultihash.set(value.split(':').map((s) => parseInt(s, 16)), 2);
                    break;
                }
            }
            if (localTlsCertificateMultihash === null) {
                // Because we've already returned from the `connect` function at this point, we pretend
                // that the connection has failed to open.
                config.onConnectionClose('Failed to obtain the browser certificate fingerprint');
                return;
            }
            // Create a new WebRTC connection.
            pc = new RTCPeerConnection({ certificates: [localCertificate] });
            // `onconnectionstatechange` is used to detect when the connection has closed or has failed
            // to open.
            // Note that smoldot will think that the connection is open even when it is still opening.
            // Therefore we don't care about events concerning the fact that the connection is now fully
            // open.
            pc.onconnectionstatechange = (_event) => {
                if (pc.connectionState == "closed" || pc.connectionState == "disconnected" || pc.connectionState == "failed") {
                    config.onConnectionClose("WebRTC state transitioned to " + pc.connectionState);
                    pc.onconnectionstatechange = null;
                    pc.onnegotiationneeded = null;
                    pc.ondatachannel = null;
                    for (const channel of Array.from(dataChannels.values())) {
                        channel.onopen = null;
                        channel.onerror = null;
                        channel.onclose = null;
                        channel.onmessage = null;
                    }
                    pc.close(); // Not necessarily necessary, but it doesn't hurt to do so.
                    dataChannels.clear();
                }
            };
            pc.onnegotiationneeded = (_event) => __awaiter(this, void 0, void 0, function* () {
                // Create a new offer and set it as local description.
                let sdpOffer = (yield pc.createOffer()).sdp;
                // According to the libp2p WebRTC spec, the ufrag and pwd are the same
                // randomly-generated string. We modify the local description to ensure that.
                const pwd = sdpOffer.match(/^a=ice-pwd:(.+)$/m);
                if (pwd != null) {
                    sdpOffer = sdpOffer.replace(/^a=ice-ufrag.*$/m, 'a=ice-ufrag:' + pwd[1]);
                }
                else {
                    console.error("Failed to set ufrag to pwd. WebRTC connections will likely fail. Please report this issues.");
                }
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
                    // "Internet". (RFC8866)
                    "o=- 0 0 IN IP" + ipVersion + " " + targetIp + "\n" +
                    // Name for the session. We are allowed to pass a dummy `-`. (RFC8866)
                    "s=-" + "\n" +
                    // Start and end of the validity of the session. `0 0` means that the session never
                    // expires. (RFC8866)
                    "t=0 0" + "\n" +
                    // A lite implementation is only appropriate for devices that will
                    // *always* be connected to the public Internet and have a public
                    // IP address at which it can receive packets from any
                    // correspondent.  ICE will not function when a lite implementation
                    // is placed behind a NAT (RFC8445).
                    "a=ice-lite" + "\n" +
                    // A `m=` line describes a request to establish a certain protocol.
                    // The protocol in this line (i.e. `TCP/DTLS/SCTP` or `UDP/DTLS/SCTP`) must always be
                    // the same as the one in the offer. We know that this is true because we tweak the
                    // offer to match the protocol.
                    // The `<fmt>` component must always be `pc-datachannel` for WebRTC.
                    // The rest of the SDP payload adds attributes to this specific media stream.
                    // RFCs: 8839, 8866, 8841
                    "m=application " + targetPort + " " + "UDP/DTLS/SCTP webrtc-datachannel" + "\n" +
                    // Indicates the IP address of the remote.
                    // Note that "IN" means "Internet".
                    "c=IN IP" + ipVersion + " " + targetIp + "\n" +
                    // Media ID - uniquely identifies this media stream (RFC9143).
                    "a=mid:0" + "\n" +
                    // Indicates that we are complying with RFC8839 (as oppposed to the legacy RFC5245).
                    "a=ice-options:ice2" + "\n" +
                    // ICE username and password, which are used for establishing and
                    // maintaining the ICE connection. (RFC8839)
                    // MUST match ones used by the answerer (server).
                    "a=ice-ufrag:" + remoteCertMultibase + "\n" +
                    "a=ice-pwd:" + remoteCertMultibase + "\n" +
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
                    "a=max-message-size:100000" + "\n" +
                    // A transport address for a candidate that can be used for connectivity checks (RFC8839).
                    "a=candidate:1 1 UDP 1 " + targetIp + " " + targetPort + " typ host" + "\n";
                yield pc.setRemoteDescription({ type: "answer", sdp: remoteSdp });
            });
            pc.ondatachannel = ({ channel }) => {
                addChannel(channel, 'inbound');
            };
            // Creating a `RTCPeerConnection` doesn't actually do anything before a channel is created.
            // The connection is therefore immediately reported as opened to smoldot so that it starts
            // opening substreams.
            // One concern might be that smoldot will think that the remote is reachable at this address
            // (because we report the connection as being open) even when it might not be the case.
            // However, WebRTC has a handshake to perform, and smoldot will only consider a connection
            // as "actually open" once the handshake has finished.
            config.onOpen({
                type: 'multi-stream',
                handshake: 'webrtc',
                localTlsCertificateMultihash,
                remoteTlsCertificateMultihash: remoteCertMultihash
            });
        });
        return {
            close: (streamId) => {
                // If `streamId` is undefined, then the whole connection must be destroyed.
                if (streamId === undefined) {
                    // The `RTCPeerConnection` is created at the same time as we report the connection as
                    // being open. It is however possible for smoldot to cancel the opening, in which case
                    // `pc` will still be undefined.
                    if (!pc) {
                        cancelOpening = true;
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
                    pc.close();
                    dataChannels.clear();
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
                if (isFirstSubstream) {
                    isFirstSubstream = false;
                    addChannel(pc.createDataChannel("data", { id: 1, negotiated: true }), 'outbound');
                }
                else {
                    addChannel(pc.createDataChannel("data"), 'outbound');
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

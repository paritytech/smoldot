// Smoldot
// Copyright (C) 2019-2026  Parity Technologies (UK) Ltd.
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

// WebRTC-direct connections for NodeJS, on top of the native API of `node-datachannel`
// (libdatachannel). NodeJS has no WebRTC API of its own; the caller passes the module through
// `ClientOptions.nodeWebRtc`.
//
// This is the same protocol as the browser implementation in `no-auto-bytecode-browser.ts`, with
// three differences imposed by libdatachannel:
//
// - libdatachannel creates its own DTLS certificate, so the local certificate fingerprint is read
//   from the local SDP offer. The offer only exists once a data channel does, so the negotiated
//   handshake channel (id 0) is created up front, before smoldot asks for it.
// - The ICE ufrag and pwd are passed to `setLocalDescription` instead of being munged into the SDP:
//   libdatachannel ignores a munged SDP.
// - The remote answer is only set when smoldot opens its first outbound substream. Until then no
//   ICE check can be sent, so nothing can arrive on the handshake channel before smoldot knows
//   about it.

import type { Connection, ConnectionConfig } from './client.js';

/**
 * Where the remote answer says the remote is.
 */
type Target = { targetIp: string, ipVersion: 4 | 6 };

/**
 * The subset of the `node-datachannel` module this file uses.
 */
export interface NodeWebRtcImplementation {
    PeerConnection: new (peerName: string, config: NodeWebRtcConfig) => NodePeerConnection;
}

interface NodeWebRtcConfig {
    iceServers: string[];
    disableAutoNegotiation?: boolean;
    maxMessageSize?: number;
}

interface NodePeerConnection {
    close(): void;
    setLocalDescription(type?: 'offer' | 'answer', init?: { iceUfrag?: string, icePwd?: string }): void;
    setRemoteDescription(sdp: string, type: 'offer' | 'answer'): void;
    localDescription(): { type: string, sdp: string } | null;
    createDataChannel(label: string, config?: { negotiated?: boolean, id?: number }): NodeDataChannel;
    onStateChange(cb: (state: string) => void): void;
    onDataChannel(cb: (dc: NodeDataChannel) => void): void;
}

interface NodeDataChannel {
    close(): void;
    sendMessageBinary(buffer: Uint8Array): boolean;
    isOpen(): boolean;
    onOpen(cb: () => void): void;
    onClosed(cb: () => void): void;
    onError(cb: (err: string) => void): void;
    onBufferedAmountLow(cb: () => void): void;
    onMessage(cb: (msg: string | Uint8Array | ArrayBuffer) => void): void;
}

// The libp2p WebRTC specification requires ufrag and pwd to be the same random string with this
// prefix. ICE limits them to 22-256 characters of `[a-zA-Z0-9+/]`, and libdatachannel aborts the
// process on anything else, so the random part only uses alphanumerics.
const UFRAG_PREFIX = 'libp2p+webrtc+v1/';
const UFRAG_ALPHABET = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
// Part of the libp2p WebRTC specification, and what the remote answer below announces.
const MAX_MESSAGE_SIZE = 16384;
// libdatachannel negotiates 1024 streams in each direction.
const MAX_STREAM_ID = 1024;
// How long an outbound stream identifier stays unused after its channel closed. The reset of a
// stream takes a round trip in each direction; a few seconds is plenty.
const STREAM_ID_QUARANTINE_MS = 10_000;

/**
 * Opens a WebRTC-direct connection to `config.address`, which must be of type `webrtc`.
 *
 * Errors are reported through `config.onConnectionReset`, never thrown.
 */
export function connectWebRtcNodeDatachannel(
    config: ConnectionConfig,
    implementation: NodeWebRtcImplementation,
    fillRandom: (buffer: Uint8Array) => void,
    resolveHostname: (hostname: string, family: 4 | 6 | undefined) => Promise<string>,
): Connection {
    const address = config.address;
    if (address.ty !== 'webrtc')
        throw new Error('Wrong connection type');
    const { targetPort, remoteTlsCertificateSha256 } = address;

    // The remote answer below needs the literal IP address of the remote. A multiaddress with a
    // domain name is resolved from the start, and the answer waits for the result if smoldot asks
    // for it first.
    const target: Target | Promise<Target> = 'targetIp' in address
        ? { targetIp: address.targetIp, ipVersion: address.ipVersion }
        : resolveHostname(address.hostname, address.family)
            .then((targetIp): Target => ({ targetIp, ipVersion: targetIp.includes(':') ? 6 : 4 }));
    if (target instanceof Promise)
        target.catch(() => { });  // Reported once the answer needs it.
    const targetName = 'targetIp' in address ? address.targetIp : address.hostname;

    // SMOLDOT_WEBRTC_DEBUG=1 prints, for each connection, its state changes, how many substreams it
    // opened, and why it ended: smoldot's own logs have no reason for a connection reset.
    const debug = (globalThis as any).process?.env?.SMOLDOT_WEBRTC_DEBUG === '1';
    const started = Date.now();
    let opened = 0;
    const trace = (what: string) => {
        if (debug)
            console.warn(`${new Date().toISOString()} [webrtc ${targetName}:${targetPort}] ${what} (after ${((Date.now() - started) / 1000).toFixed(1)} s, ${opened} outbound substreams)`);
    };
    {
        const onConnectionReset = config.onConnectionReset;
        config = { ...config, onConnectionReset: (message: string) => { trace(`reset: ${message}`); onConnectionReset(message); } };
    }

    const randomBytes = new Uint8Array(32);
    fillRandom(randomBytes);
    const ufragPwd = UFRAG_PREFIX + Array.from(randomBytes, (b) => UFRAG_ALPHABET[b % UFRAG_ALPHABET.length]).join('');

    // SCTP stream identifiers of outbound channels. libdatachannel's own allocator picks the lowest
    // free identifier, so the first substream opened after the Noise handshake gets 0, the
    // identifier of the handshake channel that is being reset at that very moment. The remote
    // then resets the new channel as well. So identifiers are allocated here instead: even ones,
    // as the DTLS client must use (RFC 8832), never one that is in use or was released less than
    // `STREAM_ID_QUARANTINE_MS` ago. Stream 0 is the handshake channel's.
    const usedStreamIds = new Set<number>([0]);
    const releasedStreamIds = new Map<number, number>();  // identifier -> time of release
    const allocateStreamId = (): number | undefined => {
        const now = Date.now();
        for (let id = 2; id < MAX_STREAM_ID; id += 2) {
            if (usedStreamIds.has(id))
                continue;
            const releasedAt = releasedStreamIds.get(id);
            if (releasedAt !== undefined && now - releasedAt < STREAM_ID_QUARANTINE_MS)
                continue;
            releasedStreamIds.delete(id);
            usedStreamIds.add(id);
            return id;
        }
        return undefined;
    };
    const releaseStreamId = (id: number | undefined) => {
        if (id === undefined || !usedStreamIds.delete(id))
            return;
        releasedStreamIds.set(id, Date.now());
    };

    // Every substream smoldot knows about, by smoldot's stream id. `sctpStreamId` is only set for
    // outbound channels, whose identifier is allocated above.
    type Channel = { channel: NodeDataChannel, bufferedBytes: number, open: boolean, closed: boolean, sctpStreamId?: number };
    const state: {
        pc: NodePeerConnection | null,
        // The negotiated channel 0, created up front, until smoldot opens its first substream.
        handshakeChannel: NodeDataChannel | null,
        dataChannels: Map<number, Channel>,
        nextStreamId: number,
        // Set once the connection is torn down, from either side. No callback is called after.
        killed: boolean,
    } = { pc: null, handshakeChannel: null, dataChannels: new Map(), nextStreamId: 0, killed: false };

    // Closes everything without reporting anything to smoldot; the caller reports if needed.
    // node-datachannel has no way to unregister a callback, so each one checks `killed` or its
    // channel's `closed` flag instead.
    const killAllJs = () => {
        if (state.killed)
            return;
        state.killed = true;
        for (const entry of Array.from(state.dataChannels.values())) {
            entry.closed = true;
            try { entry.channel.close() } catch (_) { }
        }
        state.dataChannels.clear();
        if (state.handshakeChannel) {
            try { state.handshakeChannel.close() } catch (_) { }
            state.handshakeChannel = null;
        }
        if (state.pc) {
            try { state.pc.close() } catch (_) { }
        }
    };

    // Reports a failure after `connect` has returned, as the API requires.
    const failAsync = (message: string) => {
        setTimeout(() => {
            if (state.killed)
                return;
            killAllJs();
            config.onConnectionReset(message);
        }, 0);
    };

    // Registers a channel with smoldot. For an outbound channel, `onStreamOpened` is called when it
    // opens; an inbound channel announced by `onDataChannel` is usually already open.
    const addChannel = (channel: NodeDataChannel, direction: 'inbound' | 'outbound', sctpStreamId?: number) => {
        const streamId = state.nextStreamId;
        state.nextStreamId += 1;
        const entry: Channel = { channel, bufferedBytes: 0, open: false, closed: false, sctpStreamId };
        state.dataChannels.set(streamId, entry);

        const reportOpen = () => {
            // Guard against the open event being seen twice: reporting the same stream id twice
            // makes smoldot panic.
            if (state.killed || entry.closed || entry.open)
                return;
            entry.open = true;
            config.onStreamOpened(streamId, direction);
            config.onWritableBytes(65536, streamId);
        };

        const reportClosed = (message: string) => {
            if (state.killed || entry.closed)
                return;
            entry.closed = true;
            state.dataChannels.delete(streamId);
            releaseStreamId(entry.sctpStreamId);
            if (!entry.open) {
                // The API has no way to report a substream that failed to open. As in the
                // browser implementation, the whole connection is killed instead.
                killAllJs();
                config.onConnectionReset('data channel failed to open: ' + message);
            } else {
                config.onStreamReset(streamId, message);
            }
        };

        // The registration order matters. node-datachannel delivers each kind of event through
        // its own thread-safe function, and libuv services pending ones in creation order. Its
        // close handler also aborts the message queue, so a message that arrives just before the
        // channel closes is lost unless `onMessage` is registered before `onClosed`. That happens
        // on the handshake channel: the remote sends the last Noise message and closes the
        // channel straight away. `onOpen` comes first, so that a channel's first message is not
        // delivered before the channel is reported open.
        channel.onOpen(reportOpen);
        channel.onMessage((message) => {
            if (state.killed || entry.closed)
                return;
            if (typeof message === 'string')
                return;  // The protocol only uses binary messages.
            // A channel that delivers a message is open, whichever callback ran first.
            if (!entry.open)
                reportOpen();
            // Copied, because smoldot may keep the array while libdatachannel reuses its memory.
            const bytes = message instanceof ArrayBuffer ? new Uint8Array(message.slice(0)) : Uint8Array.from(message);
            config.onMessage(bytes, streamId);
        });
        channel.onBufferedAmountLow(() => {
            if (state.killed || entry.closed || entry.bufferedBytes === 0)
                return;
            const value = entry.bufferedBytes;
            entry.bufferedBytes = 0;
            config.onWritableBytes(value, streamId);
        });
        channel.onError((err) => reportClosed('RTCDataChannel error: ' + err));
        channel.onClosed(() => reportClosed('RTCDataChannel closed'));

        // An inbound channel is normally already open when it is announced, and its `onOpen`
        // never fires. Reported asynchronously so that smoldot sees the stream after
        // `openOutSubstream` or the `onDataChannel` callback has returned.
        if (channel.isOpen())
            setTimeout(reportOpen, 0);
    };

    // The answer of the remote, built from its multiaddress, exactly as the browser implementation
    // does. See there for the meaning of each line.
    const remoteSdp = ({ targetIp, ipVersion }: Target) => {
        const fingerprint = Array.from(remoteTlsCertificateSha256).map((n) => ('0' + n.toString(16)).slice(-2).toUpperCase()).join(':');
        return 'v=0' + '\n' +
            'o=- 0 0 IN IP' + ipVersion + ' ' + targetIp + '\n' +
            's=-' + '\n' +
            't=0 0' + '\n' +
            'a=ice-lite' + '\n' +
            'm=application ' + String(targetPort) + ' ' + 'UDP/DTLS/SCTP webrtc-datachannel' + '\n' +
            'c=IN IP' + ipVersion + ' ' + targetIp + '\n' +
            'a=mid:0' + '\n' +
            'a=ice-options:ice2' + '\n' +
            'a=ice-ufrag:' + ufragPwd + '\n' +
            'a=ice-pwd:' + ufragPwd + '\n' +
            'a=fingerprint:sha-256 ' + fingerprint + '\n' +
            'a=setup:passive' + '\n' +
            'a=sctp-port:5000' + '\n' +
            'a=max-message-size:' + String(MAX_MESSAGE_SIZE) + '\n' +
            'a=candidate:1 1 UDP 1 ' + targetIp + ' ' + String(targetPort) + ' typ host' + '\n' +
            'a=end-of-candidates' + '\n';
    };

    try {
        // `maxMessageSize` is left at libdatachannel's default (256 KiB, what browsers accept as
        // well). It is the largest message this side accepts: setting it to the protocol's 16 KiB
        // makes libdatachannel reject the remote's full-size frames, whose framing overhead puts
        // them just above 16 KiB, and every large response (a runtime download) is reset midway.
        // The 16 KiB limit applies to what this side sends, through the remote answer below.
        state.pc = new implementation.PeerConnection('smoldot', {
            iceServers: [],
            disableAutoNegotiation: true,
        });

        state.pc.onStateChange((connectionState) => {
            trace(`state ${connectionState}`);
            if (state.killed)
                return;
            if (connectionState === 'closed' || connectionState === 'disconnected' || connectionState === 'failed') {
                killAllJs();
                config.onConnectionReset('WebRTC state transitioned to ' + connectionState);
            }
        });

        state.pc.onDataChannel((channel) => {
            if (state.killed) {
                try { channel.close() } catch (_) { }
                return;
            }
            addChannel(channel, 'inbound');
        });

        // The offer needs a data channel to describe; this is the one the Noise handshake uses.
        state.handshakeChannel = state.pc.createDataChannel('', { negotiated: true, id: 0 });
        state.pc.setLocalDescription('offer', { iceUfrag: ufragPwd, icePwd: ufragPwd });

        const localSdp = state.pc.localDescription()?.sdp;
        const localFingerprint = localSdp?.match(/^a=fingerprint:sha-256 ((?:[0-9a-fA-F]{2}:){31}[0-9a-fA-F]{2})\s*$/m)?.[1];
        if (localFingerprint === undefined) {
            failAsync('Failed to obtain the local certificate fingerprint from the SDP offer');
        } else {
            const localTlsCertificateSha256 = new Uint8Array(localFingerprint.split(':').map((s) => parseInt(s, 16)));
            // The API wants this "as soon as possible", but only once `connect` has returned.
            setTimeout(() => {
                if (state.killed)
                    return;
                config.onMultistreamHandshakeInfo({ handshake: 'webrtc', localTlsCertificateSha256 });
            }, 0);
        }
    } catch (error) {
        failAsync('Failed to create the WebRTC connection: ' + (error instanceof Error ? error.message : String(error)));
    }

    return {
        reset: (streamId?: number): void => {
            if (streamId === undefined) {
                killAllJs();
                return;
            }
            // The stream might already have been reset from the JS side, with the notification
            // still on its way to smoldot.
            const entry = state.dataChannels.get(streamId);
            if (entry === undefined)
                return;
            entry.closed = true;
            state.dataChannels.delete(streamId);
            releaseStreamId(entry.sctpStreamId);
            try { entry.channel.close() } catch (_) { }
        },

        send: (data: Array<Uint8Array>, streamId?: number): void => {
            const entry = streamId === undefined ? undefined : state.dataChannels.get(streamId);
            if (entry === undefined || entry.closed || !entry.channel.isOpen())
                return;  // Reset, or about to be: dropping the data is fine, as in the browser.
            let length = 0;
            for (const buffer of data)
                length += buffer.length;
            const message = data.length === 1 ? data[0]! : concat(data, length);
            // `true` means sent straight away: the bytes are writable again immediately, and no
            // `onBufferedAmountLow` would ever report them. `false` means buffered. It throws if
            // the remote closed the channel since `isOpen()` above, which libdatachannel learns on
            // its own thread; `onClosed` reports that closure, so the data is dropped here.
            let sentNow: boolean;
            try {
                sentNow = entry.channel.sendMessageBinary(message);
            } catch (_) {
                return;
            }
            if (sentNow) {
                setImmediate(() => {
                    if (state.killed || entry.closed)
                        return;
                    config.onWritableBytes(length, streamId);
                });
            } else {
                entry.bufferedBytes += length;
            }
        },

        closeSend: (): void => { throw new Error('Wrong connection type') },

        openOutSubstream: (): void => {
            if (state.killed || state.pc === null)
                return;  // The connection is about to be reported as reset anyway.
            const handshakeChannel = state.handshakeChannel;
            if (handshakeChannel !== null) {
                // The first substream is the negotiated channel 0. Only now can the connection
                // start: see the comment at the top of the file.
                state.handshakeChannel = null;
                addChannel(handshakeChannel, 'outbound', 0);
                const pc = state.pc;
                const setAnswer = (resolved: Target) => {
                    try {
                        pc.setRemoteDescription(remoteSdp(resolved), 'answer');
                    } catch (error) {
                        failAsync('Failed to set the remote description: ' + (error instanceof Error ? error.message : String(error)));
                    }
                };
                if (!(target instanceof Promise)) {
                    setAnswer(target);
                    return;
                }
                target.then((resolved) => {
                    if (!state.killed)
                        setAnswer(resolved);
                }, (error) => {
                    if (state.killed)
                        return;
                    killAllJs();
                    config.onConnectionReset('DNS resolution failed: ' + (error instanceof Error ? error.message : String(error)));
                });
                return;
            }
            const sctpStreamId = allocateStreamId();
            opened += 1;
            if (sctpStreamId === undefined) {
                // The API has no way to refuse a substream; this connection is out of streams.
                failAsync('No SCTP stream identifier left');
                return;
            }
            // The label must be empty, as per the libp2p WebRTC specification.
            addChannel(state.pc.createDataChannel('', { id: sctpStreamId }), 'outbound', sctpStreamId);
        },
    };
}

function concat(buffers: Array<Uint8Array>, length: number): Uint8Array {
    const out = new Uint8Array(length);
    let offset = 0;
    for (const buffer of buffers) {
        out.set(buffer, offset);
        offset += buffer.length;
    }
    return out;
}

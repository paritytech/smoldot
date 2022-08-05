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

import { Client, ClientOptions, start as innerStart } from './client.js'
import { Connection, ConnectionError, ConnectionConfig } from './instance/instance.js';
import pako from 'pako';

export {
  AddChainError,
  AddChainOptions,
  AlreadyDestroyedError,
  Chain,
  Client,
  ClientOptions,
  CrashError,
  JsonRpcCallback,
  JsonRpcDisabledError,
  LogCallback
} from './client.js';

/**
 * Initializes a new client. This is a pre-requisite to connecting to a blockchain.
 *
 * Can never fail.
 *
 * @param options Configuration of the client. Defaults to `{}`.
 */
export function start(options?: ClientOptions): Client {
  options = options || {}

  return innerStart(options, {
    base64DecodeAndZlibInflate: (input) => {
        return Promise.resolve(pako.inflate(trustedBase64Decode(input)))
    },
    performanceNow: () => {
      return performance.now()
    },
    getRandomValues: (buffer) => {
      const crypto = globalThis.crypto;
      if (!crypto)
          throw new Error('randomness not available');
      crypto.getRandomValues(buffer);
    },
    connect: (config) => {
      return connect(config, options?.forbidWs || false, options?.forbidNonLocalWs || false, options?.forbidWss || false)
    }
  })
}

/**
 * Decodes a base64 string.
 *
 * The input is assumed to be correct.
 */
function trustedBase64Decode(base64: string): Uint8Array {
    // This code is a bit sketchy due to the fact that we decode into a string, but it seems to
    // work.
    const binaryString = atob(base64);
    const size = binaryString.length;
    const bytes = new Uint8Array(size);
    for (let i = 0; i < size; i++) {
        bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes;
}

/**
 * Tries to open a new connection using the given configuration.
 *
 * @see Connection
 * @throws ConnectionError If the multiaddress couldn't be parsed or contains an invalid protocol.
 */
 function connect(config: ConnectionConfig, forbidWs: boolean, forbidNonLocalWs: boolean, forbidWss: boolean, forbidWebRTC: boolean): Connection {
  // Attempt to parse the multiaddress.
  // TODO: remove support for `/wss` in a long time (https://github.com/paritytech/smoldot/issues/1940)
  const wsParsed = config.address.match(/^\/(ip4|ip6|dns4|dns6|dns)\/(.*?)\/tcp\/(.*?)\/(ws|wss|tls\/ws)$/);

  const webRTCParsed = config.address.match(/^\/(ip4|ip6)\/(.*?)\/udp\/(.*?)\/x-webrtc\/(.*?)\/$/);

  if (wsParsed != null) {
      let connection: WebSocket;

      const proto = (wsParsed[4] == 'ws') ? 'ws' : 'wss';
      if (
          (proto == 'ws' && forbidWs) ||
          (proto == 'ws' && wsParsed[2] != 'localhost' && wsParsed[2] != '127.0.0.1' && forbidNonLocalWs) ||
          (proto == 'wss' && forbidWss)
      ) {
          throw new ConnectionError('Connection type not allowed');
      }

      const url = (wsParsed[1] == 'ip6') ?
          (proto + "://[" + wsParsed[2] + "]:" + wsParsed[3]) :
          (proto + "://" + wsParsed[2] + ":" + wsParsed[3]);

      connection = new WebSocket(url);
      connection.binaryType = 'arraybuffer';

      connection.onopen = () => {
          config.onOpen({ type: 'single-stream' });
      };
      connection.onclose = (event) => {
          const message = "Error code " + event.code + (!!event.reason ? (": " + event.reason) : "");
          config.onConnectionClose(message);
      };
      connection.onmessage = (msg) => {
          config.onMessage(new Uint8Array(msg.data as ArrayBuffer));
      };

      return {
        close: (): void => {
            connection.onopen = null;
            connection.onclose = null;
            connection.onmessage = null;
            connection.onerror = null;
            connection.close();
        },

        send: (data: Uint8Array): void => {
            connection.send(data);
        },

        openOutSubstream: () => { throw new Error('Wrong connection type') }
      };
  } else if (webRTCParsed != null) {
    let pc: RTCPeerConnection;

    const targetPort = webRTCParsed[3];
    if (forbidWebRTC || targetPort == '0') {
        throw new ConnectionError('Connection type not allowed');
    }

    // Create a new peer connection.
    pc = new RTCPeerConnection();

    pc.onconnectionstatechange = (_event) => {
      console.log(`conn state: ${pc.connectionState}`);
      if (pc.connectionState == "closed") {
          config.onConnectionClose("");
      }
    };

    // Create a new data channel with id=1. This will trigger a new negotiation (see
    // `negotiationneeded` handler below).
    const dataChannel = pc.createDataChannel("data", { id: 1 });

    // When a new negotion is triggered, set both local and remote descriptions.
    pc.onnegotiationneeded = async (_event) => {
        // Create a new offer and set it as local description.
        const sdpOffer = (await pc.createOffer()).sdp!;
        await pc.setLocalDescription({ type: 'offer', sdp: sdpOffer });

        console.log("LOCAL OFFER: " + pc.localDescription!.sdp);

        const ipVersion = webRTCParsed[1] == 'ip4'? '4' : '6';
        const targetIp = webRTCParsed[2];
        const ufrag = webRTCParsed[5];
        let fingerprint = "";
        for(i=0;i<=ufrag.length;i+=2) {
          fingerprint += ufrag[i] + ufrag[i+1] + ":";
        }

        // Note that the trailing line feed is important, as otherwise Chrome
        // fails to parse the payload.
        const remoteSdp =
            // Identifies the creator of the SDP document. We are allowed to use dummy values
            // (`-` and `0.0.0.0`) to remain anonymous, which we do. Note that "IN" means
            // "Internet". (RFC8866)
            "o=- 0 0 IN IP" + ipVersion  + " " + targetIp + "\n" +
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
            "a=ice-ufrag:" + ufrag + "\n" +
            "a=ice-pwd:" + ufrag + "\n" +
            // Fingerprint of the certificate that the server will use during the TLS
            // handshake. (RFC8122)
            // MUST be derived from the certificate used by the answerer (server).
            "a=fingerprint:sha-256 " + fingerprint  + "\n" +
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

        await pc.setRemoteDescription({ type: "answer", sdp: remoteSdp });

        console.log("REMOTE ANSWER: " + pc.remoteDescription!.sdp);
    };

    dataChannel.onopen = () => {
        console.log(`'${dataChannel.label}' opened`);

        // TODO: noise handshake
        const peerId = "";
        config.onOpen({ type: 'multi-stream', peerId: trustedBase64Decode(peerId) });
    };

    dataChannel.onerror = (error) => {
        console.log(`'${dataChannel.label}' errored: ${error}`);
    };

    dataChannel.onclose = () => {
        console.log(`'${dataChannel.label}' closed`);
    };

    dataChannel.onmessage = (m) => {
        console.log(`new message on '${dataChannel.label}': '${m.data}'`);
    }

    let dataChannels = new Map<number, RTCDataChannel>();

    return {
      close: (streamId: number): void => {
        if (streamId == null) {
          pc.onconnectionstatechange = null;
          pc.onnegotiationneeded = null;
          pc.close();
        } else {
          let dc = dataChannels.get(streamId);
          if (dc != null) {
            dc.close();
          } else {
            console.log(`Data channel ${streamId} not found`);
          }
        }
      },


      send: (data: Uint8Array, streamId: number): void => {
        let dc = dataChannels.get(streamId);
        if (dc != null) {
          dc.send(data);
        } else {
          console.log(`Data channel ${streamId} not found`);
        }
      },

      openOutSubstream: () => {
        var dataChannel = pc.createDataChannel("data");

        dataChannel.onopen = () => {
            console.log(`'${dataChannel.label}' opened`);
        };

        dataChannel.onerror = (error) => {
            console.log(`'${dataChannel.label}' errored: ${error}`);
        };

        dataChannel.onclose = () => {
            console.log(`'${dataChannel.label}' closed`);
        };

        dataChannel.onmessage = (m) => {
            console.log(`new message on '${dataChannel.label}': '${m.data}'`);
        }

        dataChannels.set(dataChannel.id, dataChannel);
      }
    };
  } else {
      throw new ConnectionError('Unrecognized multiaddr format');
  }
}

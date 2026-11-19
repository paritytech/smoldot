import { compactFromU8a, compactToU8a, hexToU8a, u8aConcat, u8aToHex } from "@polkadot/util";

// Field discriminants (lib/src/network/codec/statement.rs).
const FIELD_PROOF = 0;
const FIELD_DECRYPTION_KEY = 1;
const FIELD_EXPIRY = 2;
const FIELD_CHANNEL = 3;
const FIELD_TOPIC_START = 4;
const FIELD_TOPIC_END = 7;
const FIELD_DATA = 8;

const PROOF_SR25519 = 0;

// Byte length of a proof (signature and signer) by its variant: sr25519, ed25519, secp256k1.
const PROOF_LENGTHS = [64 + 32, 64 + 32, 65 + 33];

// Payload of a bench statement: the round and the message index, both u32 little endian. The
// rest of the data is zero padding up to the size of the messages pattern.
export const PAYLOAD_HEADER_LEN = 8;

export function encodePayload(round, msgIdx, size) {
  const data = new Uint8Array(size);
  const view = new DataView(data.buffer);
  view.setUint32(0, round, true);
  view.setUint32(4, msgIdx, true);
  return data;
}

// Returns the first topic of a hex-encoded statement and the round and message index of its
// payload. Throws on a statement that the bench could not have produced.
export function decodeStatement(hex) {
  const bytes = hexToU8a(hex);
  const [countLen, count] = compactFromU8a(bytes);
  let offset = countLen;
  let topic = null;
  let data = null;
  for (let i = 0; i < count.toNumber(); i++) {
    const field = bytes[offset++];
    if (field === FIELD_PROOF) {
      const length = PROOF_LENGTHS[bytes[offset++]];
      if (length === undefined) throw new Error("unknown proof variant");
      offset += length;
    } else if (field === FIELD_EXPIRY) {
      offset += 8;
    } else if (field === FIELD_DECRYPTION_KEY || field === FIELD_CHANNEL) {
      offset += 32;
    } else if (field >= FIELD_TOPIC_START && field <= FIELD_TOPIC_END) {
      topic ??= u8aToHex(bytes.subarray(offset, offset + 32));
      offset += 32;
    } else if (field === FIELD_DATA) {
      const [lenLen, len] = compactFromU8a(bytes.subarray(offset));
      offset += lenLen;
      data = bytes.subarray(offset, offset + len.toNumber());
      offset += len.toNumber();
    } else {
      throw new Error(`unknown statement field ${field}`);
    }
  }
  if (topic === null || data === null || data.length < PAYLOAD_HEADER_LEN) {
    throw new Error("statement without a topic or a bench payload");
  }
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  return { topic, round: view.getUint32(0, true), msgIdx: view.getUint32(4, true) };
}

function u64ToLeBytes(n) {
  const out = new Uint8Array(8);
  const view = new DataView(out.buffer);
  view.setBigUint64(0, BigInt(n), true);
  return out;
}

// Pack (timestamp_secs, sequence) into the u64 expiry per
// sp_statement_store::Statement::set_expiry_from_parts:
//   expiry = (timestamp_secs as u64) << 32 | sequence as u64
export function expiryFromParts(timestampSecs, sequence) {
  return (BigInt(timestampSecs) << 32n) | BigInt(sequence);
}

// Build the bytes signed over by the proof, mirroring
// sp_statement_store::Statement::encoded(for_signing=true) in polkadot-sdk:
// no leading field-count compact, no proof field, everything else in ascending
// discriminant order.
function buildSignatureMaterial({ expiry, channel, topic, data }) {
  const parts = [];

  parts.push(new Uint8Array([FIELD_EXPIRY]));
  parts.push(u64ToLeBytes(expiry));

  if (channel) {
    parts.push(new Uint8Array([FIELD_CHANNEL]));
    parts.push(channel);
  }

  parts.push(new Uint8Array([FIELD_TOPIC_START]));
  parts.push(topic);

  parts.push(new Uint8Array([FIELD_DATA]));
  parts.push(compactToU8a(data.length));
  parts.push(data);

  return u8aConcat(...parts);
}

// Encode a full sr25519-signed statement on the wire.
//
// Wire format (matches lib/src/network/codec/statement.rs and
// sp_statement_store::Statement::encoded(false)): SCALE-compact field count,
// then ascending (discriminant, value) pairs.
export function encodeStatement({ pair, expiry, channel, topic, data }) {
  const material = buildSignatureMaterial({ expiry, channel, topic, data });
  const signature = pair.sign(material);
  const signer = pair.publicKey;

  let numFields = 1; // proof
  numFields += 1; // expiry (always present)
  if (channel) numFields += 1;
  numFields += 1; // one topic
  numFields += 1; // data

  const parts = [];
  parts.push(compactToU8a(numFields));

  parts.push(new Uint8Array([FIELD_PROOF, PROOF_SR25519]));
  parts.push(signature);
  parts.push(signer);

  parts.push(new Uint8Array([FIELD_EXPIRY]));
  parts.push(u64ToLeBytes(expiry));

  if (channel) {
    parts.push(new Uint8Array([FIELD_CHANNEL]));
    parts.push(channel);
  }

  parts.push(new Uint8Array([FIELD_TOPIC_START]));
  parts.push(topic);

  parts.push(new Uint8Array([FIELD_DATA]));
  parts.push(compactToU8a(data.length));
  parts.push(data);

  return u8aToHex(u8aConcat(...parts));
}


import { compactToU8a, u8aConcat, u8aToHex } from "@polkadot/util";

// Field discriminants (lib/src/network/codec/statement.rs).
const FIELD_PROOF = 0;
const FIELD_EXPIRY = 2;
const FIELD_CHANNEL = 3;
const FIELD_TOPIC_START = 4;
const FIELD_DATA = 8;

const PROOF_SR25519 = 0;

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


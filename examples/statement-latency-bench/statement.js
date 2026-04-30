import { compactToU8a, compactFromU8a, u8aConcat, u8aToHex, hexToU8a } from "@polkadot/util";

// Field discriminants (lib/src/network/codec/statement.rs:35-46).
const FIELD_PROOF = 0;
const FIELD_DECRYPTION_KEY = 1;
const FIELD_EXPIRY = 2;
const FIELD_CHANNEL = 3;
const FIELD_TOPIC_START = 4;
const FIELD_TOPIC_END = 7;
const FIELD_DATA = 8;

const PROOF_SR25519 = 0;
const PROOF_ED25519 = 1;
const PROOF_SECP256K1_ECDSA = 2;
const PROOF_ON_CHAIN = 3;

function u64ToLeBytes(n) {
  const out = new Uint8Array(8);
  const view = new DataView(out.buffer);
  view.setBigUint64(0, BigInt(n), true);
  return out;
}

function leBytesToU64(bytes) {
  return new DataView(bytes.buffer, bytes.byteOffset, 8).getBigUint64(0, true);
}

// Pack (timestamp_secs, sequence) into the u64 expiry per
// sp_statement_store::Statement::set_expiry_from_parts:
//   expiry = (timestamp_secs as u64) << 32 | sequence as u64
export function expiryFromParts(timestampSecs, sequence) {
  return (BigInt(timestampSecs) << 32n) | BigInt(sequence);
}

// Build the bytes signed over by the proof, mirroring
// sp_statement_store::Statement::encoded(for_signing=true) in polkadot-sdk
// (substrate/primitives/statement-store/src/lib.rs:736-780): no leading
// field-count compact, no proof field, everything else in ascending discriminant
// order.
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
// Wire format (matches both lib/src/network/codec/statement.rs:269-325 and
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

// Best-effort decode for inspection / sanity checks. Skips fields we don't need
// in detail; pulls out proof signer, topic(s), and data.
export function decodeStatement(hex) {
  const bytes = hexToU8a(hex);
  let offset = 0;

  const [fieldCountSize, numFieldsBn] = compactFromU8a(bytes.subarray(offset));
  offset += fieldCountSize;
  const numFields = numFieldsBn.toNumber();

  let proof = null;
  const topics = [];
  let data = null;
  let channel = null;
  let expiry = null;

  for (let i = 0; i < numFields; i++) {
    const disc = bytes[offset++];
    switch (disc) {
      case FIELD_PROOF: {
        const proofType = bytes[offset++];
        if (proofType === PROOF_SR25519 || proofType === PROOF_ED25519) {
          const signature = bytes.slice(offset, offset + 64);
          offset += 64;
          const signer = bytes.slice(offset, offset + 32);
          offset += 32;
          proof = {
            type: proofType === PROOF_SR25519 ? "Sr25519" : "Ed25519",
            signature,
            signer,
          };
        } else if (proofType === PROOF_SECP256K1_ECDSA) {
          offset += 65 + 33;
          proof = { type: "Secp256k1Ecdsa" };
        } else if (proofType === PROOF_ON_CHAIN) {
          offset += 32 + 32 + 8;
          proof = { type: "OnChain" };
        } else {
          throw new Error(`Unknown proof type: ${proofType}`);
        }
        break;
      }
      case FIELD_DECRYPTION_KEY:
        offset += 32;
        break;
      case FIELD_EXPIRY:
        expiry = leBytesToU64(bytes.slice(offset, offset + 8));
        offset += 8;
        break;
      case FIELD_CHANNEL:
        channel = bytes.slice(offset, offset + 32);
        offset += 32;
        break;
      case FIELD_TOPIC_START:
      case FIELD_TOPIC_START + 1:
      case FIELD_TOPIC_START + 2:
      case FIELD_TOPIC_END:
        topics.push(bytes.slice(offset, offset + 32));
        offset += 32;
        break;
      case FIELD_DATA: {
        const [lenSize, lenBn] = compactFromU8a(bytes.subarray(offset));
        const len = lenBn.toNumber();
        offset += lenSize;
        data = bytes.slice(offset, offset + len);
        offset += len;
        break;
      }
      default:
        throw new Error(`Unknown field discriminant: ${disc}`);
    }
  }

  return { proof, expiry, channel, topics, data };
}

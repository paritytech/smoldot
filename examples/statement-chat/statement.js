import * as ed from "@noble/ed25519";

export function toHex(bytes) {
  return (
    "0x" +
    Array.from(bytes)
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("")
  );
}

function encodeCompact(value) {
  if (value < 0x40) {
    return new Uint8Array([value << 2]);
  } else if (value < 0x4000) {
    const v = (value << 2) | 0x01;
    return new Uint8Array([v & 0xff, v >> 8]);
  } else if (value < 0x40000000) {
    const v = (value << 2) | 0x02;
    return new Uint8Array([
      v & 0xff,
      (v >> 8) & 0xff,
      (v >> 16) & 0xff,
      v >> 24,
    ]);
  } else {
    throw new Error("Value too large for compact encoding");
  }
}

function concat(...arrays) {
  const totalLength = arrays.reduce((sum, arr) => sum + arr.length, 0);
  const result = new Uint8Array(totalLength);
  let offset = 0;
  for (const arr of arrays) {
    result.set(arr, offset);
    offset += arr.length;
  }
  return result;
}

function hexToTopic(hex) {
  if (hex.startsWith("0x")) hex = hex.slice(2);
  if (hex.length !== 64) {
    throw new Error(`Topic must be 32 bytes (64 hex chars), got ${hex.length}`);
  }
  return new Uint8Array(hex.match(/.{2}/g).map((b) => parseInt(b, 16)));
}

function encodeEd25519Proof(signature, publicKey) {
  return concat(new Uint8Array([1]), signature, publicKey);
}

function buildSignatureMaterial(topic, data) {
  const parts = [];

  parts.push(new Uint8Array([2]));
  parts.push(new Uint8Array(new BigUint64Array([0xffffffffffffffffn]).buffer));

  parts.push(new Uint8Array([4]));
  parts.push(hexToTopic(topic));

  const dataBytes = new TextEncoder().encode(data);
  parts.push(new Uint8Array([8]));
  parts.push(encodeCompact(dataBytes.length));
  parts.push(dataBytes);

  return concat(...parts);
}

function encodeStatement(proof, topic, data) {
  const parts = [];

  parts.push(encodeCompact(4));

  parts.push(new Uint8Array([0]));
  parts.push(proof);

  parts.push(new Uint8Array([2]));
  parts.push(new Uint8Array(new BigUint64Array([0xffffffffffffffffn]).buffer));

  parts.push(new Uint8Array([4]));
  parts.push(hexToTopic(topic));

  const dataBytes = new TextEncoder().encode(data);
  parts.push(new Uint8Array([8]));
  parts.push(encodeCompact(dataBytes.length));
  parts.push(dataBytes);

  return concat(...parts);
}

async function getOrCreateKeypair() {
  const stored = localStorage.getItem("statement-chat-keypair");
  if (stored) {
    const { privateKey, publicKey } = JSON.parse(stored);
    return {
      privateKey: new Uint8Array(privateKey),
      publicKey: new Uint8Array(publicKey),
    };
  }

  const privateKey = ed.utils.randomSecretKey();
  const publicKey = await ed.getPublicKeyAsync(privateKey);

  localStorage.setItem(
    "statement-chat-keypair",
    JSON.stringify({
      privateKey: Array.from(privateKey),
      publicKey: Array.from(publicKey),
    }),
  );

  return { privateKey, publicKey };
}

export async function createSignedStatement(topic, data) {
  const { privateKey, publicKey } = await getOrCreateKeypair();
  const signatureMaterial = buildSignatureMaterial(topic, data);
  const signature = await ed.signAsync(signatureMaterial, privateKey);
  const proof = encodeEd25519Proof(signature, publicKey);
  const statement = encodeStatement(proof, topic, data);
  return toHex(statement);
}

export async function getPublicKey() {
  const { publicKey } = await getOrCreateKeypair();
  return toHex(publicKey);
}

export function decodeStatement(hexData) {
  if (hexData.startsWith("0x")) hexData = hexData.slice(2);
  const bytes = new Uint8Array(
    hexData.match(/.{2}/g).map((b) => parseInt(b, 16)),
  );

  let offset = 0;
  const [numFields, fieldCountSize] = readCompact(bytes, offset);
  offset += fieldCountSize;

  let proof = null;
  let topic = null;
  let data = null;

  for (let i = 0; i < numFields; i++) {
    const discriminant = bytes[offset++];

    switch (discriminant) {
      case 0:
        const proofType = bytes[offset++];
        if (proofType === 1) {
          const signature = bytes.slice(offset, offset + 64);
          offset += 64;
          const signer = bytes.slice(offset, offset + 32);
          offset += 32;
          proof = { type: "Ed25519", signature, signer };
        } else {
          throw new Error(`Unsupported proof type: ${proofType}`);
        }
        break;
      case 1:
        offset += 32;
        break;
      case 2:
        offset += 8;
        break;
      case 3:
        offset += 32;
        break;
      case 4:
      case 5:
      case 6:
      case 7:
        topic = bytes.slice(offset, offset + 32);
        offset += 32;
        break;
      case 8:
        const [dataLen, dataLenSize] = readCompact(bytes, offset);
        offset += dataLenSize;
        data = bytes.slice(offset, offset + dataLen);
        offset += dataLen;
        break;
      default:
        throw new Error(`Unknown field discriminant: ${discriminant}`);
    }
  }

  return {
    proof,
    topic: topic ? toHex(topic) : null,
    data: data ? new TextDecoder().decode(data) : null,
  };
}

function readCompact(bytes, offset) {
  const mode = bytes[offset] & 0x03;
  if (mode === 0) {
    return [bytes[offset] >> 2, 1];
  } else if (mode === 1) {
    const value = (bytes[offset] | (bytes[offset + 1] << 8)) >> 2;
    return [value, 2];
  } else if (mode === 2) {
    const value =
      (bytes[offset] |
        (bytes[offset + 1] << 8) |
        (bytes[offset + 2] << 16) |
        (bytes[offset + 3] << 24)) >>
      2;
    return [value, 4];
  } else {
    throw new Error(
      `Big integer compact encoding not supported (mode: ${mode}, offset: ${offset})`,
    );
  }
}

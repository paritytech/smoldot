import { Keyring } from "@polkadot/keyring";
import { cryptoWaitReady } from "@polkadot/util-crypto";

let keyring = null;

async function getKeyring() {
  if (!keyring) {
    await cryptoWaitReady();
    keyring = new Keyring({ type: "sr25519" });
  }
  return keyring;
}

// Mirrors sc_statement_store::test_utils::get_keypair (substrate),
// which derives `//StatementClient//{idx}`.
export async function getKeypair(idx) {
  const ring = await getKeyring();
  return ring.createFromUri(`//StatementClient//${idx}`);
}

# Changelog

## Unreleased

### Changed

- Prune list of unverified blocks if it grows too much in order to resist spam attacks.
- Log block's parent hash in case of block announce.
- Only call `console.error` once in case of a Rust panic.

### Fixed

- Fix parachain blocks being reported multiple times in case of a relay chain fork.
- Implement the `ext_crypto_ecdsa_sign_version_1` host function.
- Implement the `ext_crypto_ecdsa_verify_version_1` host function.
- Implement the `ext_crypto_ecdsa_sign_prehashed_version_1` host function.
- Implement the `ext_crypto_ecdsa_verify_prehashed_version_1` host function.

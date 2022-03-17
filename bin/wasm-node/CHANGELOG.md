# Changelog

## Unreleased

### Added

- Add `ClientOptions.cpuRateLimit`, which lets the user put an upper bound on the amount of CPU that the client uses on average.

## 0.6.5 - 2022-17-03

### Changed

- Chain specifications with a `codeSubstitutes` field containing a block hash are no longer supported ([#2127](https://github.com/paritytech/smoldot/pull/2127)).
- Prune list of unverified blocks if it grows too much in order to resist spam attacks ([#2114](https://github.com/paritytech/smoldot/pull/2114)).
- Log block's parent hash in case of block announce ([#2105](https://github.com/paritytech/smoldot/pull/2105)).
- Only call `console.error` once in case of a Rust panic ([#2093](https://github.com/paritytech/smoldot/pull/2093)).

### Fixed

- Fix parachain blocks being reported multiple times in case of a relay chain fork ([#2106](https://github.com/paritytech/smoldot/pull/2106)).
- Implement the `ext_crypto_ecdsa_sign_version_1` host function ([#2120](https://github.com/paritytech/smoldot/pull/2120)).
- Implement the `ext_crypto_ecdsa_verify_version_1` host function ([#2120](https://github.com/paritytech/smoldot/pull/2120)).
- Implement the `ext_crypto_ecdsa_sign_prehashed_version_1` host function ([#2120](https://github.com/paritytech/smoldot/pull/2120)).
- Implement the `ext_crypto_ecdsa_verify_prehashed_version_1` host function ([#2120](https://github.com/paritytech/smoldot/pull/2120)).
- Properly mark all descendants as bad when a block is determined to be bad ([#2121](https://github.com/paritytech/smoldot/pull/2121)).

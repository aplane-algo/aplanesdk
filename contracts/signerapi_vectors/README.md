# Captured signer responses

`real_sign_responses.json` holds `/sign` requests and the responses a live
apsigner returned for them. The three SDKs feed each pair through their
response verification, so the checks are tested against what the signer really
produces, not against responses the SDKs' own test helpers build.

Each case is keyed by name and holds `key_type`, `request` (the `/sign` body's
`requests`) and `response` (`signed` and `mutations`):

- `logicsig_falcon_single`: one payment from a LogicSig Falcon account. The
  signer raised its fee, appended one resource dummy and grouped the two.
- `logicsig_falcon_pair`: two payments from a LogicSig Falcon account, plus
  one dummy.
- `native_falcon_single`: one payment from a native Falcon account. The fee
  was raised; there is no group.
- `ed25519_pair`: two payments from an Ed25519 account, grouped and otherwise
  unchanged.

The bytes were captured from a live signer on a local test network, through
aplane's SDK integration harness. The keys were throwaway; nothing here is
secret. Unlike `contracts/signerapi`, these are not wire-shape fixtures and
are not mirrored from the aplane repository.

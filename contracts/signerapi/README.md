# Signer API Contract Fixtures

These JSON files are committed golden fixtures for the signer HTTP API contract
tests. The external `aplane-algo/aplanesdk` repository also consumes this
wire-contract shape for SDK compatibility tests.

`fixture_manifest.json` is the committed list of payload fixtures that each
language should round-trip. `error_codes.json` and
`error_code_classifications.json` pin stable error-code sets and semantic
classification buckets for SDK error mapping. `SHA256SUMS` pins the complete
directory contents except itself.

They are intentionally static. Do not regenerate them automatically during test
runs. If a compatibility-bearing wire field changes, update these fixtures in
the same review as the code and documentation change.

When changing this directory, run the signer API contract tests and compare the
directory with the SDK copy:

```bash
make contract-test
make contract-sync-check APLANESDK_DIR=../aplanesdk
```

The payloads use stable dummy addresses and hex strings. They are not intended
to be valid Algorand transactions; they only pin JSON wire shapes.

For fixtures that are round-tripped through Go structs, avoid explicitly
including zero values for fields tagged `omitempty`. For example, omit
`required:false`, `byte_length:0`, and `passthrough_count:0` unless the test is
intentionally checking that the value is omitted on re-marshal. Go will strip
those zero values when encoding, which makes an otherwise valid fixture fail the
semantic round-trip comparison.

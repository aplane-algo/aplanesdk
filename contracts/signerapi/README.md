# Signer API Contract Fixtures

These JSON files are committed golden fixtures for the signer HTTP API contract
tests. The external `aplane-algo/aplanesdk` repository also consumes this
wire-contract shape for SDK compatibility tests.

They are intentionally static. Do not regenerate them automatically during test
runs. If a compatibility-bearing wire field changes, update these fixtures in
the same review as the code and documentation change.

The payloads use stable dummy addresses and hex strings. They are not intended
to be valid Algorand transactions; they only pin JSON wire shapes.

For fixtures that are round-tripped through Go structs, avoid explicitly
including zero values for fields tagged `omitempty`. For example, omit
`required:false`, `byte_length:0`, and `passthrough_count:0` unless the test is
intentionally checking that the value is omitted on re-marshal. Go will strip
those zero values when encoding, which makes an otherwise valid fixture fail the
semantic round-trip comparison.

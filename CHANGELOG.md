## 2.0.0

- Upgraded Go from 1.24 to 1.25.0.
- Updated all modules to their latest versions.

**BREAKING CHANGES:**
- Updated starknet.go dependency from v0.7.3 to v0.17.1, which introduces breaking changes to the `rpc.NewProvider` function signature. Users must now pass a `context.Context` as the first parameter when creating RPC providers.

## 1.0.0

- Stable release.

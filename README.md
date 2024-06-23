<p align="center">
    <a href="https://pkg.go.dev/github.com/metacube-games/starknetid.go">
        <img src="https://pkg.go.dev/badge/github.com/metacube-games/starknetid.go.svg" alt="Go Reference">
    </a>
    <a href="https://github.com/metacube-games/starknetid.go/blob/main/LICENSE">
        <img src="https://img.shields.io/badge/license-MIT-black">
    </a>
    <a href="https://github.com/metacube-games/starknetid.go/actions/workflows/go.yml">
        <img src="https://github.com/metacube-games/starknetid.go/actions/workflows/go.yml/badge.svg?branch=main" alt="test">
    </a>
    <a href="https://github.com/metacube-games/starknetid.go">
      <img src="https://img.shields.io/github/stars/metacube-games/starknetid.go?style=social"/>
    </a>
</p>

<p align="center">
  <a href="https://twitter.com/MetacubeGames">
    <img src="https://img.shields.io/twitter/follow/MetacubeGames?style=social"/>
  </a>
</p>

<h1 align="center">Starknetid.go</h1>

Starknetid.go is an unofficial Go library to interact with the [Starknet.id](https://starknet.id/) protocol. The implementation is inspired by the official Javascript library [Starknetid.js](https://github.com/starknet-id/starknetid.js).

Starknetid.go is powered by [Starknet.go](https://github.com/NethermindEth/starknet.go).

## Getting Started

**Step 1**: Install the module

```bash
go get github.com/metacube-games/starknetid.go
```

**Step 2**: Initialize the StarknetId provider

```go
// 1. Create a new RPC provider client
client, err := rpc.NewProvider(RPC_URL) // github.com/NethermindEth/starknet.go/rpc
if err != nil {
  panic(err)
}

// 2. Create a new Starknet.id provider
provider, err := provider.NewProvider(client, constants.SN_MAIN, nil)
if err != nil {
  panic(err)
}
```

**Step 3**: Use the provider to interact with the Starknet.id protocol

```go
// Example: Get address from Stark name
address, err := provider.GetAddressFromStarkName(context.Background(), `metacube.stark`)
if err != nil {
  panic(err)
}
println("Address of metacube.stark:", address)
```

Please refer to the [examples](examples/main.go) for more usage examples.

## Features

The library is still in development and not all features are implemented yet

| Method | Implemented |
| --- | --- |
| `GetAddressFromStarkName` | ✅ |
| `GetStarkName` | ✅ |
| `GetStarknetId` | ✅ |
| `GetUserData` | 🛠️ |
| `GetStarkNames` | ❌ |
| `GetExtendedUserData` | ❌ |
| `GetUnboundedUserData` | ❌ |
| `GetVerifierData` | ❌ |
| `GetExtendedVerifierData` | ❌ |
| `GetUnboundedVerifierData` | ❌ |
| `GetPfpVerifierData` | ❌ |
| `GetProfileData` | ❌ |
| `GetStarkProfiles` | ❌ |

## Contribute

Contributions are welcome! Please refer to the [contribution guidelines](CONTRIBUTING.md) for more information.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributors

Thanks goes to these wonderful people ([emoji key](https://allcontributors.org/docs/en/emoji-key)):

<!-- ALL-CONTRIBUTORS-LIST:START - Do not remove or modify this section -->
<!-- prettier-ignore-start -->
<!-- markdownlint-disable -->
<table>
  <tbody>
    <tr>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/BastienFaivre"><img src="https://avatars.githubusercontent.com/u/57015770?v=4?s=100" width="100px;" alt="Bastien Faivre"/><br /><sub><b>Bastien Faivre</b></sub></a><br /><a href="#code-BastienFaivre" title="Code">💻</a> <a href="#doc-BastienFaivre" title="Documentation">📖</a> <a href="#example-BastienFaivre" title="Examples">💡</a> <a href="#maintenance-BastienFaivre" title="Maintenance">🚧</a> <a href="#test-BastienFaivre" title="Tests">⚠️</a></td>
    </tr>
  </tbody>
</table>

<!-- markdownlint-restore -->
<!-- prettier-ignore-end -->

<!-- ALL-CONTRIBUTORS-LIST:END -->

This project follows the [all-contributors](https://github.com/all-contributors/all-contributors) specification. Contributions of any kind welcome!

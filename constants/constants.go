package constants

import (
	"math/big"

	"github.com/NethermindEth/juno/core/felt"
	"github.com/NethermindEth/starknet.go/rpc"
	"github.com/metacube-games/starknetid.go/types"
)

const (
	SN_MAIN    types.StarknetChainId = "0x534e5f4d41494e"
	SN_SEPOLIA types.StarknetChainId = "0x534e5f5345504f4c4941"

	IDENTITY_CONTRACT_SN_MAIN    = "0x05dbdedc203e92749e2e746e2d40a768d966bd243df04a6b712e222bc040a9af"
	IDENTITY_CONTRACT_SN_SEPOLIA = "0x3697660a0981d734780731949ecb2b4a38d6a58fc41629ed611e8defda"

	NAMING_CONTRACT_SN_MAIN    = "0x6ac597f8116f886fa1c97a23fa4e08299975ecaf6b598873ca6792b9bbfb678"
	NAMING_CONTRACT_SN_SEPOLIA = "0x154bc2e1af9260b9e66af0e9c46fc757ff893b3ff6a85718a810baf1474"

	VERIFIER_CONTRACT_SN_MAIN    = "0x07d14dfd8ee95b41fce179170d88ba1f0d5a512e13aeb232f19cfeec0a88f8bf"
	VERIFIER_CONTRACT_SN_SEPOLIA = "0x60B94fEDe525f815AE5E8377A463e121C787cCCf3a36358Aa9B18c12c4D566"

	PFP_VERIFIER_CONTRACT_SN_MAIN    = "0x070aaa20ec4a46da57c932d9fd89ca5e6bb9ca3188d3df361a32306aff7d59c7"
	PFP_VERIFIER_CONTRACT_SN_SEPOLIA = "0x9e7bdb8dabd02ea8cfc23b1d1c5278e46490f193f87516ed5ff2dfec02"

	POP_VERIFIER_CONTRACT_SN_MAIN    = "0x0293eb2ba9862f762bd3036586d5755a782bd22e6f5028320f1d0405fd47bff4"
	POP_VERIFIER_CONTRACT_SN_SEPOLIA = "0x15ae88ae054caa74090b89025c1595683f12edf7a4ed2ad0274de3e1d4a"

	MULTICALL_CONTRACT       = "0x034ffb8f4452df7a613a0210824d6414dbadcddce6c6e19bf4ddc9e22ce5f970"
	UTILS_MULTICALL_CONTRACT = "0x004a50c8a8bc97eaaa947e8cbde481beaf5d6c38b4ac89da31ebdddb547d13d7"

	BLOBBERT_CONTRACT_SN_MAIN = "0x00539f522b29ae9251dbf7443c7a950cf260372e69efab3710a11bf17a9599f1"

	ZERO = 0

	TEXT_TO_FELT_MAX_LEN = 31
)

var (
	// NOTE: The use of rune type is necessary to avoid issues with the
	// len() function.
	// Example (https://go.dev/play/p/QdXxPdznDO7):
	//     len("这来") -> 6	ouch!
	//     len([]rune("这来")) -> 2 nice!
	BASIC_ALPHABET    = []rune("abcdefghijklmnopqrstuvwxyz0123456789-")
	EXTENDED_ALPHABET = []rune("这来")
	TOTAL_ALPHABET    = append(BASIC_ALPHABET, EXTENDED_ALPHABET...)

	BASIC_ALPHABET_SIZE_FELT = (&felt.Felt{}).
					SetUint64(uint64(len(BASIC_ALPHABET)))
	BASIC_ALPHABET_SIZE_BIGINT = big.
					NewInt(int64(len(BASIC_ALPHABET)))
	BASIC_ALPHABET_SIZE_PLUS_ONE_FELT = (&felt.Felt{}).
						SetUint64(uint64(len(BASIC_ALPHABET) + 1))
	BASIC_ALPHABET_SIZE_PLUS_ONE_BIGINT = big.
						NewInt(int64(len(BASIC_ALPHABET) + 1))
	EXTENDED_ALPHABET_SIZE_FELT = (&felt.Felt{}).
					SetUint64(uint64(len(EXTENDED_ALPHABET)))
	EXTENDED_ALPHABET_SIZE_BIGINT = big.
					NewInt(int64(len(EXTENDED_ALPHABET)))
	EXTENDED_ALPHABET_SIZE_PLUS_ONE_FELT = (&felt.Felt{}).
						SetUint64(uint64(len(EXTENDED_ALPHABET) + 1))
	EXTENDED_ALPHABET_SIZE_PLUS_ONE_BIGINT = big.
						NewInt(int64(len(EXTENDED_ALPHABET) + 1))

	BLOCK_ID = rpc.BlockID{Tag: "latest"}
)

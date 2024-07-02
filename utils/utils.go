package utils

import (
	"fmt"
	"math/big"
	"regexp"
	"strings"

	"github.com/NethermindEth/juno/core/felt"
	NethermindEthUtils "github.com/NethermindEth/starknet.go/utils"
	"github.com/metacube-games/starknetid.go/constants"
	"github.com/metacube-games/starknetid.go/types"
)

// GetIdentityContract returns the identity contract address for a given chain.
//
// Parameters:
//   - chainId: The chain ID.
//
// Returns:
//   - string: The identity contract address.
//   - error: An error if the identity contract is not deployed on the chain.
func GetIdentityContract(chainId types.StarknetChainId) (string, error) {
	switch chainId {
	case constants.SN_MAIN:
		return constants.IDENTITY_CONTRACT_SN_MAIN, nil
	case constants.SN_SEPOLIA:
		return constants.IDENTITY_CONTRACT_SN_SEPOLIA, nil
	default:
		return "", fmt.Errorf(
			"starknet.id identity contract is not deployed on chain %s",
			chainId,
		)
	}
}

// GetNamingContract returns the naming contract address for a given chain.
//
// Parameters:
//   - chainId: The chain ID.
//
// Returns:
//   - string: The naming contract address.
//   - error: An error if the naming contract is not deployed on the chain.
func GetNamingContract(chainId types.StarknetChainId) (string, error) {
	switch chainId {
	case constants.SN_MAIN:
		return constants.NAMING_CONTRACT_SN_MAIN, nil
	case constants.SN_SEPOLIA:
		return constants.NAMING_CONTRACT_SN_SEPOLIA, nil
	default:
		return "", fmt.Errorf(
			"starknet.id naming contract is not deployed on chain %s",
			chainId,
		)
	}
}

// GetVerifierContract returns the verifier contract address for a given chain.
//
// Parameters:
//   - chainId: The chain ID.
//
// Returns:
//   - string: The verifier contract address.
//   - error: An error if the verifier contract is not deployed on the chain.
func GetVerifierContract(chainId types.StarknetChainId) (string, error) {
	switch chainId {
	case constants.SN_MAIN:
		return constants.VERIFIER_CONTRACT_SN_MAIN, nil
	case constants.SN_SEPOLIA:
		return constants.VERIFIER_CONTRACT_SN_SEPOLIA, nil
	default:
		return "", fmt.Errorf(
			"starknet.id verifier contract is not deployed on chain %s",
			chainId,
		)
	}
}

// GetPfpVerifierContract returns the profile picture verifier contract address
// for a given chain.
//
// Parameters:
//   - chainId: The chain ID.
//
// Returns:
//   - string: The profile picture verifier contract address.
//   - error: An error if the profile picture verifier contract is not deployed
//     on the chain.
func GetPfpVerifierContract(chainId types.StarknetChainId) (string, error) {
	switch chainId {
	case constants.SN_MAIN:
		return constants.PFP_VERIFIER_CONTRACT_SN_MAIN, nil
	case constants.SN_SEPOLIA:
		return constants.PFP_VERIFIER_CONTRACT_SN_SEPOLIA, nil
	default:
		return "", fmt.Errorf(
			"starknet.id profile picture verifier contract is not deployed on chain %s",
			chainId,
		)
	}
}

// GetPopVerifierContract returns the proof of personhood verifier contract
// address for a given chain.
//
// Parameters:
//   - chainId: The chain ID.
//
// Returns:
//   - string: The proof of personhood verifier contract address.
//   - error: An error if the proof of personhood verifier contract is not
//     deployed on the chain.
func GetPopVerifierContract(chainId types.StarknetChainId) (string, error) {
	switch chainId {
	case constants.SN_MAIN:
		return constants.POP_VERIFIER_CONTRACT_SN_MAIN, nil
	case constants.SN_SEPOLIA:
		return constants.POP_VERIFIER_CONTRACT_SN_SEPOLIA, nil
	default:
		return "", fmt.Errorf(
			"starknet.id proof of personhood verifier contract is not deployed on chain %s",
			chainId,
		)
	}
}

// GetMulticallContract returns the multicall contract address for a given
// chain.
//
// Parameters:
//   - chainId: The chain ID.
//
// Returns:
//   - string: The multicall contract address.
//   - error: An error if the multicall contract is not deployed on the chain.
func GetMulticallContract(chainId types.StarknetChainId) (string, error) {
	switch chainId {
	case constants.SN_MAIN:
		return constants.MULTICALL_CONTRACT, nil
	case constants.SN_SEPOLIA:
		return constants.MULTICALL_CONTRACT, nil
	default:
		return "", fmt.Errorf(
			"starknet.id multicall contract is not deployed on chain %s",
			chainId,
		)
	}
}

// GetUtilsMulticallContract returns the utils multicall contract address for a
// given chain.
//
// Parameters:
//   - chainId: The chain ID.
//
// Returns:
//   - string: The utils multicall contract address.
//   - error: An error if the utils multicall contract is not deployed on the
//     chain.
func GetUtilsMulticallContract(chainId types.StarknetChainId) (string, error) {
	switch chainId {
	case constants.SN_MAIN:
		return constants.UTILS_MULTICALL_CONTRACT, nil
	case constants.SN_SEPOLIA:
		return constants.UTILS_MULTICALL_CONTRACT, nil
	default:
		return "", fmt.Errorf(
			"starknet.id utils multicall contract is not deployed on chain %s",
			chainId,
		)
	}

}

// GetBlobbertContract returns the blobbert contract address for a given chain.
//
// Parameters:
//   - chainId: The chain ID.
//
// Returns:
//   - string: The blobbert contract address.
//   - error: An error if the blobbert contract is not deployed on the chain.
func GetBlobbertContract(chainId types.StarknetChainId) (string, error) {
	switch chainId {
	case constants.SN_MAIN:
		return constants.BLOBBERT_CONTRACT_SN_MAIN, nil
	default:
		return "", fmt.Errorf(
			"starknet.id blobbert contract is not deployed on chain %s",
			chainId,
		)
	}
}

// DecodeDomain decodes a starknet.id domain from a list of felt.
//
// Parameters:
//   - encoded: The encoded domain.
//
// Returns:
//   - string: The decoded domain.
//
// Examples:
//   - DecodeDomain(nil) => ""
//   - DecodeDomain([felt_0]) => ""
//   - DecodeDomain([felt_abc]) => "abc.stark"
//   - DecodeDomain([felt_def]) => "def.stark"
//   - DecodeDomain([felt_ghi]) => "ghi.stark"
//   - DecodeDomain([felt_abc, felt_def]) => "abc.def.stark"
//   - DecodeDomain([felt_abc, felt_def, felt_ghi]) => "abc.def.ghi.stark"
func DecodeDomain(encoded []*felt.Felt) string {
	var decoded strings.Builder

	for i, subdomain := range encoded {
		decoded.WriteString(decode(subdomain))
		if i < len(encoded)-1 {
			decoded.WriteRune('.')
		}
	}

	if decoded.Len() == 0 {
		return ""
	}

	decoded.WriteString(".stark")
	return decoded.String()
}

// EncodeDomain encodes a starknet.id domain into a list of felt, with one felt
// per subdomain.
//
// Parameters:
//   - domain: The domain to encode (.stark suffix is optional).
//
// Returns:
//   - []*felt.Felt: The encoded domain.
//   - error: An error if the encoding fails.
//
// Examples:
//   - EncodeDomain("") => [felt_0]
//   - EncodeDomain("abc.stark") => [felt_abc]
//   - EncodeDomain("abc") => [felt_abc]
//   - EncodeDomain("def.stark") => [felt_def]
//   - EncodeDomain("ghi.stark") => [felt_ghi]
//   - EncodeDomain("abc.def.stark") => [felt_abc, felt_def]
//   - EncodeDomain("abc.def.ghi.stark") => [felt_abc, felt_def, felt_ghi]
//   - EncodeDomain("αβγ.stark") => error failed to encode subdomain αβγ: invalid character α
func EncodeDomain(domain string) ([]*felt.Felt, error) {
	if domain == "" {
		return []*felt.Felt{(&felt.Felt{}).SetUint64(0)}, nil
	}

	encoded := []*felt.Felt{}
	subdomains := strings.Split(strings.Replace(domain, ".stark", "", 1), ".")
	for _, subdomain := range subdomains {
		encodedSubdomain, err := encode(subdomain)
		if err != nil {
			return []*felt.Felt{}, fmt.Errorf(
				"failed to encode subdomain %s: %w",
				subdomain,
				err,
			)
		}
		encoded = append(encoded, encodedSubdomain)
	}
	return encoded, nil
}

// decode decodes an encoded subdomain into a string using the StarknetID
// encoding/deconding algorithm.
//
// Parameters:
//   - encodedSubdomain: The encoded subdomain.
//
// Returns:
//   - string: The decoded subdomain.
//
// Examples:
//   - decode(nil) => ""
//   - decode(felt_0) => ""
//   - decode(felt_abc) => "abc"
//   - decode(felt_def) => "def"
func decode(encodedSubdomain *felt.Felt) string {
	// NOTE: The use of BigInt is necessary since the Felt type does not have
	// a method to get the modulo of a Felt. Furthermore, the division of a Felt
	// by another Felt is not an integer division.
	v := encodedSubdomain.BigInt(new(big.Int))
	var decoded []rune
	for v.Cmp(big.NewInt(constants.ZERO)) != 0 {
		code := new(big.Int).Mod(
			v,
			constants.BASIC_ALPHABET_SIZE_PLUS_ONE_BIGINT,
		)
		v.Div(v, constants.BASIC_ALPHABET_SIZE_PLUS_ONE_BIGINT)
		if code.Cmp(constants.BASIC_ALPHABET_SIZE_BIGINT) == 0 {
			nextV := new(big.Int).Div(
				v,
				constants.EXTENDED_ALPHABET_SIZE_PLUS_ONE_BIGINT,
			)
			if nextV.Cmp(big.NewInt(constants.ZERO)) == 0 {
				code2 := new(big.Int).Mod(
					v,
					constants.EXTENDED_ALPHABET_SIZE_PLUS_ONE_BIGINT,
				)
				v.Set(nextV)
				if code2.Cmp(big.NewInt(constants.ZERO)) == 0 {
					decoded = append(decoded, constants.BASIC_ALPHABET[0])
				} else {
					decoded = append(
						decoded,
						constants.EXTENDED_ALPHABET[int(code2.Int64())-1],
					)
				}
			} else {
				code2 := new(big.Int).Mod(
					v,
					constants.EXTENDED_ALPHABET_SIZE_BIGINT,
				)
				decoded = append(
					decoded,
					constants.EXTENDED_ALPHABET[int(code2.Int64())],
				)
				v.Div(v, constants.EXTENDED_ALPHABET_SIZE_BIGINT)
			}
		} else {
			decoded = append(
				decoded,
				constants.BASIC_ALPHABET[int(code.Int64())],
			)
		}
	}

	str, k := extractToCome(string(decoded))
	decoded = []rune(str)

	if k != 0 {
		if k%2 == 0 {
			decoded = append(
				decoded,
				append(
					[]rune(strings.Repeat(
						string(constants.EXTENDED_ALPHABET[len(
							constants.EXTENDED_ALPHABET,
						)-1]),
						k/2-1),
					),
					append(
						[]rune{constants.EXTENDED_ALPHABET[0]},
						constants.BASIC_ALPHABET[1],
					)...,
				)...,
			)
		} else {
			decoded = append(
				decoded,
				[]rune(strings.Repeat(
					string(constants.EXTENDED_ALPHABET[len(
						constants.EXTENDED_ALPHABET,
					)-1]),
					(k-1)/2+1),
				)...,
			)
		}
	}

	return string(decoded)
}

// encode encodes a subdomain into a felt using the StarknetID encoding/decoding
// algorithm.
//
// Parameters:
//   - subdomain: The subdomain to encode.
//
// Returns:
//   - *felt.Felt: The encoded subdomain.
//   - error: An error if the encoding fails.
//
// Examples:
//   - encode("abc") => felt_abc
//   - encode("def") => felt_def
//   - encode("αβγ") => error invalid character α
func encode(subdomain string) (*felt.Felt, error) {
	v := []rune(subdomain)
	encoded := &felt.Felt{}
	multiplier := (&felt.Felt{}).SetUint64(1)

	if len(v) == 0 {
		return encoded, nil
	}

	if strings.HasSuffix(
		string(v),
		string(constants.EXTENDED_ALPHABET[0])+
			string(constants.BASIC_ALPHABET[1]),
	) {
		str, k := extractToCome(string(v[:len(v)-2]))
		v = append(
			[]rune(str),
			[]rune(strings.Repeat(
				string(constants.EXTENDED_ALPHABET[len(
					constants.EXTENDED_ALPHABET,
				)-1]),
				2*(k+1)),
			)...)
	} else {
		str, k := extractToCome(string(v))
		if k != 0 {
			v = append(
				[]rune(str),
				[]rune(strings.Repeat(
					string(constants.EXTENDED_ALPHABET[len(
						constants.EXTENDED_ALPHABET,
					)-1]),
					1+2*(k-1)),
				)...)
		}
	}

	for i, r := range v {
		char := r
		index := runeIndex(constants.BASIC_ALPHABET, char)
		bnIndex := (&felt.Felt{}).SetUint64(uint64(index))

		if index != -1 {
			if i == len(v)-1 && r == constants.BASIC_ALPHABET[0] {
				encoded.Add(
					encoded,
					(&felt.Felt{}).Mul(
						multiplier,
						constants.BASIC_ALPHABET_SIZE_FELT,
					),
				)
				multiplier.Mul(
					multiplier,
					constants.BASIC_ALPHABET_SIZE_PLUS_ONE_FELT,
				)
				multiplier.Mul(
					multiplier,
					constants.BASIC_ALPHABET_SIZE_PLUS_ONE_FELT,
				)
			} else {
				encoded.Add(encoded, (&felt.Felt{}).Mul(multiplier, bnIndex))
				multiplier.Mul(
					multiplier,
					constants.BASIC_ALPHABET_SIZE_PLUS_ONE_FELT,
				)
			}
		} else if runeIndex(constants.EXTENDED_ALPHABET, char) != -1 {
			encoded.Add(
				encoded,
				(&felt.Felt{}).Mul(
					multiplier,
					constants.BASIC_ALPHABET_SIZE_FELT,
				),
			)
			multiplier.Mul(
				multiplier,
				constants.BASIC_ALPHABET_SIZE_PLUS_ONE_FELT,
			)
			newid := (&felt.Felt{}).SetUint64(
				uint64(runeIndex(constants.EXTENDED_ALPHABET, char)),
			)
			if i == len(v)-1 {
				newid.Add(newid, (&felt.Felt{}).SetUint64(1))
			}
			encoded.Add(encoded, (&felt.Felt{}).Mul(multiplier, newid))
			multiplier.Mul(multiplier, constants.EXTENDED_ALPHABET_SIZE_FELT)
		} else {
			return encoded, fmt.Errorf("invalid character %c", char)
		}
	}

	return encoded, nil
}

// runeIndex returns the index of a rune in a slice of runes.
//
// Parameters:
//   - runes: The slice of runes.
//   - r: The rune to find.
//
// Returns:
//   - int: The index of the rune in the slice or -1 if the rune is not in the
//     slice.
func runeIndex(runes []rune, r rune) int {
	for i, v := range runes {
		if v == r {
			return i
		}
	}
	return -1
}

// extractToCome removes the trailing '来' (toCome) from a string.
//
// Parameters:
//   - str: The string to remove the trailing '来' from.
//
// Returns:
//   - string: The string without the trailing '来'.
//   - int: The number of '来' removed.
func extractToCome(str string) (string, int) {
	k := 0
	for strings.HasSuffix(
		str,
		string(constants.EXTENDED_ALPHABET[len(constants.EXTENDED_ALPHABET)-1]),
	) {
		str = string([]rune(str)[:len([]rune(str))-1])
		k++
	}
	return str, k
}

// IsStarkDomain checks if a domain is a starknet.id domain based on the
// following regular expression:
// `^(?:[a-z0-9-]{1,48}(?:[a-z0-9-]{1,48}[a-z0-9-])?\.)*[a-z0-9-]{1,48}\.stark$`
//
// Parameters:
//   - domain: The domain to check.
//
// Returns:
//   - bool: True if the domain is a starknet.id domain, false otherwise.
func IsStarkDomain(domain string) bool {
	match, _ := regexp.MatchString(
		`^(?:[a-z0-9-]{1,48}(?:[a-z0-9-]{1,48}[a-z0-9-])?\.)*[a-z0-9-]{1,48}\.stark$`,
		domain,
	)
	return match
}

// IsStarkRootDomain checks if a domain is a stark root domain based on the
// following regular expression:
// `^([a-z0-9-]){1,48}\.stark$`
//
// Parameters:
//   - domain: The domain to check.
//
// Returns:
//   - bool: True if the domain is a stark root domain, false otherwise.
func IsStarkRootDomain(domain string) bool {
	match, _ := regexp.MatchString(
		`^([a-z0-9-]){1,48}\.stark$`,
		domain,
	)
	return match
}

// IsSubdomain checks if a domain is a subdomain.
//
// Parameters:
//   - subdomain: The domain to check.
//
// Returns:
//   - bool: True if the domain is a subdomain, false otherwise.
func IsSubdomain(subdomain string) bool {
	return !(subdomain == "") && strings.Count(subdomain, ".") > 1
}

// IsBraavosSubdomain checks if a domain is a Braavos subdomain based on the
// following regular expression:
// `^([a-z0-9-]){1,48}\.braavos\.stark$`
//
// Parameters:
//   - domain: The domain to check.
//
// Returns:
//   - bool: True if the domain is a Braavos subdomain, false otherwise.
func IsBraavosSubdomain(domain string) bool {
	match, _ := regexp.MatchString(
		`^([a-z0-9-]){1,48}\.braavos\.stark$`,
		domain,
	)
	return match
}

// IsXplorerSubdomain checks if a domain is an xplorer subdomain
// based on the following regular expression:
// `^([a-z0-9-]){1,48}\.xplorer\.stark$`
//
// Parameters:
//   - domain: The domain to check.
//
// Returns:
//   - bool: True if the domain is an xplorer subdomain, false otherwise.
func IsXplorerSubdomain(domain string) bool {
	match, _ := regexp.MatchString(
		`^([a-z0-9-]){1,48}\.xplorer\.stark$`,
		domain,
	)
	return match
}

// FmtFeltArrayCallData formats an array call data: [len(callData), callData...]
//
// Parameters:
//   - callData: The call data to format.
//
// Returns:
//   - []*felt.Felt: The formatted call data.
func FmtFeltArrayCallData(callData []*felt.Felt) []*felt.Felt {
	return append(
		[]*felt.Felt{(&felt.Felt{}).SetUint64(uint64(len(callData)))},
		callData...,
	)
}

// IsASCII checks if a string contains only ASCII characters.
//
// Parameters:
//   - str: The string to check.
//
// Returns:
//   - bool: True if the string contains only ASCII characters, false otherwise.
func IsASCII(str string) bool {
	asciiRegex := regexp.MustCompile(`^[\x00-\x7F]*$`)
	return asciiRegex.MatchString(str)
}

// IsShortString checks if the length of a string is valid for a short string.
//
// Parameters:
//   - str: The string to check.
//
// Returns:
//   - bool: True if the string is a short string, false otherwise.
func IsShortString(str string) bool {
	return len(str) <= constants.TEXT_TO_FELT_MAX_LEN
}

// AddHexPrefix adds the "0x" prefix to a string if it does not already have it.
//
// Parameters:
//   - str: The string to add the prefix to.
//
// Returns:
//   - string: The string with the "0x" prefix.
func AddHexPrefix(str string) string {
	if strings.HasPrefix(str, "0x") {
		return str
	}
	return "0x" + str
}

// EncodeShortString encodes a string to its hexadecimal representation with a
// "0x" prefix.
//
// Parameters:
//   - str: The string to encode.
//
// Returns:
//   - *felt.Felt: The encoded string.
//   - error: An error if the string is not an ASCII string or is too long.
func EncodeShortString(str string) (*felt.Felt, error) {
	if !IsASCII(str) {
		return nil, fmt.Errorf("%s is not an ASCII string", str)
	}
	if !IsShortString(str) {
		return nil, fmt.Errorf("%s is too long", str)
	}

	hexStr := ""
	for _, char := range str {
		hexStr += fmt.Sprintf("%02x", char)
	}

	return NethermindEthUtils.HexToFelt(AddHexPrefix(hexStr))
}

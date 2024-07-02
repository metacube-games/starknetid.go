package provider

import (
	"context"
	"fmt"
	"regexp"
	"strconv"

	"github.com/NethermindEth/juno/core/felt"
	"github.com/NethermindEth/starknet.go/rpc"
	NethermindEthUtils "github.com/NethermindEth/starknet.go/utils"
	"github.com/metacube-games/starknetid.go/constants"
	"github.com/metacube-games/starknetid.go/types"
	"github.com/metacube-games/starknetid.go/utils"
)

// Provider is a Starknet ID provider.
type Provider struct {
	Client              *rpc.Provider
	ChainId             types.StarknetChainId
	StarknetIdContracts *types.StarknetIdContracts
}

// NewProvider creates a new Provider instance.
//
// Parameters:
//   - provider: the RPC provider.
//   - chainId: the Starknet chain ID.
//   - starknetIdContracts: the Starknet ID contracts. If nil, it will try to
//     fetch the identity and naming contracts from the chain ID.
//
// Returns:
//   - *Provider: the new Provider instance.
//   - error: an error if the provider is nil, the chain ID is empty or the
//     contracts are nil and the identity or naming contracts could not be
//     fetched.
func NewProvider(
	provider *rpc.Provider,
	chainId types.StarknetChainId,
	starknetIdContracts *types.StarknetIdContracts,
) (*Provider, error) {
	if provider == nil {
		return nil, fmt.Errorf("provider is nil")
	}

	if chainId == "" {
		return nil, fmt.Errorf("chainId is empty")
	}

	if starknetIdContracts == nil {
		identityContract, err := utils.GetIdentityContract(chainId)
		if err != nil {
			return nil, fmt.Errorf(
				"failed to get identity contract with chainId %s: %w",
				chainId,
				err,
			)
		}
		namingContract, err := utils.GetNamingContract(chainId)
		if err != nil {
			return nil, fmt.Errorf(
				"failed to get naming contract with chainId %s: %w",
				chainId,
				err,
			)
		}
		starknetIdContracts = &types.StarknetIdContracts{
			IdentityContract: identityContract,
			NamingContract:   namingContract,
		}
	}

	return &Provider{
		Client:              provider,
		StarknetIdContracts: starknetIdContracts,
		ChainId:             chainId,
	}, nil
}

// GetAddressFromStarknetId returns the address for a given .stark domain.
//
// Parameters:
//   - ctx: the context.
//   - domain: the .stark domain (.stark suffix is optional).
//
// Returns:
//   - string: the address.
//   - error: an error if the domain is invalid or the address could not be
//     resolved.
func (p *Provider) GetAddressFromStarkName(
	ctx context.Context,
	domain string,
) (string, error) {
	var contract string
	var err error
	if p.StarknetIdContracts != nil &&
		p.StarknetIdContracts.NamingContract != "" {
		contract = p.StarknetIdContracts.NamingContract
	} else if p.ChainId != "" {
		contract, err = utils.GetNamingContract(p.ChainId)
		if err != nil {
			return "", fmt.Errorf(
				"failed to get naming contract with chainId %s: %w",
				p.ChainId,
				err,
			)
		}
	} else {
		return "", fmt.Errorf(
			"Provider not initialized with chainId or StarknetIdContracts",
		)
	}

	encodedDomain, err := utils.EncodeDomain(domain)
	if err != nil {
		return "", fmt.Errorf("failed to encode domain %s: %w", domain, err)
	}

	// TODO implement retry with URI and hints from error message if needed
	return p.tryResolveDomain(ctx, contract, encodedDomain, []*felt.Felt{})
}

// GetStarkName returns the .stark domain for a given address.
//
// Parameters:
//   - ctx: the context.
//   - address: the address.
//
// Returns:
//   - string: the .stark domain.
//   - error: an error if the address is invalid or the domain could not be
//     resolved.
func (p *Provider) GetStarkName(
	ctx context.Context,
	address string,
) (string, error) {
	var contract string
	var err error
	if p.StarknetIdContracts != nil &&
		p.StarknetIdContracts.NamingContract != "" {
		contract = p.StarknetIdContracts.NamingContract
	} else if p.ChainId != "" {
		contract, err = utils.GetNamingContract(p.ChainId)
		if err != nil {
			return "", fmt.Errorf(
				"failed to get naming contract with chainId %s: %w",
				p.ChainId,
				err,
			)
		}
	} else {
		return "", fmt.Errorf(
			"Provider not initialized with chainId or StarknetIdContracts",
		)
	}

	// TODO implement retry with URI and hints from error message if needed
	return p.tryResolveAddress(ctx, contract, address, []*felt.Felt{})
}

// // GetStarkNames returns the .stark domains for a given list of addresses.
// func (p *Provider) GetStarkNames(
// 	ctx context.Context,
// 	addresses []string,
// 	multicallContract string,
// ) ([]string, error) {
// 	// TODO implement
// 	return nil, fmt.Errorf("not implemented")
// }

// GetStarknetId returns the Starknet ID for a given .stark domain.
//
// Parameters:
//   - ctx: the context.
//   - domain: the .stark domain (.stark suffix is optional).
//
// Returns:
//   - string: the Starknet ID.
//   - error: an error if the domain is invalid or the Starknet ID could not be
//     resolved.
func (p *Provider) GetStarknetId(
	ctx context.Context,
	domain string,
) (string, error) {
	var contract string
	var err error
	if p.StarknetIdContracts != nil &&
		p.StarknetIdContracts.NamingContract != "" {
		contract = p.StarknetIdContracts.NamingContract
	} else if p.ChainId != "" {
		contract, err = utils.GetNamingContract(p.ChainId)
		if err != nil {
			return "", fmt.Errorf(
				"failed to get naming contract with chainId %s: %w",
				p.ChainId,
				err,
			)
		}
	} else {
		return "", fmt.Errorf(
			"Provider not initialized with chainId or StarknetIdContracts",
		)
	}
	contractAddress, err := NethermindEthUtils.HexToFelt(contract)
	if err != nil {
		return "", fmt.Errorf(
			"failed to convert contract address %s: %w",
			contract,
			err,
		)
	}

	encodedDomain, err := utils.EncodeDomain(domain)
	if err != nil {
		return "", fmt.Errorf("failed to encode domain %s: %w", domain, err)
	}

	tx := rpc.FunctionCall{
		ContractAddress: contractAddress,
		EntryPointSelector: NethermindEthUtils.GetSelectorFromNameFelt(
			"domain_to_id",
		),
		Calldata: utils.FmtFeltArrayCallData(encodedDomain),
	}

	result, rpcErr := p.Client.Call(ctx, tx, constants.BLOCK_ID)
	if rpcErr != nil {
		return "", fmt.Errorf("failed to call contract: %w", rpcErr)
	}

	if len(result) != 1 {
		return "", fmt.Errorf("unexpected result length %d", len(result))
	}

	return result[0].Text(10), nil
}

// GetUserData returns the user data for a given Starknet ID, domain or address.
//
// Parameters:
//   - ctx: the context.
//   - idDomainOrAddr: the Starknet ID, .stark domain (.stark suffix is
//     optional) or address.
//   - field: the field name.
//
// Returns:
//   - *felt.Felt: the user data.
//   - error: an error if the Starknet ID, domain or address is invalid or the
//     user data could not be fetched.
func (p *Provider) GetUserData(
	ctx context.Context,
	idDomainOrAddr string,
	field string,
) (*felt.Felt, error) {
	var contract string
	var err error
	if p.StarknetIdContracts != nil &&
		p.StarknetIdContracts.IdentityContract != "" {
		contract = p.StarknetIdContracts.IdentityContract
	} else if p.ChainId != "" {
		contract, err = utils.GetIdentityContract(p.ChainId)
		if err != nil {
			return nil, fmt.Errorf(
				"failed to get identity contract with chainId %s: %w",
				p.ChainId,
				err,
			)
		}
	} else {
		return nil, fmt.Errorf(
			"Provider not initialized with chainId or StarknetIdContracts",
		)
	}
	contractAddress, err := NethermindEthUtils.HexToFelt(contract)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to convert contract address %s: %w",
			contract,
			err,
		)
	}

	idFelt, err := p.checkArguments(ctx, idDomainOrAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to check arguments: %w", err)
	}

	fieldFelt, err := utils.EncodeShortString(field)
	if err != nil {
		return nil, fmt.Errorf("failed to encode field %s: %w", field, err)
	}

	callData := []*felt.Felt{
		idFelt,
		fieldFelt,
		(&felt.Felt{}).SetUint64(0), // domain: 0
	}

	tx := rpc.FunctionCall{
		ContractAddress: contractAddress,
		EntryPointSelector: NethermindEthUtils.GetSelectorFromNameFelt(
			"get_user_data",
		),
		Calldata: callData,
	}

	result, rpcErr := p.Client.Call(ctx, tx, constants.BLOCK_ID)
	if rpcErr != nil {
		return nil, fmt.Errorf("failed to call contract: %w", rpcErr)
	}

	if len(result) != 1 {
		return nil, fmt.Errorf("unexpected result length %d", len(result))
	}

	return result[0], nil
}

// GetExtendedUserData returns the extended user data for a given Starknet ID,
// domain or address.
//
// Parameters:
//   - ctx: the context.
//   - idDomainOrAddr: the Starknet ID, .stark domain (.stark suffix is
//     optional) or address.
//   - field: the field name.
//   - length: the length of the data.
//
// Returns:
//   - []*felt.Felt: the extended user data.
//   - error: an error if the Starknet ID, domain or address is invalid or the
//     extended user data could not be fetched.
func (p *Provider) GetExtendedUserData(
	ctx context.Context,
	idDomainOrAddr string,
	field string,
	length int,
) ([]*felt.Felt, error) {
	var contract string
	var err error
	if p.StarknetIdContracts != nil &&
		p.StarknetIdContracts.IdentityContract != "" {
		contract = p.StarknetIdContracts.IdentityContract
	} else if p.ChainId != "" {
		contract, err = utils.GetIdentityContract(p.ChainId)
		if err != nil {
			return nil, fmt.Errorf(
				"failed to get identity contract with chainId %s: %w",
				p.ChainId,
				err,
			)
		}
	} else {
		return nil, fmt.Errorf(
			"Provider not initialized with chainId or StarknetIdContracts",
		)
	}
	contractAddress, err := NethermindEthUtils.HexToFelt(contract)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to convert contract address %s: %w",
			contract,
			err,
		)
	}

	idFelt, err := p.checkArguments(ctx, idDomainOrAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to check arguments: %w", err)
	}

	fieldFelt, err := utils.EncodeShortString(field)
	if err != nil {
		return nil, fmt.Errorf("failed to encode field %s: %w", field, err)
	}

	callData := []*felt.Felt{
		idFelt,
		fieldFelt,
		(&felt.Felt{}).SetUint64(uint64(length)),
		(&felt.Felt{}).SetUint64(0), // domain: 0
	}

	tx := rpc.FunctionCall{
		ContractAddress: contractAddress,
		EntryPointSelector: NethermindEthUtils.GetSelectorFromNameFelt(
			"get_extended_user_data",
		),
		Calldata: callData,
	}

	result, rpcErr := p.Client.Call(ctx, tx, constants.BLOCK_ID)
	if rpcErr != nil {
		return nil, fmt.Errorf("failed to call contract: %w", rpcErr)
	}

	return result[1:], nil
}

// GetUnboundedUserData returns the unbounded user data for a given Starknet ID,
// domain or address.
//
// Parameters:
//   - ctx: the context.
//   - idDomainOrAddr: the Starknet ID, .stark domain (.stark suffix is
//     optional) or address.
//   - field: the field name.
//
// Returns:
//   - []*felt.Felt: the unbounded user data.
//   - error: an error if the Starknet ID, domain or address is invalid or the
//     unbounded user data could not be fetched.
func (p *Provider) GetUnboundedUserData(
	ctx context.Context,
	idDomainOrAddr string,
	field string,
) ([]*felt.Felt, error) {
	var contract string
	var err error
	if p.StarknetIdContracts != nil &&
		p.StarknetIdContracts.IdentityContract != "" {
		contract = p.StarknetIdContracts.IdentityContract
	} else if p.ChainId != "" {
		contract, err = utils.GetIdentityContract(p.ChainId)
		if err != nil {
			return nil, fmt.Errorf(
				"failed to get identity contract with chainId %s: %w",
				p.ChainId,
				err,
			)
		}
	} else {
		return nil, fmt.Errorf(
			"Provider not initialized with chainId or StarknetIdContracts",
		)
	}
	contractAddress, err := NethermindEthUtils.HexToFelt(contract)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to convert contract address %s: %w",
			contract,
			err,
		)
	}

	idFelt, err := p.checkArguments(ctx, idDomainOrAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to check arguments: %w", err)
	}

	fieldFelt, err := utils.EncodeShortString(field)
	if err != nil {
		return nil, fmt.Errorf("failed to encode field %s: %w", field, err)
	}

	callData := []*felt.Felt{
		idFelt,
		fieldFelt,
		(&felt.Felt{}).SetUint64(0), // domain: 0
	}

	tx := rpc.FunctionCall{
		ContractAddress: contractAddress,
		EntryPointSelector: NethermindEthUtils.GetSelectorFromNameFelt(
			"get_unbounded_user_data",
		),
		Calldata: callData,
	}

	result, rpcErr := p.Client.Call(ctx, tx, constants.BLOCK_ID)
	if rpcErr != nil {
		return nil, fmt.Errorf("failed to call contract: %w", rpcErr)
	}

	return result[1:], nil
}

// GetVerifierData returns the verifier data for a given Starknet ID, domain or
// address.
//
// Parameters:
//   - ctx: the context.
//   - idDomainOrAddr: the Starknet ID, .stark domain (.stark suffix is
//     optional) or address.
//   - field: the field name.
//   - verifier: the verifier contract address. If nil, it will try to fetch the
//     verifier contract from the chain ID.
//
// Returns:
//   - *felt.Felt: the verifier data.
//   - error: an error if the Starknet ID, domain or address is invalid or the
//     verifier data could not be fetched.
func (p *Provider) GetVerifierData(
	ctx context.Context,
	idDomainOrAddr string,
	field string,
	verifier *string,
) (*felt.Felt, error) {
	var contract string
	var err error
	if p.StarknetIdContracts != nil &&
		p.StarknetIdContracts.IdentityContract != "" {
		contract = p.StarknetIdContracts.IdentityContract
	} else if p.ChainId != "" {
		contract, err = utils.GetIdentityContract(p.ChainId)
		if err != nil {
			return nil, fmt.Errorf(
				"failed to get identity contract with chainId %s: %w",
				p.ChainId,
				err,
			)
		}
	} else {
		return nil, fmt.Errorf(
			"Provider not initialized with chainId or StarknetIdContracts",
		)
	}
	contractAddress, err := NethermindEthUtils.HexToFelt(contract)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to convert contract address %s: %w",
			contract,
			err,
		)
	}

	if verifier == nil {
		contract, err = utils.GetVerifierContract(p.ChainId)
		if err != nil {
			return nil, fmt.Errorf(
				"failed to get verifier contract with chainId %s: %w",
				p.ChainId,
				err,
			)
		}
	} else {
		contract = *verifier
	}
	verifierAddress, err := NethermindEthUtils.HexToFelt(contract)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to convert verifier address %s: %w",
			*verifier,
			err,
		)
	}

	idFelt, err := p.checkArguments(ctx, idDomainOrAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to check arguments: %w", err)
	}

	fieldFelt, err := utils.EncodeShortString(field)
	if err != nil {
		return nil, fmt.Errorf("failed to encode field %s: %w", field, err)
	}

	callData := []*felt.Felt{
		idFelt,
		fieldFelt,
		verifierAddress,
		(&felt.Felt{}).SetUint64(0), // domain: 0
	}

	tx := rpc.FunctionCall{
		ContractAddress: contractAddress,
		EntryPointSelector: NethermindEthUtils.GetSelectorFromNameFelt(
			"get_verifier_data",
		),
		Calldata: callData,
	}

	result, rpcErr := p.Client.Call(ctx, tx, constants.BLOCK_ID)
	if rpcErr != nil {
		return nil, fmt.Errorf("failed to call contract: %w", rpcErr)
	}

	if len(result) != 1 {
		return nil, fmt.Errorf("unexpected result length %d", len(result))
	}

	return result[0], nil
}

// GetExtendedVerifierData returns the extended verifier data for a given
// Starknet ID, domain or address.
//
// Parameters:
//   - ctx: the context.
//   - idDomainOrAddr: the Starknet ID, .stark domain (.stark suffix is
//     optional) or address.
//   - field: the field name.
//   - length: the length of the data.
//   - verifier: the verifier contract address. If nil, it will try to fetch the
//     verifier contract from the chain ID.
//
// Returns:
//   - []*felt.Felt: the extended verifier data.
//   - error: an error if the Starknet ID, domain or address is invalid or the
//     extended verifier data could not be fetched.
func (p *Provider) GetExtendedVerifierData(
	ctx context.Context,
	idDomainOrAddr string,
	field string,
	length int,
	verifier *string,
) ([]*felt.Felt, error) {
	var contract string
	var err error
	if p.StarknetIdContracts != nil &&
		p.StarknetIdContracts.IdentityContract != "" {
		contract = p.StarknetIdContracts.IdentityContract
	} else if p.ChainId != "" {
		contract, err = utils.GetIdentityContract(p.ChainId)
		if err != nil {
			return nil, fmt.Errorf(
				"failed to get identity contract with chainId %s: %w",
				p.ChainId,
				err,
			)
		}
	} else {
		return nil, fmt.Errorf(
			"Provider not initialized with chainId or StarknetIdContracts",
		)
	}
	contractAddress, err := NethermindEthUtils.HexToFelt(contract)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to convert contract address %s: %w",
			contract,
			err,
		)
	}

	if verifier == nil {
		contract, err = utils.GetVerifierContract(p.ChainId)
		if err != nil {
			return nil, fmt.Errorf(
				"failed to get verifier contract with chainId %s: %w",
				p.ChainId,
				err,
			)
		}
	} else {
		contract = *verifier
	}
	verifierAddress, err := NethermindEthUtils.HexToFelt(contract)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to convert verifier address %s: %w",
			*verifier,
			err,
		)
	}

	idFelt, err := p.checkArguments(ctx, idDomainOrAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to check arguments: %w", err)
	}

	fieldFelt, err := utils.EncodeShortString(field)
	if err != nil {
		return nil, fmt.Errorf("failed to encode field %s: %w", field, err)
	}

	callData := []*felt.Felt{
		idFelt,
		fieldFelt,
		(&felt.Felt{}).SetUint64(uint64(length)),
		verifierAddress,
		(&felt.Felt{}).SetUint64(0), // domain: 0
	}

	tx := rpc.FunctionCall{
		ContractAddress: contractAddress,
		EntryPointSelector: NethermindEthUtils.GetSelectorFromNameFelt(
			"get_extended_verifier_data",
		),
		Calldata: callData,
	}

	result, rpcErr := p.Client.Call(ctx, tx, constants.BLOCK_ID)
	if rpcErr != nil {
		return nil, fmt.Errorf("failed to call contract: %w", rpcErr)
	}

	return result[1:], nil
}

// GetUnboundedVerifierData returns the unbounded verifier data for a given
// Starknet ID, domain or address.
//
// Parameters:
//   - ctx: the context.
//   - idDomainOrAddr: the Starknet ID, .stark domain (.stark suffix is
//     optional) or address.
//   - field: the field name.
//   - verifier: the verifier contract address. If nil, it will try to fetch the
//     verifier contract from the chain ID.
//
// Returns:
//   - []*felt.Felt: the unbounded verifier data.
//   - error: an error if the Starknet ID, domain or address is invalid or the
//     unbounded verifier data could not be fetched.
func (p *Provider) GetUnboundedVerifierData(
	ctx context.Context,
	idDomainOrAddr string,
	field string,
	verifier *string,
) ([]*felt.Felt, error) {
	var contract string
	var err error
	if p.StarknetIdContracts != nil &&
		p.StarknetIdContracts.IdentityContract != "" {
		contract = p.StarknetIdContracts.IdentityContract
	} else if p.ChainId != "" {
		contract, err = utils.GetIdentityContract(p.ChainId)
		if err != nil {
			return nil, fmt.Errorf(
				"failed to get identity contract with chainId %s: %w",
				p.ChainId,
				err,
			)
		}
	} else {
		return nil, fmt.Errorf(
			"Provider not initialized with chainId or StarknetIdContracts",
		)
	}
	contractAddress, err := NethermindEthUtils.HexToFelt(contract)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to convert contract address %s: %w",
			contract,
			err,
		)
	}

	if verifier == nil {
		contract, err = utils.GetVerifierContract(p.ChainId)
		if err != nil {
			return nil, fmt.Errorf(
				"failed to get verifier contract with chainId %s: %w",
				p.ChainId,
				err,
			)
		}
	} else {
		contract = *verifier
	}
	verifierAddress, err := NethermindEthUtils.HexToFelt(contract)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to convert verifier address %s: %w",
			*verifier,
			err,
		)
	}

	idFelt, err := p.checkArguments(ctx, idDomainOrAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to check arguments: %w", err)
	}

	fieldFelt, err := utils.EncodeShortString(field)
	if err != nil {
		return nil, fmt.Errorf("failed to encode field %s: %w", field, err)
	}

	callData := []*felt.Felt{
		idFelt,
		fieldFelt,
		verifierAddress,
		(&felt.Felt{}).SetUint64(0), // domain: 0
	}

	tx := rpc.FunctionCall{
		ContractAddress: contractAddress,
		EntryPointSelector: NethermindEthUtils.GetSelectorFromNameFelt(
			"get_unbounded_verifier_data",
		),
		Calldata: callData,
	}

	result, rpcErr := p.Client.Call(ctx, tx, constants.BLOCK_ID)
	if rpcErr != nil {
		return nil, fmt.Errorf("failed to call contract: %w", rpcErr)
	}

	return result[1:], nil
}

// GetPfpVerifierData returns the profile picture verifier data for a given
// Starknet ID, domain or address.
//
// Parameters:
//   - ctx: the context.
//   - idDomainOrAddr: the Starknet ID, .stark domain (.stark suffix is
//     optional) or address.
//   - verifier: the verifier contract address. If nil, it will try to fetch the
//     verifier contract from the chain ID.
//
// Returns:
//   - []*felt.Felt: the profile picture verifier data.
//   - error: an error if the Starknet ID, domain or address is invalid or the
//     profile picture verifier data could not be fetched.
func (p *Provider) GetPfpVerifierData(
	ctx context.Context,
	idDomainOrAddr string,
	verifier *string,
) ([]*felt.Felt, error) {
	var contract string
	var err error
	if p.StarknetIdContracts != nil &&
		p.StarknetIdContracts.IdentityContract != "" {
		contract = p.StarknetIdContracts.IdentityContract
	} else if p.ChainId != "" {
		contract, err = utils.GetIdentityContract(p.ChainId)
		if err != nil {
			return nil, fmt.Errorf(
				"failed to get identity contract with chainId %s: %w",
				p.ChainId,
				err,
			)
		}
	} else {
		return nil, fmt.Errorf(
			"Provider not initialized with chainId or StarknetIdContracts",
		)
	}
	contractAddress, err := NethermindEthUtils.HexToFelt(contract)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to convert contract address %s: %w",
			contract,
			err,
		)
	}

	if verifier == nil {
		contract, err = utils.GetPfpVerifierContract(p.ChainId)
		if err != nil {
			return nil, fmt.Errorf(
				"failed to get verifier contract with chainId %s: %w",
				p.ChainId,
				err,
			)
		}
	} else {
		contract = *verifier
	}
	verifierAddress, err := NethermindEthUtils.HexToFelt(contract)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to convert verifier address %s: %w",
			*verifier,
			err,
		)
	}

	idFelt, err := p.checkArguments(ctx, idDomainOrAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to check arguments: %w", err)
	}

	fieldFelt, err := utils.EncodeShortString("nft_pp_contract")
	if err != nil {
		return nil, fmt.Errorf(
			"failed to encode field %s: %w",
			"nft_pp_contract",
			err,
		)
	}

	callData := []*felt.Felt{
		idFelt,
		fieldFelt,
		verifierAddress,
		(&felt.Felt{}).SetUint64(0), // domain: 0
	}

	tx := rpc.FunctionCall{
		ContractAddress: contractAddress,
		EntryPointSelector: NethermindEthUtils.GetSelectorFromNameFelt(
			"get_verifier_data",
		),
		Calldata: callData,
	}

	resultContractData, rpcErr := p.Client.Call(ctx, tx, constants.BLOCK_ID)
	if rpcErr != nil {
		return nil, fmt.Errorf("failed to call contract: %w", rpcErr)
	}

	fieldFelt, err = utils.EncodeShortString("nft_pp_id")
	if err != nil {
		return nil, fmt.Errorf(
			"failed to encode field %s: %w",
			"nft_pp_id",
			err,
		)
	}

	callData = []*felt.Felt{
		idFelt,
		fieldFelt,
		(&felt.Felt{}).SetUint64(2), // length: 2
		verifierAddress,
		(&felt.Felt{}).SetUint64(0), // domain: 0
	}

	tx = rpc.FunctionCall{
		ContractAddress: contractAddress,
		EntryPointSelector: NethermindEthUtils.GetSelectorFromNameFelt(
			"get_extended_verifier_data",
		),
		Calldata: callData,
	}

	resultNftTokenData, rpcErr := p.Client.Call(ctx, tx, constants.BLOCK_ID)
	if rpcErr != nil {
		return nil, fmt.Errorf("failed to call contract: %w", rpcErr)
	}

	return append(
		[]*felt.Felt{(&felt.Felt{}).SetUint64(0)},
		append(
			resultContractData,
			resultNftTokenData[1:]...,
		)...,
	), nil

}

// // GetExtendedPfpVerifierData returns the extended profile data for a given
// // address.
// func (p *Provider) GetProfileData(
// 	ctx context.Context,
// 	address string,
// 	useDefaultPfp bool,
// 	verifier *string,
// 	pfpVerifier *string,
// 	popVerifier *string,
// ) (types.StarkProfile, error) {
// 	// TODO implement
// 	return types.StarkProfile{}, fmt.Errorf("not implemented")
// }

// // GetStarkProfiles returns the profile data for a given list of addresses.
// func (p *Provider) GetStarkProfiles(
// 	ctx context.Context,
// 	addresses []string,
// 	useDefaultPfp bool,
// 	pfpVerifier *string,
// ) ([]types.StarkProfile, error) {
// 	// TODO implement
// 	return nil, fmt.Errorf("not implemented")
// }

// tryResolveDomain tries to resolve a .stark domain to an address.
//
// Parameters:
//   - ctx: the context.
//   - contract: the contract address.
//   - encodedDomain: the encoded domain.
//   - hint: the hint.
//
// Returns:
//   - string: the address.
//   - error: an error if the address could not be resolved.
func (p *Provider) tryResolveDomain(
	ctx context.Context,
	contract string,
	encodedDomain []*felt.Felt,
	hint []*felt.Felt,
) (string, error) {
	contractAddress, err := NethermindEthUtils.HexToFelt(contract)
	if err != nil {
		return "", fmt.Errorf(
			"failed to convert contract address %s: %w",
			contract,
			err,
		)
	}

	tx := rpc.FunctionCall{
		ContractAddress: contractAddress,
		EntryPointSelector: NethermindEthUtils.GetSelectorFromNameFelt(
			"domain_to_address",
		),
		Calldata: append(
			utils.FmtFeltArrayCallData(encodedDomain),
			utils.FmtFeltArrayCallData(hint)...,
		),
	}

	result, rpcErr := p.Client.Call(ctx, tx, constants.BLOCK_ID)
	if rpcErr != nil {
		return "", fmt.Errorf("failed to call contract: %w", rpcErr)
	}

	if len(result) != 1 {
		return "", fmt.Errorf("unexpected result length %d", len(result))
	}

	return result[0].String(), nil
}

// tryResolveAddress tries to resolve an address to a .stark domain.
//
// Parameters:
//   - ctx: the context.
//   - contract: the contract address.
//   - address: the address.
//   - hint: the hint.
//
// Returns:
//   - string: the .stark domain.
//   - error: an error if the domain could not be resolved.
func (p *Provider) tryResolveAddress(
	ctx context.Context,
	contract string,
	address string,
	hint []*felt.Felt,
) (string, error) {
	contractAddress, err := NethermindEthUtils.HexToFelt(contract)
	if err != nil {
		return "", fmt.Errorf(
			"failed to convert contract address %s: %w",
			contract,
			err,
		)
	}

	addressFelt, err := NethermindEthUtils.HexToFelt(address)
	if err != nil {
		return "", fmt.Errorf(
			"failed to convert address %s: %w",
			address,
			err,
		)
	}

	tx := rpc.FunctionCall{
		ContractAddress: contractAddress,
		EntryPointSelector: NethermindEthUtils.GetSelectorFromNameFelt(
			"address_to_domain",
		),
		Calldata: append(
			[]*felt.Felt{addressFelt},
			utils.FmtFeltArrayCallData(hint)...,
		),
	}

	result, rpcErr := p.Client.Call(ctx, tx, constants.BLOCK_ID)
	if rpcErr != nil {
		return "", fmt.Errorf("failed to call contract: %w", rpcErr)
	}

	nbDomains := result[0].Uint64()
	if nbDomains == 0 {
		return "", fmt.Errorf("no domain found for address %s", address)
	}

	return utils.DecodeDomain(result[1:]), nil
}

// checkArguments checks if the given idDomainOrAddr is a Starknet ID, .stark
// domain or address.
//
// Parameters:
//   - ctx: the context.
//   - idDomainOrAddr: the Starknet ID, .stark domain (.stark suffix is
//     optional) or address.
//
// Returns:
//   - *felt.Felt: the Starknet ID.
//   - error: an error if the idDomainOrAddr is invalid.
func (p *Provider) checkArguments(
	ctx context.Context,
	idDomainOrAddr string,
) (*felt.Felt, error) {
	if _, err := strconv.Atoi(idDomainOrAddr); err == nil {
		return (&felt.Felt{}).SetString(idDomainOrAddr)
	}
	if utils.IsStarkDomain(idDomainOrAddr) {
		id, err := p.GetStarknetId(ctx, idDomainOrAddr)
		if err != nil {
			return nil, fmt.Errorf("failed to get Starknet ID: %w", err)
		}
		return (&felt.Felt{}).SetString(id)
	}
	matched, _ := regexp.MatchString(`^[-+]?0x[0-9a-f]+$`, idDomainOrAddr)
	if matched {
		// TODO validate checksum address
		domain, err := p.GetStarkName(
			ctx,
			idDomainOrAddr,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to get Stark name: %w", err)
		}
		id, err := p.GetStarknetId(ctx, domain)
		if err != nil {
			return nil, fmt.Errorf("failed to get Starknet ID: %w", err)
		}
		return (&felt.Felt{}).SetString(id)
	} else {
		return nil, fmt.Errorf("invalid idDomainOrAddr")
	}
}

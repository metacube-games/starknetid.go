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

type Provider struct {
	Client              *rpc.Provider
	ChainId             types.StarknetChainId
	StarknetIdContracts *types.StarknetIdContracts
}

// NewProvider creates a new Provider instance.
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

// // GetUserData returns the user data for a given Starknet ID, domain or address.
// func (p *Provider) GetUserData(
// 	ctx context.Context,
// 	idDomainOrAddr string,
// 	field string,
// ) (string, error) {
// 	// TODO implementation not working yet
// 	return "", fmt.Errorf("not implemented")

// 	// var contract string
// 	// var err error
// 	// if p.StarknetIdContracts != nil &&
// 	// 	p.StarknetIdContracts.IdentityContract != "" {
// 	// 	contract = p.StarknetIdContracts.IdentityContract
// 	// } else if p.ChainId != "" {
// 	// 	contract, err = utils.GetIdentityContract(p.ChainId)
// 	// 	if err != nil {
// 	// 		return "", fmt.Errorf(
// 	// 			"failed to get identity contract with chainId %s: %w",
// 	// 			p.ChainId,
// 	// 			err,
// 	// 		)
// 	// 	}
// 	// } else {
// 	// 	return "", fmt.Errorf(
// 	// 		"Provider not initialized with chainId or StarknetIdContracts",
// 	// 	)
// 	// }
// 	// contractAddress, err := NethermindEthUtils.HexToFelt(contract)
// 	// if err != nil {
// 	// 	return "", fmt.Errorf(
// 	// 		"failed to convert contract address %s: %w",
// 	// 		contract,
// 	// 		err,
// 	// 	)
// 	// }

// 	// id, err := p.checkArguments(ctx, idDomainOrAddr)
// 	// if err != nil {
// 	// 	return "", fmt.Errorf("failed to check arguments: %w", err)
// 	// }
// 	// idFelt, err := (&felt.Felt{}).SetString(id)
// 	// if err != nil {
// 	// 	return "", fmt.Errorf("failed to convert id %s: %w", id, err)
// 	// }

// 	// fieldFelt, err := utils.EncodeShortString(field)
// 	// if err != nil {
// 	// 	return "", fmt.Errorf("failed to encode field %s: %w", field, err)
// 	// }

// 	// callData := []*felt.Felt{
// 	// 	idFelt,
// 	// 	fieldFelt,
// 	// 	(&felt.Felt{}).SetUint64(0),
// 	// }

// 	// tx := rpc.FunctionCall{
// 	// 	ContractAddress: contractAddress,
// 	// 	EntryPointSelector: NethermindEthUtils.GetSelectorFromNameFelt(
// 	// 		"get_user_data",
// 	// 	),
// 	// 	Calldata: callData,
// 	// }

// 	// result, rpcErr := p.Client.Call(ctx, tx, constants.BLOCK_ID)
// 	// if rpcErr != nil {
// 	// 	return "", fmt.Errorf("failed to call contract: %w", rpcErr)
// 	// }

// 	// fmt.Printf("result: %v\n", result)

// 	// return "", nil
// }

// // GetExtendedUserData returns the extended user data for a given Starknet ID,
// // domain or address.
// func (p *Provider) GetExtendedUserData(
// 	ctx context.Context,
// 	idDomainOrAddr string,
// 	field string,
// 	length int,
// ) ([]string, error) {
// 	// TODO implement
// 	return nil, fmt.Errorf("not implemented")
// }

// // GetUnboundedUserData returns the unbounded user data for a given Starknet ID,
// // domain or address.
// func (p *Provider) GetUnboundedUserData(
// 	ctx context.Context,
// 	idDomainOrAddr string,
// 	field string,
// ) ([]string, error) {
// 	// TODO implement
// 	return nil, fmt.Errorf("not implemented")
// }

// // GetVerifierData returns the verifier data for a given Starknet ID, domain or
// // address.
// func (p *Provider) GetVerifierData(
// 	ctx context.Context,
// 	idDomainOrAddr string,
// 	field string,
// 	verifier *string,
// ) (string, error) {
// 	// TODO implement
// 	return "", fmt.Errorf("not implemented")
// }

// // GetExtendedVerifierData returns the extended verifier data for a given
// // Starknet ID, domain or address.
// func (p *Provider) GetExtendedVerifierData(
// 	ctx context.Context,
// 	idDomainOrAddr string,
// 	field string,
// 	length int,
// 	verifier *string,
// ) ([]string, error) {
// 	// TODO implement
// 	return nil, fmt.Errorf("not implemented")
// }

// // GetUnboundedVerifierData returns the unbounded verifier data for a given
// // Starknet ID, domain or address.
// func (p *Provider) GetUnboundedVerifierData(
// 	ctx context.Context,
// 	idDomainOrAddr string,
// 	field string,
// 	verifier *string,
// ) ([]string, error) {
// 	// TODO implement
// 	return nil, fmt.Errorf("not implemented")
// }

// // GetPfpVerifierData returns the profile picture verifier data for a given
// // Starknet ID, domain or address.
// func (p *Provider) GetPfpVerifierData(
// 	ctx context.Context,
// 	idDomainOrAddr string,
// 	verifier *string,
// ) (string, error) {
// 	// TODO implement
// 	return "", fmt.Errorf("not implemented")
// }

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
func (p *Provider) checkArguments(
	ctx context.Context,
	idDomainOrAddr string,
) (string, error) {
	if _, err := strconv.Atoi(idDomainOrAddr); err == nil {
		return idDomainOrAddr, nil
	}
	if utils.IsStarkDomain(idDomainOrAddr) {
		id, err := p.GetStarknetId(
			ctx,
			idDomainOrAddr,
		)
		if err != nil {
			return "", fmt.Errorf("failed to get Starknet ID: %w", err)
		}
		return id, nil
	}
	matched, _ := regexp.MatchString(`^[-+]?0x[0-9a-f]+$`, idDomainOrAddr)
	if matched {
		// TODO validate checksum address
		domain, err := p.GetStarkName(
			ctx,
			idDomainOrAddr,
		)
		if err != nil {
			return "", fmt.Errorf("failed to get Stark name: %w", err)
		}
		return p.GetStarknetId(ctx, domain)
	} else {
		return "", fmt.Errorf("invalid idDomainOrAddr")
	}
}

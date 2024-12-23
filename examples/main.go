package main

import (
	"context"
	"fmt"

	"github.com/NethermindEth/starknet.go/rpc"
	"github.com/metacube-games/starknetid.go/constants"
	"github.com/metacube-games/starknetid.go/provider"
)

const (
	RPC_URL          = "https://starknet-mainnet.public.blastapi.io/rpc/v0_7"
	METACUBE_ADDRESS = "0x2ba4ea61d80d1a60adf03150b7634af5fee6f4b3167d915ab8cce2be3ac2023"
	METACUBE_DOMAIN  = "metacube.stark"
	METACUBE_ID      = "899148099505"

	FRICOBEN_ADDRESS         = "0x061b6c0a78f9edf13cea17b50719f3344533fadd470b8cb29c2b4318014f52d3"
	FRICOBEN_DOMAIN          = "fricoben.stark"
	FRICOBEN_NFT_PP_CONTRACT = "0x3ab1124ef9ec3a2f2b1d9838f9066f9a894483d40b33390dda8d85c01a315a3"
)

var (
	METACUBE_NAME_VERIFIER_CONTRACT   = "0x06ac597f8116f886fa1c97a23fa4e08299975ecaf6b598873ca6792b9bbfb678"
	FRICOBEN_NFT_PP_CONTRACT_VERIFIER = "0x070aaa20ec4a46da57c932d9fd89ca5e6bb9ca3188d3df361a32306aff7d59c7"
)

func main() {
	// Step 1: Create a new RPC provider client
	client, err := rpc.NewProvider(RPC_URL)
	if err != nil {
		panic(err)
	}

	// Step 2: Create a new Starknet.id provider
	provider, err := provider.NewProvider(client, constants.SN_MAIN, nil)
	if err != nil {
		panic(err)
	}

	// Step 3: Interact with the Starknet.id protocol

	// Get address from Stark name
	address, err := provider.GetAddressFromStarkName(
		context.Background(),
		METACUBE_DOMAIN,
	)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Address from Stark name: %s\n", address)

	// Get Stark name from address
	starkName, err := provider.GetStarkName(
		context.Background(),
		METACUBE_ADDRESS,
	)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Stark name from address: %s\n", starkName)

	// Get Starknet ID from Stark name
	starknetID, err := provider.GetStarknetId(
		context.Background(),
		METACUBE_DOMAIN,
	)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Starknet ID from Stark name: %s\n", starknetID)

	// Get user data from Starknet ID, domain or address
	userData, err := provider.GetUserData(
		context.Background(),
		METACUBE_ADDRESS,
		"starknet",
	)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Starknet field from user data: %s\n", userData.String())

	// Get extended user data from Starknet ID, domain or address
	extendedUserData, err := provider.GetExtendedUserData(
		context.Background(),
		METACUBE_ADDRESS,
		"starknet",
		1,
	)
	if err != nil {
		panic(err)
	}
	if len(extendedUserData) != 1 {
		panic("Invalid extended user data length")
	}
	fmt.Printf(
		"Starknet field from extended user data: %s\n",
		extendedUserData[0].String(),
	)

	// Get unbounded user data from Starknet ID, domain or address
	unboundedUserData, err := provider.GetUnboundedUserData(
		context.Background(),
		METACUBE_ADDRESS,
		"starknet",
	)
	if err != nil {
		panic(err)
	}
	if len(unboundedUserData) != 1 {
		panic("Invalid unbounded user data length")
	}
	fmt.Printf(
		"Starknet field from unbounded user data: %s\n",
		unboundedUserData[0].String(),
	)

	// Get verifier data from Starknet ID, domain or address
	verifierData, err := provider.GetVerifierData(
		context.Background(),
		METACUBE_ADDRESS,
		"name",
		&METACUBE_NAME_VERIFIER_CONTRACT,
	)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Verifier data from Starknet ID: %s\n", verifierData.String())

	// Get extended verifier data from Starknet ID, domain or address
	extendedVerifierData, err := provider.GetExtendedVerifierData(
		context.Background(),
		METACUBE_ADDRESS,
		"name",
		1,
		&METACUBE_NAME_VERIFIER_CONTRACT,
	)
	if err != nil {
		panic(err)
	}
	if len(extendedVerifierData) != 1 {
		panic("Invalid extended verifier data length")
	}
	fmt.Printf(
		"Verifier data from extended verifier data: %s\n",
		extendedVerifierData[0].String(),
	)

	// Get unbouded verifier data from Starknet ID, domain or address
	unboundedVerifierData, err := provider.GetUnboundedVerifierData(
		context.Background(),
		METACUBE_ADDRESS,
		"name",
		&METACUBE_NAME_VERIFIER_CONTRACT,
	)
	if err != nil {
		panic(err)
	}
	if len(unboundedVerifierData) != 1 {
		panic("Invalid unbounded verifier data length")
	}
	fmt.Printf(
		"Verifier data from unbounded verifier data: %s\n",
		unboundedVerifierData[0].String(),
	)

	// Get profile picture verifier data from Starknet ID, domain or address
	ppVerifierData, err := provider.GetPfpVerifierData(
		context.Background(),
		FRICOBEN_DOMAIN,
		&FRICOBEN_NFT_PP_CONTRACT_VERIFIER,
	)
	if err != nil {
		panic(err)
	}
	fmt.Printf(
		"Profile picture verifier data: %v\n",
		ppVerifierData,
	)

	// Get Stark profile from the address
	starkProfile, err := provider.GetProfileData(
		context.Background(),
		FRICOBEN_ADDRESS,
		true,
		nil,
		nil,
		nil,
	)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Stark profile: %v\n", starkProfile)

	// Get Stark profile of multiple addresses
	starkProfiles, err := provider.GetStarkProfiles(
		context.Background(),
		[]string{METACUBE_ADDRESS, FRICOBEN_ADDRESS},
		true,
		nil,
	)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Stark profiles: %v\n", starkProfiles)
}

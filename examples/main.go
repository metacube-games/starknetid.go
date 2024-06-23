package main

import (
	"context"

	"github.com/NethermindEth/starknet.go/rpc"
	"github.com/metacube-games/starknetid.go/constants"
	"github.com/metacube-games/starknetid.go/provider"
)

const (
	RPC_URL          = "https://starknet-mainnet.public.blastapi.io/rpc/v0_7"
	METACUBE_ADDRESS = "0x2ba4ea61d80d1a60adf03150b7634af5fee6f4b3167d915ab8cce2be3ac2023"
	METACUBE_DOMAIN  = "metacube.stark"
	METACUBE_ID      = "899148099505"
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
	address, err := provider.GetAddressFromStarkName(context.Background(), METACUBE_DOMAIN)
	if err != nil {
		panic(err)
	}
	println("Address from Stark name:", address)

	// Get Stark name from address
	starkName, err := provider.GetStarkName(context.Background(), METACUBE_ADDRESS)
	if err != nil {
		panic(err)
	}
	println("Stark name from address:", starkName)

	// Get Starknet ID from Stark name
	starknetID, err := provider.GetStarknetId(context.Background(), METACUBE_DOMAIN)
	if err != nil {
		panic(err)
	}
	println("Starknet ID from Stark name:", starknetID)
}

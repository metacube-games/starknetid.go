package provider

import (
	"context"
	"testing"

	"github.com/NethermindEth/starknet.go/rpc"
	"github.com/metacube-games/starknetid.go/constants"
	"github.com/metacube-games/starknetid.go/types"
)

const (
	RPC_URL          = "https://starknet-mainnet.public.blastapi.io/rpc/v0_7"
	METACUBE_ADDRESS = "0x2ba4ea61d80d1a60adf03150b7634af5fee6f4b3167d915ab8cce2be3ac2023"
	METACUBE_DOMAIN  = "metacube.stark"
	METACUBE_ID      = "899148099505"
)

func createProvider() (*Provider, error) {
	client, err := rpc.NewProvider(RPC_URL)
	if err != nil {
		return nil, err
	}
	return NewProvider(client, constants.SN_MAIN, nil)
}

func TestNewProvider(t *testing.T) {
	_, err := NewProvider(nil, constants.SN_MAIN, nil)
	if err == nil {
		t.Error("Expected error but got nil")
	}

	client, err := rpc.NewProvider(RPC_URL)
	if err != nil {
		t.Error(err)
	}

	p, err := NewProvider(client, constants.SN_MAIN, nil)
	if err != nil {
		t.Errorf("Expected nil but got %v", err)
	}
	if p == nil {
		t.Error("Expected provider but got nil")
	}

	_, err = NewProvider(client, "wrondId", nil)
	if err == nil {
		t.Error("Expected error but got nil")
	}

	_, err = NewProvider(client, constants.SN_MAIN, &types.StarknetIdContracts{
		IdentityContract: constants.IDENTITY_CONTRACT_SN_MAIN,
		NamingContract:   constants.NAMING_CONTRACT_SN_MAIN,
	})
	if err != nil {
		t.Errorf("Expected nil but got %v", err)
	}
}

func TestGetAddressFromStarkName(t *testing.T) {
	p, err := createProvider()
	if err != nil {
		t.Error(err)
	}

	address, err := p.GetAddressFromStarkName(
		context.Background(),
		METACUBE_DOMAIN,
	)
	if err != nil {
		t.Error(err)
	}
	if address != METACUBE_ADDRESS {
		t.Errorf(
			"Expected %s but got %s",
			METACUBE_ADDRESS,
			address,
		)
	}
}

func TestGetStarkName(t *testing.T) {
	p, err := createProvider()
	if err != nil {
		t.Error(err)
	}

	starkName, err := p.GetStarkName(
		context.Background(),
		METACUBE_ADDRESS,
	)
	if err != nil {
		t.Error(err)
	}
	if starkName != METACUBE_DOMAIN {
		t.Errorf("Expected metacube.stark but got %s", starkName)
	}
}

func TestGetStarknetId(t *testing.T) {
	p, err := createProvider()
	if err != nil {
		t.Error(err)
	}

	starknetId, err := p.GetStarknetId(
		context.Background(),
		METACUBE_DOMAIN,
	)
	if err != nil {
		t.Error(err)
	}
	if starknetId != METACUBE_ID {
		t.Errorf("Expected %s but got %s", METACUBE_ID, starknetId)
	}
}

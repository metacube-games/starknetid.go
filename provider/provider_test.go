package provider

import (
	"context"
	"testing"

	"github.com/NethermindEth/starknet.go/rpc"
	"github.com/metacube-games/starknetid.go/constants"
	"github.com/metacube-games/starknetid.go/types"
)

const (
	RPC_URL            = "https://starknet-mainnet.public.blastapi.io/rpc/v0_7"
	METACUBE_ADDRESS   = "0x2ba4ea61d80d1a60adf03150b7634af5fee6f4b3167d915ab8cce2be3ac2023"
	METACUBE_DOMAIN    = "metacube.stark"
	METACUBE_ID        = "899148099505"
	METACUBE_NAME_DATA = "0x4c81b30ba350e0b28880951cb656abc37cfd78b343d993af79edd6f13d96905"

	FRICOBEN_ADDRESS         = "0x061b6c0a78f9edf13cea17b50719f3344533fadd470b8cb29c2b4318014f52d3"
	FRICOBEN_DOMAIN          = "fricoben.stark"
	FRICOBEN_NFT_PP_CONTRACT = "0x3ab1124ef9ec3a2f2b1d9838f9066f9a894483d40b33390dda8d85c01a315a3"

	TEST_BRAAVOS_ADDRESS = "0x0191ae0a520af918d4e218e254946f67486f090f4c52411476544c7a4471f6d2"
	TEST_BRAAVOS_DOMAIN  = "test.braavos.stark"
)

var (
	METACUBE_NAME_VERIFIER_CONTRACT   = "0x06ac597f8116f886fa1c97a23fa4e08299975ecaf6b598873ca6792b9bbfb678"
	FRICOBEN_NFT_PP_CONTRACT_VERIFIER = "0x070aaa20ec4a46da57c932d9fd89ca5e6bb9ca3188d3df361a32306aff7d59c7"
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
		t.Errorf("Expected %s but got %s", METACUBE_DOMAIN, starkName)
	}
}

func TestGetStarkNames(t *testing.T) {
	p, err := createProvider()
	if err != nil {
		t.Error(err)
	}

	starkNames, err := p.GetStarkNames(
		context.Background(),
		[]string{METACUBE_ADDRESS, TEST_BRAAVOS_ADDRESS},
		nil,
	)
	if err != nil {
		t.Error(err)
	}
	if len(starkNames) != 2 {
		t.Errorf("Expected 2 but got %d", len(starkNames))
	}
	if starkNames[0] != METACUBE_DOMAIN {
		t.Errorf("Expected %s but got %s", METACUBE_DOMAIN, starkNames[0])
	}
	if starkNames[1] != TEST_BRAAVOS_DOMAIN {
		t.Errorf("Expected %s but got %s", TEST_BRAAVOS_DOMAIN, starkNames[1])
	}

	starkNames, err = p.GetStarkNames(
		context.Background(),
		[]string{
			// random address with no stark name
			"0x0302de76464d4e2447F2d1831fb0A1AF101B18F80964fCfff1aD831C0A92e1fD",
			TEST_BRAAVOS_ADDRESS,
		},
		nil,
	)
	if err != nil {
		t.Error(err)
	}
	if len(starkNames) != 2 {
		t.Errorf("Expected 2 but got %d", len(starkNames))
	}
	if starkNames[0] != "" {
		t.Errorf("Expected empty string but got %s", starkNames[0])
	}
	if starkNames[1] != TEST_BRAAVOS_DOMAIN {
		t.Errorf("Expected %s but got %s", TEST_BRAAVOS_DOMAIN, starkNames[1])
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

func TestGetUserData(t *testing.T) {
	p, err := createProvider()
	if err != nil {
		t.Error(err)
	}

	userData, err := p.GetUserData(
		context.Background(),
		METACUBE_ADDRESS,
		"starknet",
	)
	if err != nil {
		t.Error(err)
	}
	if userData.String() != METACUBE_ADDRESS {
		t.Errorf("Expected %s but got %s", METACUBE_ADDRESS, userData.String())
	}
}

func TestGetExtendedUserData(t *testing.T) {
	p, err := createProvider()
	if err != nil {
		t.Error(err)
	}

	extendedUserData, err := p.GetExtendedUserData(
		context.Background(),
		METACUBE_ADDRESS,
		"starknet",
		3,
	)
	if err != nil {
		t.Error(err)
	}
	if extendedUserData[0].String() != METACUBE_ADDRESS {
		t.Errorf(
			"Expected %s but got %s",
			METACUBE_ADDRESS,
			extendedUserData[0].String(),
		)
	}
	if extendedUserData[1].String() != "0x0" {
		t.Errorf(
			"Expected empty string but got %s",
			extendedUserData[1].String(),
		)
	}
	if extendedUserData[2].String() != "0x0" {
		t.Errorf(
			"Expected empty string but got %s",
			extendedUserData[2].String(),
		)
	}
}

func TestGetUnboundedUserData(t *testing.T) {
	p, err := createProvider()
	if err != nil {
		t.Error(err)
	}

	unboundedUserData, err := p.GetUnboundedUserData(
		context.Background(),
		METACUBE_ADDRESS,
		"starknet",
	)
	if err != nil {
		t.Error(err)
	}
	if len(unboundedUserData) != 1 {
		t.Errorf("Expected 1 but got %d", len(unboundedUserData))
	}
	if unboundedUserData[0].String() != METACUBE_ADDRESS {
		t.Errorf(
			"Expected %s but got %s",
			METACUBE_ADDRESS,
			unboundedUserData[0].String(),
		)
	}
}

func TestGetVerifierData(t *testing.T) {
	p, err := createProvider()
	if err != nil {
		t.Error(err)
	}

	verifierData, err := p.GetVerifierData(
		context.Background(),
		METACUBE_ADDRESS,
		"name",
		&METACUBE_NAME_VERIFIER_CONTRACT,
	)
	if err != nil {
		t.Error(err)
	}
	if verifierData.String() != METACUBE_NAME_DATA {
		t.Errorf(
			"Expected %s but got %s",
			METACUBE_NAME_DATA,
			verifierData.String(),
		)
	}
}

func TestGetExtendedVerifierData(t *testing.T) {
	p, err := createProvider()
	if err != nil {
		t.Error(err)
	}

	extendedVerifierData, err := p.GetExtendedVerifierData(
		context.Background(),
		METACUBE_ADDRESS,
		"name",
		3,
		&METACUBE_NAME_VERIFIER_CONTRACT,
	)
	if err != nil {
		t.Error(err)
	}
	if extendedVerifierData[0].String() != METACUBE_NAME_DATA {
		t.Errorf(
			"Expected %s but got %s",
			METACUBE_NAME_DATA,
			extendedVerifierData[0].String(),
		)
	}
	if extendedVerifierData[1].String() != "0x0" {
		t.Errorf(
			"Expected empty string but got %s",
			extendedVerifierData[1].String(),
		)
	}
	if extendedVerifierData[2].String() != "0x0" {
		t.Errorf(
			"Expected empty string but got %s",
			extendedVerifierData[2].String(),
		)
	}
}

func TestGetUnboundedVerifierData(t *testing.T) {
	p, err := createProvider()
	if err != nil {
		t.Error(err)
	}

	unboundedVerifierData, err := p.GetUnboundedVerifierData(
		context.Background(),
		METACUBE_ADDRESS,
		"name",
		&METACUBE_NAME_VERIFIER_CONTRACT,
	)
	if err != nil {
		t.Error(err)
	}
	if len(unboundedVerifierData) != 1 {
		t.Errorf("Expected 1 but got %d", len(unboundedVerifierData))
	}
	if unboundedVerifierData[0].String() != METACUBE_NAME_DATA {
		t.Errorf(
			"Expected %s but got %s",
			METACUBE_NAME_DATA,
			unboundedVerifierData[0].String(),
		)
	}
}

func TestGetPfpVerifierData(t *testing.T) {
	p, err := createProvider()
	if err != nil {
		t.Error(err)
	}

	pfpVerifierData, err := p.GetPfpVerifierData(
		context.Background(),
		FRICOBEN_DOMAIN,
		&FRICOBEN_NFT_PP_CONTRACT_VERIFIER,
	)
	if err != nil {
		t.Error(err)
	}
	if len(pfpVerifierData) != 4 {
		t.Errorf("Expected 4 but got %d", len(pfpVerifierData))
	}
	if pfpVerifierData[0].String() != "0x0" {
		t.Errorf(
			"Expected empty string but got %s",
			pfpVerifierData[0].String(),
		)
	}
	if pfpVerifierData[1].String() != FRICOBEN_NFT_PP_CONTRACT {
		t.Errorf(
			"Expected %s but got %s",
			FRICOBEN_NFT_PP_CONTRACT,
			pfpVerifierData[1].String(),
		)
	}
	if pfpVerifierData[2].String() != "0x1b99" {
		t.Errorf(
			"Expected 0x1b99 but got %s",
			pfpVerifierData[2].String(),
		)
	}
	if pfpVerifierData[3].String() != "0x0" {
		t.Errorf(
			"Expected empty string but got %s",
			pfpVerifierData[3].String(),
		)
	}
}

package types

type StarknetChainId string

type StarknetIdContracts struct {
	IdentityContract string
	NamingContract   string
}

type StarkProfile struct {
	Name              string  `json:"name"`
	Id                uint64  `json:"id"`
	ProfilePicture    *string `json:"profilePicture"`
	Discord           *string `json:"discord"`
	Twitter           *string `json:"twitter"`
	Github            *string `json:"github"`
	ProofOfPersonhood bool    `json:"proofOfPersonhood"`
}

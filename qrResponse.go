package identity

type QRRegistrationResponse struct {
	Type string             `json:"type"`
	Data QRRegistrationData `json:"data"`
}

type QRRegistrationData struct {
	ProveIdentityParams ProveIdentityParams `json:"proveIdentityParams"`
	RegisterProofParams RegisterProofParams `json:"registerProofParams"`
}

type ProveIdentityParams struct {
	IssuingAuthority  string `json:"issuingAuthority"`
	DocumentNullifier string `json:"documentNullifier"`
	Commitment        string `json:"commitment"`
}

type RegisterProofParams struct {
	A                []string         `json:"a"`
	B                [][]string       `json:"b"`
	C                []string         `json:"c"`
	Inputs           []string         `json:"inputs"`
	StatesMerkleData StatesMerkleData `json:"statesMerkleData"`
}

type StatesMerkleData struct {
	MerkleProof        []string `json:"merkleProof"`
	CreatedAtTimestamp string   `json:"createdAtTimestamp"`
	IssuerState        string   `json:"issuerState"`
	IssuerID           string   `json:"issuerId"`
}

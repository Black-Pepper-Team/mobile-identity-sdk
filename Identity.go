package identity

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strconv"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi"
	circuits "github.com/iden3/go-circuits/v2"
	core "github.com/iden3/go-iden3-core/v2"
	"github.com/iden3/go-iden3-core/v2/w3c"
	babyjub "github.com/iden3/go-iden3-crypto/babyjub"
	"github.com/iden3/go-iden3-crypto/constants"
	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/iden3/go-rapidsnark/types"
	"github.com/rarimo/go-jwz"
	merkletree "github.com/rarimo/go-merkletree"
	merkletree_db_memory "github.com/rarimo/go-merkletree/db/memory"
	merklize "github.com/rarimo/go-schema-processor/merklize"
	verifiable "github.com/rarimo/go-schema-processor/verifiable"
	"golang.org/x/crypto/sha3"
)

type Identity struct {
	did       *w3c.DID
	secretKey *babyjub.PrivateKey

	treeState *TreeState

	authClaim                 *core.Claim
	authClaimIncProofSiblings []*merkletree.Hash
	authClaimNonRevProof      *merkletree.Proof

	stateProvider StateProvider
}

func Load(
	secretKeyHex string,
	stateProvider StateProvider,
) (*Identity, error) {
	rawSecretKey, err := hex.DecodeString(secretKeyHex)
	if err != nil {
		return nil, fmt.Errorf("error decoding secret key: %v", err)
	}

	secretKey := babyjub.PrivateKey(rawSecretKey)

	publickey := secretKey.Public()

	slotA := core.ElemBytes{}
	if err := slotA.SetInt(publickey.X); err != nil {
		return nil, fmt.Errorf("error setting slotA: %v", err)
	}

	slotB := core.ElemBytes{}
	if err := slotB.SetInt(publickey.Y); err != nil {
		return nil, fmt.Errorf("error setting slotB: %v", err)
	}

	authClaim, err := core.NewClaim(
		core.AuthSchemaHash,
		core.WithIndexData(slotA, slotB),
		core.WithRevocationNonce(0),
	)
	if err != nil {
		return nil, fmt.Errorf("error creating auth claim: %v", err)
	}

	authHashIndex, authHashValue, err := authClaim.HiHv()
	if err != nil {
		return nil, fmt.Errorf("error getting auth claim HiHv: %v", err)

	}

	claimsTreeDB := merkletree_db_memory.NewMemoryStorage().WithPrefix([]byte("claims"))
	claimsTree, err := merkletree.NewMerkleTree(claimsTreeDB, 32)
	if err != nil {
		return nil, fmt.Errorf("error creating claims tree: %v", err)
	}

	revocationsTreeDB := merkletree_db_memory.NewMemoryStorage().WithPrefix([]byte("revocations"))
	revocationsTree, err := merkletree.NewMerkleTree(revocationsTreeDB, 32)
	if err != nil {
		return nil, fmt.Errorf("error creating revocations tree: %v", err)
	}

	rootsTreeDB := merkletree_db_memory.NewMemoryStorage().WithPrefix([]byte("roots"))
	rootsTree, err := merkletree.NewMerkleTree(rootsTreeDB, 32)
	if err != nil {
		return nil, fmt.Errorf("error creating roots tree: %v", err)
	}

	claimsTree.Add(authHashIndex, authHashValue)

	claimsTreeRoot := claimsTree.Root()
	revocationsTreeRoot := revocationsTree.Root()
	rootsTreeRoot := rootsTree.Root()

	idenState, err := core.IdenState(claimsTreeRoot.BigInt(), revocationsTreeRoot.BigInt(), rootsTreeRoot.BigInt())
	if err != nil {
		return nil, fmt.Errorf("error creating iden state: %v", err)
	}

	did, err := core.NewDIDFromIdenState([2]byte{0x1, 0x0}, idenState)
	if err != nil {
		return nil, fmt.Errorf("error creating did: %v", err)
	}

	authClaimIncProof, _, err := claimsTree.GenerateProof(authHashIndex, claimsTreeRoot)
	if err != nil {
		return nil, fmt.Errorf("error creating auth claim inc proof: %v", err)
	}

	authClaimIncProofSiblings := extendHashes(authClaimIncProof.AllSiblings(), 40)

	authClaimNonRevProof, _, err := revocationsTree.GenerateProof(authHashIndex, revocationsTreeRoot)
	if err != nil {
		return nil, fmt.Errorf("error creating auth claim non rev proof: %v", err)
	}

	stateHash, err := merkletree.HashElems(claimsTreeRoot.BigInt(), revocationsTreeRoot.BigInt(), rootsTreeRoot.BigInt())
	if err != nil {
		return nil, fmt.Errorf("error creating state hash: %v", err)
	}

	return &Identity{
		authClaim: authClaim,
		did:       did,
		secretKey: &secretKey,
		treeState: &TreeState{
			State:           stateHash,
			ClaimsRoot:      claimsTreeRoot,
			RevocationsRoot: revocationsTreeRoot,
			RootsRoot:       rootsTreeRoot,
		},
		authClaimIncProofSiblings: authClaimIncProofSiblings,
		authClaimNonRevProof:      authClaimNonRevProof,
		stateProvider:             stateProvider,
	}, nil
}

func (i *Identity) DID() string {
	return i.did.String()
}

func (i *Identity) GetID() (string, error) {
	id, err := core.IDFromDID(*i.did)
	if err != nil {
		return "", fmt.Errorf("unable to get id from identity did: %v", err)
	}

	return id.BigInt().String(), nil
}

func (i *Identity) initVerifiableCredentials(offerData []byte) ([]*verifiable.W3CCredential, error) {
	offer := new(ClaimOfferResponse)
	if err := json.Unmarshal(offerData, &offer); err != nil {
		return nil, fmt.Errorf("error unmarshaling offer: %v", err)
	}

	credentials := make([]*verifiable.W3CCredential, len(offer.Body.Credentials))

	for index := 0; index < len(offer.Body.Credentials); index++ {
		claimDetails := ClaimDetails{
			Id:        offer.Identifier,
			Typ:       offer.Typ,
			ClaimType: "https://iden3-communication.io/credentials/1.0/fetch-request",
			ThreadID:  offer.ThreadID,
			Body: ClaimDetailsBody{
				Id: offer.Body.Credentials[index].Identifier,
			},
			From: offer.To,
			To:   offer.From,
		}

		claimDetailsJson, err := json.Marshal(claimDetails)
		if err != nil {
			return nil, fmt.Errorf("error matshaling claim details: %v", err)
		}

		jwzToken, err := i.GenerateJWZ(claimDetailsJson)
		if err != nil {
			return nil, fmt.Errorf("error generating jwz: %v", err)
		}

		response, err := http.Post(offer.Body.Url, "application/json", bytes.NewBuffer([]byte(jwzToken)))
		if err != nil {
			return nil, fmt.Errorf("error posting response: %v", err)
		}

		body, err := io.ReadAll(response.Body)
		if err != nil {
			return nil, fmt.Errorf("error reading response body: %v", err)
		}

		vsResponse := new(VSResponse)
		if err := json.Unmarshal(body, &vsResponse); err != nil {
			return nil, fmt.Errorf("error unmarshaling response: %v", err)
		}

		credentials[index] = &vsResponse.Body.Credential
	}

	return credentials, nil
}

func (i *Identity) PrepareAuth2Inputs(hash []byte, circuitID circuits.CircuitID) ([]byte, error) {
	messageHash := new(big.Int).SetBytes(hash)

	signature := i.secretKey.SignPoseidon(messageHash)

	userId, err := i.GetID()
	if err != nil {
		return nil, fmt.Errorf("error getting user id: %v", err)
	}

	gistProofInfoRaw, err := i.stateProvider.GetGISTProof(i.DID())
	if err != nil {
		return nil, fmt.Errorf("error getting gist proof from state: %v", err)
	}

	gistProofInfo := new(GISTProofInfo)
	if err := json.Unmarshal(gistProofInfoRaw, &gistProofInfo); err != nil {
		return nil, fmt.Errorf("error unmarshaling gist proof: %v", err)
	}

	gistProof, err := gistProofInfo.GetProof()
	if err != nil {
		return nil, fmt.Errorf("error getting gist proof: %v", err)
	}

	globalNodeAux := i.getNodeAuxValue(gistProof.Proof)
	nodeAuxAuth := i.getNodeAuxValue(i.authClaimNonRevProof)

	auth2Inputs := AuthV2CircuitInputs{
		GenesisID:               userId,
		ProfileNonce:            "0",
		AuthClaim:               i.authClaim,
		AuthClaimMtp:            i.authClaimIncProofSiblings,
		AuthClaimNonRevMtp:      prepareSiblings(i.authClaimNonRevProof.Siblings, 40),
		AuthClaimNonRevMtpAuxHi: &nodeAuxAuth.key,
		AuthClaimNonRevMtpAuxHv: &nodeAuxAuth.value,
		AuthClaimNonRevMtpNoAux: nodeAuxAuth.noAux,
		Challenge:               messageHash.String(),
		ChallengeSignatureR8X:   signature.R8.X.String(),
		ChallengeSignatureR8Y:   signature.R8.Y.String(),
		ChallengeSignatureS:     signature.S.String(),
		ClaimsTreeRoot:          i.treeState.ClaimsRoot,
		RevTreeRoot:             i.treeState.RevocationsRoot,
		RootsTreeRoot:           i.treeState.RootsRoot,
		State:                   i.treeState.State,
		GISTRoot:                gistProof.Root,
		GISTMtp:                 prepareSiblings(gistProof.Proof.Siblings, 64),
		GISTMtpAuxHi:            &globalNodeAux.key,
		GISTMtpAuxHv:            &globalNodeAux.value,
		GISTMtpNoAux:            globalNodeAux.noAux,
	}

	data, err := json.Marshal(auth2Inputs)
	if err != nil {
		return nil, fmt.Errorf("error marshaling auth2 inputs: %v", err)
	}

	return data, nil
}

func (i *Identity) getNodeAuxValue(proof *merkletree.Proof) NodeAuxValue {
	if proof.Existence {
		return NodeAuxValue{
			key:   merkletree.HashZero,
			value: merkletree.HashZero,
			noAux: "0",
		}
	}

	if proof.NodeAux != nil && proof.NodeAux.Value != nil && proof.NodeAux.Key != nil {
		return NodeAuxValue{
			key:   *proof.NodeAux.Key,
			value: *proof.NodeAux.Value,
			noAux: "0",
		}
	}

	return NodeAuxValue{
		key:   merkletree.HashZero,
		value: merkletree.HashZero,
		noAux: "1",
	}
}

func (i *Identity) Register(
	offerData []byte,
	rarimoCoreURL string,
	issuerDid string,
	votingAddress string,
	schemaJsonLd []byte,
	issuingAuthorityCode string,
	stateInfoJSON []byte,
) (*RegistrationData, error) {
	credentials, err := i.initVerifiableCredentials(offerData)
	if err != nil {
		return nil, fmt.Errorf("error initializing verifiable credentials: %v", err)
	}

	if len(credentials) == 0 {
		return nil, errors.New("no credentials found")
	}

	credential := credentials[0]

	in, e := big.NewInt(2), big.NewInt(248)
	maxKeySize := in.Exp(in, e, nil)

	secret, err := rand.Int(rand.Reader, maxKeySize)
	if err != nil {
		return nil, fmt.Errorf("error generating secret: %v", err)
	}

	nullifier, err := rand.Int(rand.Reader, maxKeySize)
	if err != nil {
		return nil, fmt.Errorf("error generating nullifier: %v", err)
	}

	commitment, err := poseidon.Hash([]*big.Int{secret, nullifier})
	if err != nil {
		return nil, fmt.Errorf("error hashing secret and nullifier: %v", err)
	}

	coreStateInfo := new(StateInfo)
	if err := json.Unmarshal(stateInfoJSON, coreStateInfo); err != nil {
		return nil, fmt.Errorf("error unmarshaling state info: %v", err)
	}

	issuerState, err := i.GetIssuerState(credential)
	if err != nil {
		return nil, fmt.Errorf("error getting issuer state: %v", err)
	}

	coreMTP, err := i.getCoreMTP(rarimoCoreURL, issuerDid, coreStateInfo.CreatedAtBlock)
	if err != nil {
		return nil, fmt.Errorf("error getting core mtp: %v", err)
	}

	coreOperation, err := i.getCoreOperation(rarimoCoreURL, coreStateInfo.LastUpdateOperationIdx)
	if err != nil {
		return nil, fmt.Errorf("error getting core operation: %v", err)
	}

	coreOperationProof, err := i.getCoreOperationProof(rarimoCoreURL, coreStateInfo.LastUpdateOperationIdx)
	if err != nil {
		return nil, fmt.Errorf("error getting core operation proof: %v", err)
	}

	votingQueryInputs, documentNullifier, err := i.prepareQueryInputs(commitment, credential, coreStateInfo.Hash, votingAddress, schemaJsonLd)
	if err != nil {
		return nil, fmt.Errorf("error preparing query inputs: %v", err)
	}

	votingQueryInputsJson, err := json.Marshal(votingQueryInputs)
	if err != nil {
		return nil, fmt.Errorf("error marshaling voting query inputs: %v", err)
	}

	proofBytes, err := i.stateProvider.ProveCredentialAtomicQueryMTPV2OnChainVoting(votingQueryInputsJson)
	if err != nil {
		return nil, fmt.Errorf("error proving credential atomic query mtp v2 on chain voting: %v", err)
	}

	proof := new(types.ZKProof)
	if err := json.Unmarshal(proofBytes, &proof); err != nil {
		return nil, fmt.Errorf("error unmarshaling proof: %v", err)
	}

	proveIdentityParams, err := i.buildProveIdentityParams(
		issuerDid,
		issuerState,
		coreStateInfo.CreatedAtTimestamp,
		coreMTP.Proof,
		proof,
	)
	if err != nil {
		return nil, fmt.Errorf("error building prove identity params: %v", err)
	}

	transitStateParams, err := i.buildTransitStateParams(
		coreOperationProof,
		coreOperation,
	)
	if err != nil {
		return nil, fmt.Errorf("error building transit state params: %v", err)
	}

	registerProofParams, err := i.buildRegisterProofParams(
		commitment,
		issuingAuthorityCode,
		documentNullifier,
	)
	if err != nil {
		return nil, fmt.Errorf("error building register proof params: %v", err)
	}

	coder, err := NewRegistrationCoder()
	if err != nil {
		return nil, fmt.Errorf("error creating registration coder: %v", err)
	}

	calldata, err := coder.Pack("register", proveIdentityParams, registerProofParams, transitStateParams, true)
	if err != nil {
		return nil, fmt.Errorf("error packing calldata: %v", err)
	}

	return &RegistrationData{
		Calldata:          hex.EncodeToString(calldata),
		Secret:            secret.String(),
		Nullifier:         nullifier.String(),
		DocumentNullifier: documentNullifier.String(),
	}, nil
}

func (i *Identity) buildRegisterProofParams(
	commitment *big.Int,
	issuingAuthorityCode string,
	documentNullifier *big.Int,
) (*IRegisterVerifierRegisterProofParams, error) {
	issuingAuthorityCodeBigInt, ok := new(big.Int).SetString(issuingAuthorityCode, 10)
	if !ok {
		return nil, errors.New("error setting issuing authority code")
	}

	commitmentBytes := commitment.Bytes()

	var commitmentBytes32 [32]byte
	copy(commitmentBytes32[:], commitmentBytes[:32])

	return &IRegisterVerifierRegisterProofParams{
		IssuingAuthority:  issuingAuthorityCodeBigInt,
		DocumentNullifier: documentNullifier,
		Commitment:        commitmentBytes32,
	}, nil
}

func (i *Identity) buildTransitStateParams(
	coreOperationProof *OperationProof,
	coreOperation *Operation,
) (*IBaseVerifierTransitStateParams, error) {
	gistRootBigInt, ok := new(big.Int).SetString(coreOperation.Details.GISTHash[2:], 16)
	if !ok {
		return nil, errors.New("error setting gist root")
	}

	gistRootCreatedAtTimestampBigInt, ok := new(big.Int).SetString(coreOperation.Details.Timestamp, 10)
	if !ok {
		return nil, errors.New("error setting gist root created at timestamp")
	}

	coreStateProof, err := i.getStateProof(*coreOperationProof)
	if err != nil {
		return nil, fmt.Errorf("error getting core state proof: %v", err)
	}

	newIdentitiesStatesRootBytes, err := hex.DecodeString(coreOperation.Details.StateRootHash[2:])
	if err != nil {
		return nil, fmt.Errorf("error getting new identities states root: %v", err)
	}

	var newIdentitiesStatesRoot [32]byte
	copy(newIdentitiesStatesRoot[:], newIdentitiesStatesRootBytes[:32])

	return &IBaseVerifierTransitStateParams{
		NewIdentitiesStatesRoot: newIdentitiesStatesRoot,
		GistData: ILightweightStateGistRootData{
			Root:               gistRootBigInt,
			CreatedAtTimestamp: gistRootCreatedAtTimestampBigInt,
		},
		Proof: coreStateProof,
	}, nil
}

func (i *Identity) buildProveIdentityParams(
	issuerDid string,
	issuerState string,
	createdAtTimestamp string,
	merkleProof []string,
	zkProof *types.ZKProof,
) (*IBaseVerifierProveIdentityParams, error) {
	issuerId, err := i.DidToId(issuerDid)
	if err != nil {
		return nil, fmt.Errorf("error converting issuer did to id: %v", err)
	}

	issuerIdBigInt, ok := new(big.Int).SetString(issuerId, 10)
	if !ok {
		return nil, errors.New("error setting issuer id")
	}

	issuerStateBigEndian := hexEndianSwap(issuerState)

	issuerStateBigInt, ok := new(big.Int).SetString(issuerStateBigEndian, 16)
	if !ok {
		return nil, errors.New("error setting issuer state")
	}

	createdAtTimestampBigInt, ok := new(big.Int).SetString(createdAtTimestamp, 10)
	if !ok {
		return nil, errors.New("error setting created at timestamp")
	}

	var merkleProofBigInt [][32]byte
	for _, proof := range merkleProof {
		proofBytes, err := hex.DecodeString(proof[2:])
		if err != nil {
			return nil, fmt.Errorf("error decoding merkle proof: %v", err)
		}

		var newProofData [32]byte
		copy(newProofData[:], proofBytes[:32])

		merkleProofBigInt = append(merkleProofBigInt, newProofData)
	}

	var inputs []*big.Int
	for _, input := range zkProof.PubSignals {
		inputBigInt, ok := new(big.Int).SetString(input, 10)
		if !ok {
			return nil, fmt.Errorf("error setting input: %v", err)
		}

		inputs = append(inputs, inputBigInt)
	}

	var a [2]*big.Int
	for index, val := range zkProof.Proof.A[:2] {
		a_i, ok := new(big.Int).SetString(val, 10)
		if !ok {
			return nil, fmt.Errorf("error setting a[%d]: %v", index, err)
		}

		a[index] = a_i
	}

	var b [2][2]*big.Int
	for index, val := range zkProof.Proof.B[:2] {
		for index2, val2 := range val[:2] {
			b_i, ok := new(big.Int).SetString(val2, 10)
			if !ok {
				return nil, fmt.Errorf("error setting b[%d][%d]: %v", index, index2, err)
			}

			b[index][index2] = b_i
		}
	}

	b[0][0], b[0][1] = b[0][1], b[0][0]
	b[1][0], b[1][1] = b[1][1], b[1][0]

	var c [2]*big.Int
	for index, val := range zkProof.Proof.C[:2] {
		c_i, ok := new(big.Int).SetString(val, 10)
		if !ok {
			return nil, fmt.Errorf("error setting c[%d]: %v", index, err)
		}

		c[index] = c_i
	}

	return &IBaseVerifierProveIdentityParams{
		StatesMerkleData: ILightweightStateStatesMerkleData{
			IssuerId:           issuerIdBigInt,
			IssuerState:        issuerStateBigInt,
			CreatedAtTimestamp: createdAtTimestampBigInt,
			MerkleProof:        merkleProofBigInt,
		},
		Inputs: inputs,
		A:      a,
		B:      b,
		C:      c,
	}, nil
}

func (i *Identity) getCoreOperationProof(rarimoCoreURL string, index string) (*OperationProof, error) {
	rarimoCoreURL += fmt.Sprintf("/rarimo/rarimo-core/rarimocore/operation/%v/proof", index)

	response, err := http.Get(rarimoCoreURL)
	if err != nil {
		return nil, fmt.Errorf("error getting operation proof: %v", err)
	}

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading response body: %v", err)
	}

	operationProof := new(OperationProof)
	if err := json.Unmarshal(body, &operationProof); err != nil {
		return nil, fmt.Errorf("error unmarshaling operation proof: %v", err)
	}

	if operationProof.Signature == "" {
		return nil, errors.New("operation proof signature is empty")
	}

	return operationProof, nil
}

func (i *Identity) getCoreOperation(rarimoCoreURL string, index string) (*Operation, error) {
	rarimoCoreURL += fmt.Sprintf("/rarimo/rarimo-core/rarimocore/operation/%v", index)

	response, err := http.Get(rarimoCoreURL)
	if err != nil {
		return nil, fmt.Errorf("error getting operation: %v", err)
	}

	operationBytes, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading operation bytes: %v", err)
	}

	operation := new(OperationData)
	if err := json.Unmarshal(operationBytes, &operation); err != nil {
		return nil, fmt.Errorf("error unmarshaling operation: %v", err)
	}

	return &operation.Operation, nil
}

func (i *Identity) getCoreMTP(rarimoCoreURL string, issuerDid string, createdAtBlock string) (*CoreMTP, error) {
	issuerIdHex, err := i.didToIDHex(issuerDid)
	if err != nil {
		return nil, fmt.Errorf("error converting issuer did to id hex: %v", err)
	}

	rarimoCoreURL += fmt.Sprintf("/rarimo/rarimo-core/identity/state/%v/proof", issuerIdHex)

	client := &http.Client{}

	request, err := http.NewRequest("GET", rarimoCoreURL, nil)
	if err != nil {
		return nil, fmt.Errorf("error creating request: %v", err)
	}

	request.Header.Set("X-Cosmos-Block-Height", createdAtBlock)

	response, err := client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("error getting core mtp: %v", err)
	}

	coreMTPBytes, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading core mtp bytes: %v", err)
	}

	coreMTP := new(CoreMTP)
	if err := json.Unmarshal(coreMTPBytes, &coreMTP); err != nil {
		return nil, fmt.Errorf("error unmarshaling core mtp: %v", err)
	}

	return coreMTP, nil
}

func (i *Identity) getStateInfo(rarimoCoreURL string, issuerDid string) (*StateInfo, error) {
	issuerIdHex, err := i.didToIDHex(issuerDid)
	if err != nil {
		return nil, fmt.Errorf("error converting issuer did to id hex: %v", err)
	}

	rarimoCoreURL += fmt.Sprintf("/rarimo/rarimo-core/identity/state/%s", issuerIdHex)

	response, err := http.Get(rarimoCoreURL)
	if err != nil {
		return nil, fmt.Errorf("error getting state info: %v", err)
	}

	getStateInfoResponseBytes, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading state info bytes: %v", err)
	}

	getStateInfoResponse := new(GetStateInfoResponse)
	if err := json.Unmarshal(getStateInfoResponseBytes, &getStateInfoResponse); err != nil {
		return nil, fmt.Errorf("error unmarshaling state info: %v", err)
	}

	return &getStateInfoResponse.State, nil
}

func (i *Identity) getRevocationStatus(status *CredentialStatus) (*ProofStatus, error) {
	response, err := http.Get(status.Identifier)
	if err != nil {
		return nil, fmt.Errorf("error getting revocation status: %v", err)
	}

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading response body: %v", err)
	}

	revocationStatus := new(ProofStatus)
	if err := json.Unmarshal(body, &revocationStatus); err != nil {
		return nil, fmt.Errorf("error unmarshaling revocation status: %v", err)
	}

	return revocationStatus, nil
}

func (i *Identity) DidToId(did string) (string, error) {
	didParsed, err := w3c.ParseDID(did)
	if err != nil {
		return "", fmt.Errorf("error parsing did: %v", err)
	}

	id, err := core.IDFromDID(*didParsed)
	if err != nil {
		return "", fmt.Errorf("unable to get id from identity did: %v", err)
	}

	return id.BigInt().String(), nil
}

func (i *Identity) GetIssuerState(
	credential *verifiable.W3CCredential,
) (string, error) {
	credentialStatusRaw, ok := credential.CredentialStatus.(map[string]interface{})
	if !ok {
		return "", errors.New("credential status is not a map")
	}

	credentialStatusJson, err := json.Marshal(credentialStatusRaw)
	if err != nil {
		return "", fmt.Errorf("error marshaling credential status: %v", err)
	}

	credentialStatus := new(CredentialStatus)
	if err := json.Unmarshal(credentialStatusJson, &credentialStatus); err != nil {
		return "", fmt.Errorf("error unmarshaling credential status: %v", err)
	}

	revStatus, err := i.getRevocationStatus(credentialStatus)
	if err != nil {
		return "", fmt.Errorf("error getting revocation status: %v", err)
	}

	return revStatus.Issuer.State, nil
}

func (i *Identity) findNonRevokedCredential(
	credentials []*verifiable.W3CCredential,
) (*verifiable.W3CCredential, *ProofStatus, error) {
	for _, credential := range credentials {
		credentialStatusRaw, ok := credential.CredentialStatus.(map[string]interface{})
		if !ok {
			return nil, nil, errors.New("credential status is not a map")
		}

		credentialStatusJson, err := json.Marshal(credentialStatusRaw)
		if err != nil {
			return nil, nil, fmt.Errorf("error marshaling credential status: %v", err)
		}

		credentialStatus := new(CredentialStatus)
		if err := json.Unmarshal(credentialStatusJson, &credentialStatus); err != nil {
			return nil, nil, fmt.Errorf("error unmarshaling credential status: %v", err)
		}

		status, err := i.getRevocationStatus(credentialStatus)
		if err != nil {
			return nil, nil, fmt.Errorf("error getting revocation status: %v", err)
		}

		if status.Mtp.Existence {
			continue
		}

		return credential, status, nil
	}

	return nil, nil, fmt.Errorf("no non-revoked credentials found")
}

func (i *Identity) getPreparedCredential(
	credential *verifiable.W3CCredential,
) (*verifiable.W3CCredential, *ProofStatus, *core.Claim, error) {
	credential, revStatus, err := i.findNonRevokedCredential([]*verifiable.W3CCredential{credential})
	if err != nil {
		return nil, nil, nil, fmt.Errorf("error finding non-revoked credential: %v", err)
	}

	coreClaim, err := getCoreClaimFromProof(credential.Proof, verifiable.Iden3SparseMerkleTreeProofType)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("error getting core claim from credential: %v", err)
	}

	return credential, revStatus, coreClaim, nil
}

func (i *Identity) getMTPDataByUrl(url string, endianSwappedCoreStateHash *string) (*ProofStatus, error) {
	if endianSwappedCoreStateHash != nil {
		url = fmt.Sprintf("%s?state_hash=%s", url, *endianSwappedCoreStateHash)
	}

	response, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("error getting mtp data: %v", err)
	}

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading response body: %v", err)
	}

	mtp := new(ProofStatus)
	if err := json.Unmarshal(body, &mtp); err != nil {
		return nil, fmt.Errorf("error unmarshaling mtp data: %v", err)
	}

	return mtp, nil
}

func getCoreClaimFromProof(proofs verifiable.CredentialProofs, proofType verifiable.ProofType) (*core.Claim, error) {
	for _, proof := range proofs {
		if proofType != proof.ProofType() {
			continue
		}

		claim, err := proof.GetCoreClaim()
		if err != nil {
			return nil, fmt.Errorf("error getting core claim from proof: %v", err)
		}

		return claim, nil
	}

	return nil, fmt.Errorf("no core claim found")
}

func getIden3SparseMerkleTreeProof(credentialProof verifiable.CredentialProofs) (*verifiable.Iden3SparseMerkleTreeProof, error) {
	for _, proof := range credentialProof {
		if verifiable.Iden3SparseMerkleTreeProofType == proof.ProofType() {
			id3Proof, ok := proof.(*verifiable.Iden3SparseMerkleTreeProof)
			if !ok {
				return nil, errors.New("unexpected proof type")
			}

			return id3Proof, nil
		}
	}

	return nil, nil
}

func (i *Identity) prepareQueryInputs(
	commitment *big.Int,
	credential *verifiable.W3CCredential,
	coreStateHash string,
	votingAddress string,
	schemaJson []byte,
) (*AtomicQueryMTPV2OnChainVotingCircuitInputs, *big.Int, error) {
	accountAddress, err := i.getEthereumAccountAddress()
	if err != nil {
		return nil, nil, fmt.Errorf("error getting ethereum account address: %v", err)
	}

	requestID, err := rand.Int(rand.Reader, constants.Q)
	if err != nil {
		return nil, nil, fmt.Errorf("error generating request id: %v", err)
	}

	userId, err := i.GetID()
	if err != nil {
		return nil, nil, fmt.Errorf("error getting user id: %v", err)
	}

	gistProofInfoRaw, err := i.stateProvider.GetGISTProof(i.DID())
	if err != nil {
		return nil, nil, fmt.Errorf("error getting gist proof from state: %v", err)
	}

	gistProofInfo := new(GISTProofInfo)
	if err := json.Unmarshal(gistProofInfoRaw, &gistProofInfo); err != nil {
		return nil, nil, fmt.Errorf("error unmarshaling gist proof: %v", err)
	}

	gistProof, err := gistProofInfo.GetProof()
	if err != nil {
		return nil, nil, fmt.Errorf("error getting gist proof for: %v", err)
	}

	globalNodeAux := i.getNodeAuxValue(gistProof.Proof)
	nodeAuxAuth := i.getNodeAuxValue(i.authClaimNonRevProof)

	validCredential, revStatus, coreClaim, err := i.getPreparedCredential(credential)
	if err != nil {
		return nil, nil, fmt.Errorf("error getting prepared credential: %v", err)
	}

	credentialHash, ok := validCredential.CredentialSubject["credentialHash"].(string)
	if !ok {
		return nil, nil, errors.New("credential hash is not a string")
	}

	documentNullifier, ok := validCredential.CredentialSubject["documentNullifier"].(string)
	if !ok {
		return nil, nil, errors.New("documentNullifier is not a string")
	}

	documentNullifierBigInt, ok := new(big.Int).SetString(documentNullifier, 10)
	if !ok {
		return nil, nil, errors.New("error setting document nullifier")
	}

	createProofRequest := &CreateProofRequest{
		AccountAddress: accountAddress,
		Query: &ProofQuery{
			AllowedIssuers: []string{"*"},
			CredentialSubject: &ProofQueryCredentialSubject{
				CredentialHash: &CredentialHash{
					Eq: credentialHash,
				},
			},
			Type: validCredential.Type,
		},
	}

	circuitClaimData, err := i.newCircuitClaimData(validCredential, coreClaim, coreStateHash)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating circuit claim: %v", err)
	}

	query, err := i.toCircuitsQuery(
		createProofRequest.Query,
		validCredential,
		coreClaim,
		schemaJson,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating circuits query: %v", err)
	}

	revState, err := revStatus.Issuer.GetIssuerPreparedState()
	if err != nil {
		return nil, nil, fmt.Errorf("error getting issuer prepared state: %v", err)
	}

	nonRevProof := &MTP{
		Proof:     revStatus.Mtp,
		TreeState: revState,
	}

	timestamp := time.Now().Unix()

	nodeAuxNonRev := i.getNodeAuxValue(nonRevProof.Proof)
	nodAuxJSONLD := i.getNodeAuxValue(query.ValueProof.Mtp)

	rawValue := prepareCircuitArrayValues(query.Values, 1)

	value := make([]string, len(rawValue))
	for index, val := range rawValue {
		value[index] = val.String()
	}

	challengeBytes, err := hex.DecodeString(createProofRequest.AccountAddress[2:])
	if err != nil {
		return nil, nil, fmt.Errorf("error decoding challenge: %v", err)
	}

	challenge := fromLittleEndian(challengeBytes)

	signature := i.secretKey.SignPoseidon(challenge)

	issuerTreeState, err := circuitClaimData.Status.Issuer.GetIssuerPreparedState()
	if err != nil {
		return nil, nil, fmt.Errorf("error getting issuer prepared state: %v", err)
	}

	return &AtomicQueryMTPV2OnChainVotingCircuitInputs{
		RequestID: requestID.String(),

		UserGenesisID:            userId,
		ProfileNonce:             "0",
		ClaimSubjectProfileNonce: "0",

		IssuerID:                  circuitClaimData.IssuerId,
		IssuerClaim:               circuitClaimData.Claim,
		IssuerClaimMtp:            prepareSiblings(circuitClaimData.Status.Mtp.Siblings, 40),
		IssuerClaimClaimsTreeRoot: issuerTreeState.ClaimsRoot,
		IssuerClaimRevTreeRoot:    issuerTreeState.RevocationsRoot,
		IssuerClaimRootsTreeRoot:  issuerTreeState.RootsRoot,
		IssuerClaimIdenState:      issuerTreeState.State,

		IssuerClaimNonRevClaimsTreeRoot: nonRevProof.TreeState.ClaimsRoot,
		IssuerClaimNonRevRevTreeRoot:    nonRevProof.TreeState.RevocationsRoot,
		IssuerClaimNonRevRootsTreeRoot:  nonRevProof.TreeState.RootsRoot,
		IssuerClaimNonRevState:          nonRevProof.TreeState.State,
		IssuerClaimNonRevMtp:            prepareSiblings(nonRevProof.Proof.Siblings, 40),
		IssuerClaimNonRevMtpAuxHi:       &nodeAuxNonRev.key,
		IssuerClaimNonRevMtpAuxHv:       &nodeAuxNonRev.value,
		IssuerClaimNonRevMtpNoAux:       nodeAuxNonRev.noAux,

		IsRevocationChecked: 0,

		ClaimSchema: circuitClaimData.Claim.GetSchemaHash().BigInt().String(),

		ClaimPathNotExists: Btoi(!query.ValueProof.Mtp.Existence),
		ClaimPathMtp:       prepareSiblings(query.ValueProof.Mtp.Siblings, 32),
		ClaimPathMtpNoAux:  nodAuxJSONLD.noAux,
		ClaimPathMtpAuxHi:  &nodAuxJSONLD.key,
		ClaimPathMtpAuxHv:  &nodAuxJSONLD.value,
		ClaimPathKey:       query.ValueProof.Path.String(),
		ClaimPathValue:     query.ValueProof.Value.String(),

		Operator:  int(query.Operator),
		SlotIndex: query.SlotIndex,
		Timestamp: timestamp,
		Value:     value,

		AuthClaim:    i.authClaim,
		AuthClaimMtp: prepareSiblings(i.authClaimIncProofSiblings, 40),

		AuthClaimNonRevMtp:      prepareSiblings(i.authClaimNonRevProof.Siblings, 40),
		AuthClaimNonRevMtpAuxHi: &nodeAuxAuth.key,
		AuthClaimNonRevMtpAuxHv: &nodeAuxAuth.value,
		AuthClaimNonRevMtpNoAux: nodeAuxAuth.noAux,

		Challenge:             challenge.String(),
		ChallengeSignatureR8X: signature.R8.X.String(),
		ChallengeSignatureR8Y: signature.R8.Y.String(),
		ChallengeSignatureS:   signature.S.String(),

		ClaimsTreeRoot: i.treeState.ClaimsRoot,
		RevTreeRoot:    i.treeState.RevocationsRoot,
		RootsTreeRoot:  i.treeState.RootsRoot,
		State:          i.treeState.State,

		GISTRoot:     gistProof.Root,
		GISTMtp:      prepareSiblings(gistProof.Proof.Siblings, 64),
		GISTMtpAuxHi: &globalNodeAux.key,
		GISTMtpAuxHv: &globalNodeAux.value,
		GISTMtpNoAux: globalNodeAux.noAux,

		VotingAddress: votingAddress,
		Commitment:    commitment.String(),
	}, documentNullifierBigInt, nil
}

func (i *Identity) getStateProof(operationProof OperationProof) ([]byte, error) {
	var operationProofPathData [][32]byte
	for _, path := range operationProof.Path {
		pathData, err := hex.DecodeString(path[2:])
		if err != nil {
			return nil, fmt.Errorf("error decoding path: %v", err)
		}

		var newProofData [32]byte
		copy(newProofData[:], pathData[:32])

		operationProofPathData = append(operationProofPathData, newProofData)
	}

	signature, err := hex.DecodeString(operationProof.Signature[2:])
	if err != nil {
		return nil, fmt.Errorf("error decoding signature: %v", err)
	}

	if len(signature) >= 65 {
		signature[64] += 27
	}

	bytes32ArrT, _ := abi.NewType("bytes32[]", "", nil)
	bytes32T, _ := abi.NewType("bytes", "", nil)

	arguments := abi.Arguments{
		{
			Type: bytes32ArrT,
		},
		{
			Type: bytes32T,
		},
	}

	proof, err := arguments.Pack(operationProofPathData, signature)
	if err != nil {
		return nil, fmt.Errorf("error packing proof: %v", err)
	}

	return proof, nil
}

func (i *Identity) didToIDHex(did string) (string, error) {
	didParsed, err := w3c.ParseDID(did)
	if err != nil {
		return "", fmt.Errorf("error parsing did: %v", err)
	}

	id, err := core.IDFromDID(*didParsed)
	if err != nil {
		return "", fmt.Errorf("error getting id from did: %v", err)
	}

	return fmt.Sprintf("0x0%s", id.BigInt().Text(16)), nil
}

func prepareCircuitArrayValues(arr []*big.Int, size uint64) []*big.Int {
	if len(arr) > int(size) {
		arr = arr[:size]
	}

	for i := len(arr); i < int(size); i++ {
		arr = append(arr, big.NewInt(0))
	}

	return arr
}

func Btoi(b bool) int {
	if b {
		return 1
	}
	return 0
}

func fromLittleEndian(bytes []byte) *big.Int {
	n256 := big.NewInt(256)
	result := big.NewInt(0)
	base := big.NewInt(1)

	for _, b := range bytes {
		byteBigInt := big.NewInt(int64(b))
		result.Add(result, new(big.Int).Mul(base, byteBigInt))
		base.Mul(base, n256)
	}

	return result
}

func (i *Identity) toCircuitsQuery(
	query *ProofQuery,
	credential *verifiable.W3CCredential,
	coreClaim *core.Claim,
	schemaJson []byte,
) (*Query, error) {
	mtPosition, err := coreClaim.GetMerklizedPosition()
	if err != nil {
		return nil, fmt.Errorf("error getting merklized position: %v", err)
	}

	if mtPosition == core.MerklizedRootPositionNone {
		return nil, errors.New("merklized position is none")
	}

	return i.prepareMerklizedQuery(query, credential, schemaJson)
}

func merklizeW3CCredential(credential *verifiable.W3CCredential) (*merklize.Merklizer, error) {
	credentialCopy := *credential

	credentialCopy.Proof = nil

	credentialJson, err := json.Marshal(credentialCopy)
	if err != nil {
		return nil, fmt.Errorf("error marshaling credential: %v", err)
	}

	ctx := context.Background()

	merklizer, err := merklize.MerklizeJSONLD(ctx, bytes.NewReader(credentialJson))
	if err != nil {
		return nil, fmt.Errorf("error merklizing credential: %v", err)
	}

	return merklizer, nil
}

func (i *Identity) prepareMerklizedQuery(
	query *ProofQuery,
	credential *verifiable.W3CCredential,
	schemaJson []byte,
) (*Query, error) {
	parsedQuery, err := parseRequest(query.CredentialSubject)
	if err != nil {
		return nil, fmt.Errorf("error parsing request: %v", err)
	}

	mk, err := merklizeW3CCredential(credential)
	if err != nil {
		return nil, fmt.Errorf("error merklizing credential: %v", err)
	}

	path, err := merklize.NewFieldPathFromContext(schemaJson, credential.Type[1], parsedQuery.FieldName)
	if err != nil {
		return nil, fmt.Errorf("error getting context path key: %v", err)
	}

	path.Prepend("https://www.w3.org/2018/credentials#credentialSubject")

	proof, value, err := mk.Proof(context.Background(), path)
	if err != nil {
		return nil, fmt.Errorf("error proving: %v", err)
	}

	pathKey, err := path.MtEntry()
	if err != nil {
		return nil, fmt.Errorf("error getting path key: %v", err)
	}

	mtEntry, err := value.MtEntry()
	if err != nil {
		return nil, fmt.Errorf("error getting mt entry: %v", err)
	}

	var siblings []*merkletree.Hash
	for _, sibling := range proof.AllSiblings() {
		siblingText, err := sibling.MarshalText()
		if err != nil {
			return nil, fmt.Errorf("error marshaling sibling: %v", err)
		}

		newSibling := merkletree.Hash{}
		if err := newSibling.UnmarshalText(siblingText); err != nil {
			return nil, fmt.Errorf("error unmarshaling sibling: %v", err)
		}

		siblings = append(siblings, &newSibling)
	}

	keyHash := merkletree.NewHashFromBigInt(pathKey)

	valueHash := merkletree.NewHashFromBigInt(mtEntry)

	valueProof := &ValueProof{
		Path: pathKey,
		Mtp: &merkletree.Proof{
			Existence: proof.Existence,
			Siblings:  siblings,
			NodeAux: &merkletree.NodeAux{
				Key:   keyHash,
				Value: valueHash,
			},
		},
		Value: mtEntry,
	}

	parsedQuery.Query.ValueProof = valueProof

	parsedQuery.Query.SlotIndex = 0

	return &parsedQuery.Query, nil
}

func parseRequest(req *ProofQueryCredentialSubject) (*QueryWithFieldName, error) {
	value, ok := new(big.Int).SetString(req.CredentialHash.Eq, 10)
	if !ok {
		return nil, errors.New("error setting credential hash")
	}

	query := Query{
		Operator: EQ,
		Values:   []*big.Int{value},
	}

	return &QueryWithFieldName{
		Query:     query,
		FieldName: "credentialHash",
	}, nil
}

func (i *Identity) newCircuitClaimData(
	credential *verifiable.W3CCredential,
	coreClaim *core.Claim,
	coreStateHash string,
) (*CircuitClaim, error) {
	circuitClaim := new(CircuitClaim)
	circuitClaim.Claim = coreClaim

	issuerDid, err := w3c.ParseDID(credential.Issuer)
	if err != nil {
		return nil, fmt.Errorf("error parsing issuer did: %v", err)
	}

	issuerId, err := core.IDFromDID(*issuerDid)
	if err != nil {
		return nil, fmt.Errorf("unable to get id from identity did: %v", err)
	}

	circuitClaim.IssuerId = issuerId.BigInt().String()

	smtProof, err := getIden3SparseMerkleTreeProof(credential.Proof)
	if err != nil {
		return nil, fmt.Errorf("error getting iden3 sparse merkle tree proof: %v", err)
	}

	swappedCoreStateHash := hexEndianSwap(coreStateHash)

	if smtProof != nil {
		mtp, err := i.getMTPDataByUrl(smtProof.ID, &swappedCoreStateHash)
		if err != nil {
			return nil, fmt.Errorf("error getting mtp data: %v", err)
		}

		circuitClaim.Status = mtp
	}

	return circuitClaim, nil
}

func (i *Identity) getEthereumAccountAddress() (string, error) {
	pubkey := i.secretKey.Public().Compress()

	var buf []byte
	hasher := sha3.NewLegacyKeccak256()
	hasher.Write((pubkey)[:])

	address := hasher.Sum(buf)[12:]

	return "0x" + hex.EncodeToString(address), nil
}

type IsFinalizedRequest struct {
	RarimoCoreURL string `json:"rarimoCoreURL"`
	IssuerDid     string `json:"issuerDid"`
	StateInfoJSON []byte `json:"stateInfo"`
	Timestamp     int64  `json:"timestamp"`
}

func (i *Identity) IsFinalized(
	isFinalizedRequestJSON []byte,
) ([]byte, error) {
	isFinalizedRequest := new(IsFinalizedRequest)
	if err := json.Unmarshal(isFinalizedRequestJSON, isFinalizedRequest); err != nil {
		return nil, fmt.Errorf("error unmarshaling is finalized request: %v", err)
	}

	var stateInfo *StateInfo
	if len(isFinalizedRequest.StateInfoJSON) != 0 {
		stateInfo = new(StateInfo)
		if err := json.Unmarshal(isFinalizedRequest.StateInfoJSON, stateInfo); err != nil {
			return nil, fmt.Errorf("error unmarshaling state info: %v", err)
		}
	} else {
		coreStateInfo, err := i.getStateInfo(isFinalizedRequest.RarimoCoreURL, isFinalizedRequest.IssuerDid)
		if err != nil {
			return nil, fmt.Errorf("error getting state info: %v", err)
		}

		stateInfo = coreStateInfo
	}

	coreOperation, err := i.getCoreOperation(isFinalizedRequest.RarimoCoreURL, stateInfo.LastUpdateOperationIdx)
	if err != nil {
		return nil, fmt.Errorf("error getting core operation: %v", err)
	}

	timestamp, err := strconv.ParseInt(coreOperation.Timestamp, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("timestamp is not valid integer: %v", err)
	}

	if isFinalizedRequest.Timestamp > timestamp {
		response := &FinalizedResponse{
			IsFinalized: false,
			StateInfo:   &StateInfo{},
		}

		return json.Marshal(response)
	}

	if coreOperation.Status != OperationFinalizedStatus {
		response := &FinalizedResponse{
			IsFinalized: false,
			StateInfo:   stateInfo,
		}

		return json.Marshal(response)
	}

	response := &FinalizedResponse{
		IsFinalized: true,
		StateInfo:   stateInfo,
	}

	return json.Marshal(response)
}

var OperationFinalizedStatus = "SIGNED"

func (i *Identity) GenerateJWZ(payload []byte) (string, error) {
	token, err := jwz.NewWithPayload(
		jwz.ProvingMethodGroth16AuthV2Instance,
		payload,
		i.PrepareAuth2Inputs,
	)
	if err != nil {
		return "", fmt.Errorf("error creating token: %v", err)
	}

	headers, err := json.Marshal(token.Raw.Header)
	if err != nil {
		return "", fmt.Errorf("error marshaling token headers: %v", err)
	}
	token.Raw.Protected = headers

	msgHash, err := token.GetMessageHash()
	if err != nil {
		return "", fmt.Errorf("error getting message hash: %v", err)
	}

	inputs, err := token.InputsPreparer.Prepare(msgHash, circuits.CircuitID(token.CircuitID))
	if err != nil {
		return "", fmt.Errorf("error preparing inputs: %v", err)
	}

	proofRaw, err := i.stateProvider.ProveAuthV2(inputs)
	if err != nil {
		return "", fmt.Errorf("error proving: %v", err)
	}

	proof := new(types.ZKProof)
	if err := json.Unmarshal(proofRaw, &proof); err != nil {
		return "", fmt.Errorf("error unmarshaling proof: %v", err)
	}

	token.ZkProof = proof
	token.Raw.ZKP = proofRaw

	jwzToken, err := token.CompactSerialize()
	if err != nil {
		return "", fmt.Errorf("error serializing token: %v", err)
	}

	return jwzToken, nil
}

func (i *Identity) GetCommitmentIndex(secret string, nullifier string) ([]byte, error) {
	secretBigInt, ok := new(big.Int).SetString(secret, 10)
	if !ok {
		return nil, errors.New("error setting secret")
	}

	nullifierBigInt, ok := new(big.Int).SetString(nullifier, 10)
	if !ok {
		return nil, errors.New("error setting nullifier")
	}

	commitment, err := poseidon.Hash([]*big.Int{secretBigInt, nullifierBigInt})
	if err != nil {
		return nil, fmt.Errorf("error hashing secret and nullifier: %v", err)
	}

	commitmentIndex, err := poseidon.HashBytes(commitment.Bytes())
	if err != nil {
		return nil, fmt.Errorf("error hashing commitment: %v", err)
	}

	return commitmentIndex.Bytes(), nil
}

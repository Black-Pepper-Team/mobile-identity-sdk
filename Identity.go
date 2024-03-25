package identity

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strconv"

	"github.com/ethereum/go-ethereum/common"
	"github.com/google/uuid"
	circuits "github.com/iden3/go-circuits/v2"
	core "github.com/iden3/go-iden3-core/v2"
	"github.com/iden3/go-iden3-core/v2/w3c"
	babyjub "github.com/iden3/go-iden3-crypto/babyjub"
	"github.com/iden3/go-rapidsnark/types"
	jwz "github.com/rarimo/go-jwz"
	merkletree "github.com/rarimo/go-merkletree"
	merkletree_db_memory "github.com/rarimo/go-merkletree/db/memory"
	verifiable "github.com/rarimo/go-schema-processor/verifiable"
)

var OperationFinalizedStatus = "SIGNED"

type TreeState struct {
	State           *merkletree.Hash
	ClaimsRoot      *merkletree.Hash
	RevocationsRoot *merkletree.Hash
	RootsRoot       *merkletree.Hash
}

type Identity struct {
	UsedId string

	secretKey *babyjub.PrivateKey
	authClaim *core.Claim
	did       *w3c.DID

	treeState *TreeState

	authClaimIncProofSiblings []*merkletree.Hash
	authClaimNonRevProof      *merkletree.Proof

	stateProvider StateProvider

	credentials []*verifiable.W3CCredential
}

func NewIdentityWithData(
	secretKeyHex string,
	userId string,
	stateProvider StateProvider,
) (*Identity, error) {
	rawSecretKey, err := hex.DecodeString(secretKeyHex)
	if err != nil {
		return nil, fmt.Errorf("error decoding secret key: %v", err)
	}

	secretKey := babyjub.PrivateKey(rawSecretKey)

	return newIdentity(&secretKey, userId, stateProvider)
}

func NewIdentity(secretKeyHex string, stateProvider StateProvider) (*Identity, error) {
	rawSecretKey, err := hex.DecodeString(secretKeyHex)
	if err != nil {
		return nil, fmt.Errorf("error decoding secret key: %v", err)
	}

	secretKey := babyjub.PrivateKey(rawSecretKey)

	userID := uuid.NewString()

	return newIdentity(&secretKey, userID, stateProvider)
}

func newIdentity(
	secretKey *babyjub.PrivateKey,
	userId string,
	stateProvider StateProvider,
) (*Identity, error) {
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

	authClaimIncProofSiblings := prepareSiblings(authClaimIncProof.AllSiblings(), 40)

	authClaimNonRevProof, _, err := revocationsTree.GenerateProof(authHashIndex, revocationsTreeRoot)
	if err != nil {
		return nil, fmt.Errorf("error creating auth claim non rev proof: %v", err)
	}

	stateHash, err := merkletree.HashElems(claimsTreeRoot.BigInt(), revocationsTreeRoot.BigInt(), rootsTreeRoot.BigInt())
	if err != nil {
		return nil, fmt.Errorf("error creating state hash: %v", err)
	}

	return &Identity{
		UsedId:    userId,
		authClaim: authClaim,
		did:       did,
		secretKey: secretKey,
		treeState: &TreeState{
			State:           stateHash,
			ClaimsRoot:      claimsTreeRoot,
			RevocationsRoot: revocationsTreeRoot,
			RootsRoot:       rootsTreeRoot,
		},
		authClaimIncProofSiblings: authClaimIncProofSiblings,
		authClaimNonRevProof:      authClaimNonRevProof,
		stateProvider:             stateProvider,
		credentials:               []*verifiable.W3CCredential{},
	}, nil
}

func (i *Identity) SetOldUsedId(userId string) {
	i.UsedId = userId
}

func (i *Identity) GetSecretKeyHex() string {
	return hex.EncodeToString((*i.secretKey)[:])
}

func (i *Identity) GetRegisterCallData() ([]byte, error) {
	trustedIssuers_ := []*big.Int{}

	threshold := big.NewInt(0)

	saltRaw := make([]byte, 32)
	rand.Read(saltRaw)

	salt := [32]byte{}
	copy(salt[:], saltRaw)

	return CreateAccountWithSaltCalldata(i.UsedId, trustedIssuers_, threshold, salt)
}

func (i *Identity) GetTransferCalldata(token string, amount string, to string) ([]byte, error) {
	amountBigInt, ok := new(big.Int).SetString(amount, 10)
	if !ok {
		return nil, errors.New("amount is not a valid integer")
	}

	tokenArrr := common.HexToAddress(token)
	toAddr := common.HexToAddress(to)

	return CreateTransferERC20Calldata(tokenArrr, amountBigInt, toAddr)
}

func (i *Identity) InitVerifiableCredentials(offerData []byte) error {
	offer := new(ClaimOfferResponse)
	if err := json.Unmarshal(offerData, &offer); err != nil {
		return fmt.Errorf("error unmarshaling offer: %v", err)
	}

	credentials := make([]*verifiable.W3CCredential, len(offer.Body.Credentials))

	for index := 0; index < len(offer.Body.Credentials); index++ {
		claimDetails := ClaimDetails{
			Id:        offer.Identifier,
			Typ:       offer.Typ,
			ClaimType: "https://iden3-communication.io/credentials/1.0/fetch-request",
			ThreadID:  offer.ThreadID,
			Body: claimDetailsBody{
				Id: offer.Body.Credentials[index].Identifier,
			},
			From: offer.To,
			To:   offer.From,
		}

		claimDetailsJson, err := json.Marshal(claimDetails)
		if err != nil {
			return fmt.Errorf("error matshaling claim details: %v", err)
		}

		token, err := jwz.NewWithPayload(
			jwz.ProvingMethodGroth16AuthV2Instance,
			claimDetailsJson,
			i.PrepareAuth2Inputs,
		)
		if err != nil {
			return fmt.Errorf("error creating token: %v", err)
		}

		headers, err := json.Marshal(token.Raw.Header)
		if err != nil {
			return fmt.Errorf("error marshaling token headers: %v", err)
		}
		token.Raw.Protected = headers

		msgHash, err := token.GetMessageHash()
		if err != nil {
			return fmt.Errorf("error getting message hash: %v", err)
		}

		inputs, err := token.InputsPreparer.Prepare(msgHash, circuits.CircuitID(token.CircuitID))
		if err != nil {
			return fmt.Errorf("error preparing inputs: %v", err)
		}

		proofRaw, err := i.stateProvider.ProveAuthV2(inputs)
		if err != nil {
			return fmt.Errorf("error proving: %v", err)
		}

		proof := new(types.ZKProof)
		if err := json.Unmarshal(proofRaw, &proof); err != nil {
			return fmt.Errorf("error unmarshaling proof: %v", err)
		}

		token.ZkProof = proof
		token.Raw.ZKP = proofRaw

		jwzToken, err := token.CompactSerialize()
		if err != nil {
			return fmt.Errorf("error serializing token: %v", err)
		}

		response, err := i.stateProvider.Fetch(offer.Body.Url, "POST", []byte(jwzToken), "", "")
		if err != nil {
			return fmt.Errorf("error fetching credentials: %v", err)
		}

		vsResponse := new(VSResponse)
		if err := json.Unmarshal(response, &vsResponse); err != nil {
			return fmt.Errorf("error unmarshaling response: %v", err)
		}

		credentials[index] = &vsResponse.Body.Credential
	}

	i.credentials = credentials

	return nil
}

func (i *Identity) IsFinalized(
	rarimoCoreURL string,
	issuerDid string,
	creationTimestamp int64,
) (bool, error) {
	coreStateInfo, err := i.getStateInfo(rarimoCoreURL, issuerDid)
	if err != nil {
		return false, fmt.Errorf("error getting state info: %v", err)
	}

	coreOperation, err := i.getCoreOperation(rarimoCoreURL, coreStateInfo.LastUpdateOperationIdx)
	if err != nil {
		return false, fmt.Errorf("error getting core operation: %v", err)
	}

	timestamp, err := strconv.ParseInt(coreOperation.Timestamp, 10, 64)
	if err != nil {
		return false, fmt.Errorf("timestamp is not valid integer: %v", err)
	}

	if creationTimestamp > timestamp {
		return false, nil
	}

	if coreOperation.Status != OperationFinalizedStatus {
		return false, nil
	}

	return true, nil
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

func (i *Identity) getCoreOperation(rarimoCoreURL string, index string) (*Operation, error) {
	rarimoCoreURL += fmt.Sprintf("/rarimo/rarimo-core/rarimocore/operation/%v", index)

	operationBytes, err := i.stateProvider.Fetch(rarimoCoreURL, "GET", nil, "", "")
	if err != nil {
		return nil, fmt.Errorf("error fetching operation: %v", err)
	}

	operation := new(OperationData)
	if err := json.Unmarshal(operationBytes, &operation); err != nil {
		return nil, fmt.Errorf("error unmarshaling operation: %v", err)
	}

	return &operation.Operation, nil
}

func (i *Identity) getStateInfo(rarimoCoreURL string, issuerDid string) (*StateInfo, error) {
	issuerIdHex, err := i.didToIDHex(issuerDid)
	if err != nil {
		return nil, fmt.Errorf("error converting issuer did to id hex: %v", err)
	}

	rarimoCoreURL += fmt.Sprintf("/rarimo/rarimo-core/identity/state/%s", issuerIdHex)

	getStateInfoResponseBytes, err := i.stateProvider.Fetch(rarimoCoreURL, "GET", nil, "", "")
	if err != nil {
		return nil, fmt.Errorf("error fetching state info: %v", err)
	}

	getStateInfoResponse := new(GetStateInfoResponse)
	if err := json.Unmarshal(getStateInfoResponseBytes, &getStateInfoResponse); err != nil {
		return nil, fmt.Errorf("error unmarshaling state info: %v", err)
	}

	return &getStateInfoResponse.State, nil
}

func (i *Identity) PrepareAuth2Inputs(hash []byte, circuitID circuits.CircuitID) ([]byte, error) {
	messageHash := new(big.Int).SetBytes(hash)

	signature := i.secretKey.SignPoseidon(messageHash)

	userId, err := i.GetID()
	if err != nil {
		return nil, fmt.Errorf("error getting user id: %v", err)
	}

	gistProofInfoRaw, err := i.stateProvider.GetGISTProof(i.GetDID())
	if err != nil {
		return nil, fmt.Errorf("error getting gist proof: %v", err)
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
func (i *Identity) GetDID() string {
	return i.did.String()
}

func (i *Identity) GetPublicKeyHex() string {
	return i.secretKey.Public().String()
}

func (i *Identity) GetID() (string, error) {
	id, err := core.IDFromDID(*i.did)
	if err != nil {
		return "", fmt.Errorf("unable to get id from identity did: %v", err)
	}

	return id.BigInt().String(), nil
}

func (i *Identity) getRevocationStatus(status *CredentialStatus) (*ProofStatus, error) {
	response, err := i.stateProvider.Fetch(status.Identifier, "GET", nil, "", "")
	if err != nil {
		return nil, fmt.Errorf("error fetching revocation status: %v", err)
	}

	revocationStatus := new(ProofStatus)
	if err := json.Unmarshal(response, &revocationStatus); err != nil {
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

func (i *Identity) GetIssuerState() (string, error) {
	if len(i.credentials) == 0 {
		return "", errors.New("no credentials found")
	}

	credential := i.credentials[0]

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

func prepareSiblings(siblings []*merkletree.Hash, size uint64) []*merkletree.Hash {
	if len(siblings) > int(size) {
		siblings = siblings[:size]
	}

	for i := len(siblings); i < int(size); i++ {
		siblings = append(siblings, &merkletree.HashZero)
	}

	return siblings
}

func Btoi(b bool) int {
	if b {
		return 1
	}
	return 0
}

package identity

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/iden3/go-iden3-crypto/babyjub"
	merkletree "github.com/rarimo/go-merkletree"
)

func NewBJJSecretKey() string {
	secretKey := babyjub.NewRandPrivKey()

	return hex.EncodeToString(secretKey[:])
}

func extendHashes(hashes []*merkletree.Hash, size uint64) []*merkletree.Hash {
	if len(hashes) > int(size) {
		hashes = hashes[:size]
	}

	for i := len(hashes); i < int(size); i++ {
		hashes = append(hashes, &merkletree.HashZero)
	}

	return hashes
}

func BigIntToString(raw string) (string, error) {
	bigInt, ok := new(big.Int).SetString(raw, 10)
	if !ok {
		return "", fmt.Errorf("error converting string to big.Int")
	}

	return string(bigInt.Bytes()), nil
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

func hexEndianSwap(hash string) string {
	if hash[:2] == "0x" {
		hash = hash[2:]
	}

	// Remove the "0x" prefix and decode the hex string
	decodedHash, err := hex.DecodeString(hash)
	if err != nil {
		return ""
	}

	// Reverse the byte order (little-endian to big-endian)
	reverseBytes(decodedHash)

	// Convert the reversed byte array back to a hex string
	convertedStateHash := hex.EncodeToString(decodedHash)

	zeroesToAddNumber := 64 - len(convertedStateHash)
	var zeroesToAdd string
	for i := 0; i < zeroesToAddNumber; i++ {
		zeroesToAdd += "0"
	}

	return convertedStateHash + zeroesToAdd
}

func reverseBytes(data []byte) {
	for i, j := 0, len(data)-1; i < j; i, j = i+1, j-1 {
		data[i], data[j] = data[j], data[i]
	}
}

func GenerateVotingCalldata(proofJson []byte, pubSignalsJson []byte) (string, error) {
	var proof ProofData
	if err := json.Unmarshal(proofJson, &proof); err != nil {
		return "", err
	}

	var a [2]*big.Int
	for index, val := range proof.A[:2] {
		a_i, ok := new(big.Int).SetString(val, 10)
		if !ok {
			return "", fmt.Errorf("error setting a[%d]: %v", index, val)
		}

		a[index] = a_i
	}

	var b [2][2]*big.Int
	for index, val := range proof.B[:2] {
		for index2, val2 := range val[:2] {
			b_i, ok := new(big.Int).SetString(val2, 10)
			if !ok {
				return "", fmt.Errorf("error setting b[%d][%d]: %v", index, index2, val2)
			}

			b[index][index2] = b_i
		}
	}

	b[0][0], b[0][1] = b[0][1], b[0][0]
	b[1][0], b[1][1] = b[1][1], b[1][0]

	var c [2]*big.Int
	for index, val := range proof.C[:2] {
		c_i, ok := new(big.Int).SetString(val, 10)
		if !ok {
			return "", fmt.Errorf("error setting c[%d]: %v", index, val)
		}

		c[index] = c_i
	}

	var pubSignals []string
	if err := json.Unmarshal(pubSignalsJson, &pubSignals); err != nil {
		return "", err
	}

	votingCoder, err := NewVotingCoder()
	if err != nil {
		return "", err
	}

	nullifierHashBigInt, ok := new(big.Int).SetString(pubSignals[0], 10)
	if !ok {
		return "", fmt.Errorf("error converting string to big.Int")
	}

	rootBigInt, ok := new(big.Int).SetString(pubSignals[1], 10)
	if !ok {
		return "", fmt.Errorf("error converting string to big.Int")
	}

	candidateBigInt, ok := new(big.Int).SetString(pubSignals[2], 10)
	if !ok {
		return "", fmt.Errorf("error converting string to big.Int")
	}

	var nullifierHash [32]byte
	copy(nullifierHash[:], nullifierHashBigInt.Bytes())

	var root [32]byte
	copy(root[:], rootBigInt.Bytes())

	var candidate [32]byte
	copy(candidate[:], candidateBigInt.Bytes())

	points := &VerifierHelperProofPoints{
		A: a,
		B: b,
		C: c,
	}

	calldata, err := votingCoder.Pack("vote", root, nullifierHash, candidate, points)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(calldata), nil
}

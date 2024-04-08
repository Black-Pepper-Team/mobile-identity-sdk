package identity

import (
	"encoding/hex"
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

	// Add "0x" prefix if necessary
	if len(convertedStateHash) < 64 {
		return "0" + convertedStateHash
	}

	return convertedStateHash
}

func reverseBytes(data []byte) {
	for i, j := 0, len(data)-1; i < j; i, j = i+1, j-1 {
		data[i], data[j] = data[j], data[i]
	}
}

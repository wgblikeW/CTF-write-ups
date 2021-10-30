package cipherfactory

import (
	"encoding/hex"
	"log"
	"math/big"
	"os"

	"github.com/ethereum/go-ethereum/crypto/secp256k1"
)

type Point struct {
	X *big.Int
	Y *big.Int
}

type EllipticCurveCSOption struct {
	EllipticCurve *secp256k1.BitCurve
	PublicKey     []*big.Int
	PrivateKey    *big.Int
}

type AesCSSetting struct {
	Key     []byte
	AesMode string
	IV      []byte
}

type Cipherimple2Operation interface {
	Encrypt([]byte) ([]byte, error)
	Decrypt([]byte) ([]byte, error)
}

func (ellipticCurveOption *EllipticCurveCSOption) CompleteEllipticCurveOption() {

	// setting ellipticCurve
	ellipticCurve := secp256k1.S256()
	ellipticCurveOption.EllipticCurve = ellipticCurve

	// setting privateKey
	privateKey_Byte, _ := hex.DecodeString(os.Getenv("PRIVATEKEY"))
	privateKey := new(big.Int).SetBytes(privateKey_Byte)
	ellipticCurveOption.PrivateKey = privateKey

	// setting publicKey
	publicKey_x, publicKey_y := ellipticCurve.ScalarBaseMult(privateKey.Bytes())
	ellipticCurveOption.PublicKey = make([]*big.Int, 2)
	ellipticCurveOption.PublicKey[0], ellipticCurveOption.PublicKey[1] = publicKey_x, publicKey_y
	log.Printf("Pubkey_x %s Pubkey_y %s", hex.EncodeToString(publicKey_x.Bytes()), hex.EncodeToString(publicKey_y.Bytes()))
}

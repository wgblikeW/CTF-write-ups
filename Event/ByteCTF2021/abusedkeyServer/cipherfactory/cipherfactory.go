package cipherfactory

import (
	"crypto/elliptic"
	"math/big"
	"os"
)

type Point struct {
	X *big.Int
	Y *big.Int
}

type EllipticCurveCSOption struct {
	EllipticCurve elliptic.Curve
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
	ellipticCurve := elliptic.P256()

	privateKey := convertStringToBigInt(os.Getenv("PRIVATEKEY"), 16)

	publicKey_X := os.Getenv("GX")
	publicKey_Y := os.Getenv("GY")
	var publicKey []*big.Int
	publicKey = append(publicKey, convertStringToBigInt(publicKey_X, 10), convertStringToBigInt(publicKey_Y, 10))

	ellipticCurveOption.EllipticCurve = ellipticCurve
	ellipticCurveOption.PrivateKey = privateKey
	ellipticCurveOption.PublicKey = publicKey
}

func convertStringToBigInt(bigIntString string, base int) *big.Int {
	bigInt := new(big.Int)
	bigInt.SetString(bigIntString, base)
	return bigInt
}

package server

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"log"
	"math/big"
	"os"

	"github.com/gorilla/securecookie"
)

func ImplementProtocol1Phase1() (string, string) {
	ellipticCurve := ellipticCurveOption.EllipticCurve
	N := ellipticCurve.N
	// t_S <- Z_p
	t_S, err := rand.Int(rand.Reader, new(big.Int).Sub(N, big.NewInt(1)))
	if err != nil {
		log.Println("Error in Generating random number")
	}

	// T_S <- t_S * G
	T_S_x, T_S_y := ellipticCurve.ScalarBaseMult(t_S.Bytes())
	T_S_hex := hex.EncodeToString(T_S_x.Bytes()) + hex.EncodeToString(T_S_y.Bytes())
	return T_S_hex, hex.EncodeToString(t_S.Bytes())
}

func ImplementProtocol1Phase3(T_C_x *big.Int, T_C_y *big.Int, t_S string) ([]byte, error) {
	t_S_BigInt, ok := new(big.Int).SetString(t_S, 16)

	if !ok {
		err := errors.New("error occured when converting string to BigInt")
		return nil, err
	}

	ellipticCurve := ellipticCurveOption.EllipticCurve

	d_S := ellipticCurveOption.PrivateKey
	publicKey_C_X_B, _ := hex.DecodeString(os.Getenv("PUBKEY_C_X"))
	publicKey_C_Y_B, _ := hex.DecodeString(os.Getenv("PUBKEY_C_Y"))
	publicKey_X := new(big.Int).SetBytes(publicKey_C_X_B)
	publicKey_Y := new(big.Int).SetBytes(publicKey_C_Y_B)

	d_S_plus_t_S := new(big.Int).Add(d_S, t_S_BigInt)

	leftpoint_x, leftpoint_y := ellipticCurve.ScalarMult(T_C_x, T_C_y, d_S_plus_t_S.Bytes())

	rightpoint_x, rightpoint_y := ellipticCurve.ScalarMult(publicKey_X, publicKey_Y, t_S_BigInt.Bytes())

	K_CS_x, _ := ellipticCurve.Add(leftpoint_x, leftpoint_y, rightpoint_x, rightpoint_y)

	return K_CS_x.Bytes(), nil
}

func ImplementSymmetricEncryption(key []byte) (string, error) {

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", errors.New("error occured when CreatingNewCipher")
	}
	block_mode, err := cipher.NewGCM(block)
	if err != nil {
		return "", errors.New("error occured when implementAESMODE_GCM")
	}
	secret := os.Getenv("SECRET")
	secret_pad, err := pkcs7Pad([]byte(secret), 16)
	if err != nil {
		return "", err
	}
	nonce := securecookie.GenerateRandomKey(12)
	ciphertext := block_mode.Seal(nil, nonce, secret_pad, nil)
	ciphertext_hex := hex.EncodeToString(ciphertext)
	nonce_hex := hex.EncodeToString(nonce)
	return nonce_hex + ciphertext_hex, nil
}

func pkcs7Pad(data []byte, blocklen int) ([]byte, error) {
	if blocklen <= 0 {
		return nil, errors.New("invalid blocklen")
	}
	padlen := 1
	for ((len(data) + padlen) % blocklen) != 0 {
		padlen = padlen + 1
	}

	pad := bytes.Repeat([]byte{byte(padlen)}, padlen)
	return append(data, pad...), nil
}

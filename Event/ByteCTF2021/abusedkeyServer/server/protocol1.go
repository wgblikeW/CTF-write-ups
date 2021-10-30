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

func ImplementProtocol1Phase1() (string, *big.Int) {
	ellipticCurveParams := ellipticCurveOption.EllipticCurve.Params()
	t_S, err := rand.Int(rand.Reader, ellipticCurveParams.P)
	if err != nil {
		log.Println("Error in Generating random number")
	}
	T_S_x, T_S_y := ellipticCurveParams.ScalarBaseMult(t_S.Bytes())
	T_S_hex := hex.EncodeToString(T_S_x.Bytes()) + hex.EncodeToString(T_S_y.Bytes())
	return T_S_hex, t_S
}

func ImplementProtocol1Phase3(T_C_x *big.Int, T_C_y *big.Int, t_S string) ([]byte, error) {
	t_S_BigInt, ok := new(big.Int).SetString(t_S, 16)
	if !ok {
		err := errors.New("error occured when converting string to BigInt")
		return nil, err
	}

	ellipticCurve := ellipticCurveOption.EllipticCurve
	N := ellipticCurveOption.EllipticCurve.Params().N

	d_S := ellipticCurveOption.PrivateKey
	d_S_plus_t_S := new(big.Int).Add(d_S, t_S_BigInt)
	d_S_plus_t_S = d_S_plus_t_S.Mod(d_S_plus_t_S, N)

	left_pointx, left_pointy := ellipticCurve.ScalarMult(T_C_x, T_C_y, d_S_plus_t_S.Bytes())
	right_pointx, right_pointy := ellipticCurve.ScalarMult(ellipticCurveOption.PublicKey[0], ellipticCurveOption.PublicKey[1], t_S_BigInt.Bytes())
	K_CS_x, _ := ellipticCurve.Add(left_pointx, left_pointy, right_pointx, right_pointy)
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

	return ciphertext_hex, nil
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

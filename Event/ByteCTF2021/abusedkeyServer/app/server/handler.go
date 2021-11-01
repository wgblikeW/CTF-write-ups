package server

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"math/big"
	"net/http"
)

var store map[string]string = make(map[string]string)

// handle HTTP GET request to /abusedkey/server/msg11
func Stage1Phase1Handler(w http.ResponseWriter, r *http.Request) {
	var dataBuffer []byte = make([]byte, 1024)
	// receive sid1 hex string 32bytes
	dataLen, _ := r.Body.Read(dataBuffer)
	defer r.Body.Close()

	msg_12, t_S := ImplementProtocol1Phase1()

	store[string(dataBuffer[0:dataLen])] = t_S

	io.WriteString(w, msg_12)
}

// handle HTTP GET request to /abusedkey/server/msg13
func Stage1Phase3Handler(w http.ResponseWriter, r *http.Request) {
	var dataBuffer []byte = make([]byte, 1024)

	// receive sid1 || T_C 32bytes in hex string
	r.Body.Read(dataBuffer)
	defer r.Body.Close()

	sid_1 := string(dataBuffer[:64]) // hex string

	// get random number t_S
	if _, exists := store[string(sid_1)]; !exists {
		io.WriteString(w, "Error occured please check your sid")
		return
	}

	T_C_x_B, _ := hex.DecodeString(string(dataBuffer[64:128]))
	T_C_y_B, _ := hex.DecodeString(string(dataBuffer[128:192]))
	T_C_x := new(big.Int).SetBytes(T_C_x_B)
	T_C_y := new(big.Int).SetBytes(T_C_y_B)

	// retrieve t_S according to sid1
	t_S := store[string(sid_1)]

	key, err := ImplementProtocol1Phase3(T_C_x, T_C_y, t_S)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	hash_key := sha256.Sum256(key)

	ciphertext, err := ImplementSymmetricEncryption(hash_key[:])
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

	io.WriteString(w, ciphertext)
}

func Stage2Phase1Handler(w http.ResponseWriter, r *http.Request) {}

func Stage2Phase3Handler(w http.ResponseWriter, r *http.Request) {}

func Stage2Phase5Handler(w http.ResponseWriter, r *http.Request) {}

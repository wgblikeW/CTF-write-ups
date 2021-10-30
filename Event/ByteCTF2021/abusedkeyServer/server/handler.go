package server

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"log"
	"math/big"
	"net/http"
)

var store map[string]string = make(map[string]string)

// handle HTTP GET request to /abusedkey/server/msg11
func Stage1Phase1Handler(w http.ResponseWriter, r *http.Request) {
	var dataBuffer []byte = make([]byte, 1024)
	dataLen, _ := r.Body.Read(dataBuffer)
	defer r.Body.Close()

	log.Printf("Stage1 Receive Data %s", string(dataBuffer))

	msg_12, t_S := ImplementProtocol1Phase1()

	store[string(dataBuffer[0:dataLen])] = t_S
	log.Printf("msg11Storage %s \n", store[string(dataBuffer)])
	io.WriteString(w, msg_12)
}

// handle HTTP GET request to /abusedkey/server/msg13
func Stage1Phase3Handler(w http.ResponseWriter, r *http.Request) {
	var dataBuffer []byte = make([]byte, 1024)

	r.Body.Read(dataBuffer)
	defer r.Body.Close()
	log.Printf("Receive Data Msg13 %s\n", string(dataBuffer))

	sid_1 := string(dataBuffer[:64])

	if _, exists := store[string(sid_1)]; !exists {
		io.WriteString(w, "Error occured please check your sid")
		return
	}
	log.Printf("T_C_x:%s T_C_y:%s", string(dataBuffer[64:128]), string(dataBuffer[128:128+64]))
	T_C_x := new(big.Int).SetBytes(dataBuffer[64:128])
	T_C_y := new(big.Int).SetBytes(dataBuffer[128 : 128+64])

	t_S := store[string(sid_1)]

	key, err := ImplementProtocol1Phase3(T_C_x, T_C_y, t_S)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	hash_key := sha256.Sum256(key)
	log.Printf("KCS_X KEY %s", hex.EncodeToString(hash_key[:]))
	ciphertext, err := ImplementSymmetricEncryption(hash_key[:])
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	log.Printf("Ciphertext: %s", ciphertext)
	io.WriteString(w, ciphertext)
}

func Stage2Phase1Handler(w http.ResponseWriter, r *http.Request) {}

func Stage2Phase3Handler(w http.ResponseWriter, r *http.Request) {}

func Stage2Phase5Handler(w http.ResponseWriter, r *http.Request) {}

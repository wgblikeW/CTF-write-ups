package server

import (
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
	//TODO: Check the dataBuffer it can't be empty
	msg_12, t_S := ImplementProtocol1Phase1()

	//TODO: Adding parmas to Storage
	store[string(dataBuffer[0:dataLen])] = t_S.String()
	log.Printf("msg11Storage %s \n", store[string(dataBuffer)])
	io.WriteString(w, msg_12)
}

func Stage1Phase3Handler(w http.ResponseWriter, r *http.Request) {
	var dataBuffer []byte = make([]byte, 1024)
	//TODO: Check dataBuffer
	r.Body.Read(dataBuffer)
	defer r.Body.Close()
	log.Printf("Receive Data Msg13 %s\n", string(dataBuffer))

	sid_1 := string(dataBuffer[:64])

	if _, exists := store[string(sid_1)]; !exists {
		io.WriteString(w, "Error occured please check your sid")
		return
	}

	T_C_x := new(big.Int).SetBytes(dataBuffer[64:128])
	T_C_y := new(big.Int).SetBytes(dataBuffer[128:])
	//TODO: Retrieve parmas from Storage
	t_S := store[string(sid_1)]

	key, err := ImplementProtocol1Phase3(T_C_x, T_C_y, t_S)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	ciphertext, err := ImplementSymmetricEncryption(key)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	log.Printf("Ciphertext: %s", ciphertext)
	io.WriteString(w, ciphertext)
}

func Stage2Phase1Handler(w http.ResponseWriter, r *http.Request) {}

func Stage2Phase3Handler(w http.ResponseWriter, r *http.Request) {}

func Stage2Phase5Handler(w http.ResponseWriter, r *http.Request) {}

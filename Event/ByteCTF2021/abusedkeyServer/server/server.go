package server

import (
	"abusedkeyServer/cipherfactory"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
)

var ellipticCurveOption *cipherfactory.EllipticCurveCSOption = new(cipherfactory.EllipticCurveCSOption)

func HandleRequests() {

	route := mux.NewRouter()

	route.HandleFunc("/abusedkey/server/msg11", Stage1Phase1Handler).Methods("GET")
	route.HandleFunc("/abusedkey/server/msg13", Stage1Phase3Handler).Methods("GET")
	route.HandleFunc("/abusedkey/server/msg21", Stage2Phase1Handler).Methods("GET")
	route.HandleFunc("/abusedkey/server/msg23", Stage2Phase3Handler).Methods("GET")
	route.HandleFunc("/abusedkey/server/msg25", Stage2Phase5Handler).Methods("GET")

	loggedRouter := handlers.LoggingHandler(os.Stdout, route)

	server := &http.Server{
		Addr:         os.Getenv("IPADDR") + os.Getenv("PORT"),
		WriteTimeout: time.Second * 15,
		ReadTimeout:  time.Second * 15,
		IdleTimeout:  time.Second * 60,
		Handler:      loggedRouter,
	}
	if err := server.ListenAndServe(); err != nil {
		log.Println(err)
	}
}

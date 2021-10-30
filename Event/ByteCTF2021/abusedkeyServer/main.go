package main

import (
	"abusedkeyServer/server"
	"log"
	"os"
)

func main() {

	log.Printf("App running on http://%s%s\n", os.Getenv("IPADDR"), os.Getenv("PORT"))
	server.HandleRequests()
}

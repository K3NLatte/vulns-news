package main

import (
	"log"
	"net/http"

	"vulns-news/server/api"
)

func main() {
	log.Println("API起動: http://127.0.0.1:8080")
	log.Fatal(http.ListenAndServe("127.0.0.1:8080", api.NewMockRouter()))
}

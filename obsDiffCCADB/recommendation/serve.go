package main

import (
	"log"
	"net/http"
)

func main() {
	http.Handle("/", http.FileServer(http.Dir("public/")))
	if err := http.ListenAndServe(":8081", nil); err != nil {
		log.Fatal(err)
	}
}

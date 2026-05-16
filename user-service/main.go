package main

import (
	"fmt"
	"net/http"
)

func usersHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "User Service Response")
}

func main() {
	http.HandleFunc("/users", usersHandler)

	fmt.Println("User service running on port 8001")
	http.ListenAndServe(":8001", nil)
}
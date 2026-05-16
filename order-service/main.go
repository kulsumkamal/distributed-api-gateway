package main

import (
	"fmt"
	"net/http"
)

func ordersHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Order Service Response")
}

func main() {
	http.HandleFunc("/orders", ordersHandler)

	fmt.Println("Order service running on port 8002")
	http.ListenAndServe(":8002", nil)
}
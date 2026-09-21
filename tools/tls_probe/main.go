package main

import (
	"crypto/tls"
	"fmt"
	"net/http"
)

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "http-server-test")
	})
	cert, err := tls.LoadX509KeyPair("/tmp/nosans.crt", "/tmp/nosans.key")
	if err != nil {
		panic(err)
	}
	srv := &http.Server{
		Addr:    ":8444",
		Handler: mux,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			NextProtos:   []string{"h2", "http/1.1"},
		},
	}
	fmt.Println("listening :8444 with net/http.Server + TLSConfig")
	err = srv.ListenAndServeTLS("", "")
	fmt.Println("exited:", err)
}

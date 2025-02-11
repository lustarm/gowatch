package api

import (
    "log"
    "fmt"
    "net/http"
    "time"
    "github.com/gorilla/mux"
)

func homeHandler(w http.ResponseWriter, r *http.Request) {
    fmt.Fprintf(w, "hello world")
}

func StartAPI() {
    r := mux.NewRouter()
    r.HandleFunc("/", homeHandler)

    srv := &http.Server {
        Handler: r,
        Addr: "0.0.0.0:8000",

        // ! good practice
        WriteTimeout: 15 * time.Second,
        ReadTimeout:  15 * time.Second,
    }

    log.Fatal(srv.ListenAndServe())
}

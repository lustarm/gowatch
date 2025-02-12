package api

import (
    "log"
    "net/http"
    "time"

    "github.com/gorilla/mux"
)

const VERSION = "v0"

func Start() {
    r := mux.NewRouter()
    r.HandleFunc("/" + VERSION, homeHandler)

    // ! config loader
    r.HandleFunc("/" + VERSION + "/config", configHandler)

    srv := &http.Server {
        Handler: r,
        Addr: "0.0.0.0:8000",

        // ! good practice
        WriteTimeout: 15 * time.Second,
        ReadTimeout:  15 * time.Second,
    }

    log.Fatal(srv.ListenAndServe())
}

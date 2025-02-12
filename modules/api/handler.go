package api

import (
	"encoding/json"
	"net/http"
    "strconv"
    "log"
    "os"

    "gowatch/modules/config"
    "gowatch/modules/packet"
)

const INVALID_REQUEST = "Invalid request"

type APIResponse map[string]interface{}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// Create a map for our JSON response
	response := map[string]string{
		"total_malicious_packets_intercepted": strconv.Itoa(packet.BadCount),
	}

	// Encode the map to JSON and write to the response writer
	json.NewEncoder(w).Encode(response)
}

func configHandler(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "application/json")

    err := json.NewDecoder(r.Body).Decode(&config.GlobalConfig)

    if err != nil {
        w.WriteHeader(http.StatusBadRequest)
        json.NewEncoder(w).Encode(APIResponse{"error" : true, "message" : INVALID_REQUEST})
        return
    }

    bytes, err := json.Marshal(config.GlobalConfig)

    // ! write config to save
    err = os.WriteFile("./data/save/config.json", bytes, 0644)

    if err != nil {
        w.WriteHeader(http.StatusInternalServerError)
        json.NewEncoder(w).Encode(APIResponse{"error" : true, "message" : "Failed to save config to file"})
        return
    }

    log.Println("Config loaded from API")

    response := APIResponse {
        "error" : false,
        "message" : "Loaded config correctly",
    }

    json.NewEncoder(w).Encode(response)
}

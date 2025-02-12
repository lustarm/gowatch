package config

import (
	"encoding/json"
	"log"
	"os"
)

// ! load config
func Load() error {
    data, err := os.ReadFile("./data/save/config.json")

    if err != nil {
        return err
    }

    err = json.Unmarshal(data, &GlobalConfig)

    if err != nil {
        return err
    }

    log.Println("Loaded config correctly")

    return nil
}

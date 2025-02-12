package config

// ! global config
var GlobalConfig Config

type Config struct {
	CaptureConfig struct {
		Interface   string `json:"interface"`
	} `json:"capture_config"`

    signal chan interface{}
}



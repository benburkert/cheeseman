package main

import (
	"cheeseman/server"
	"flag"
)

var (
	configFile = flag.String("c", "", "Config file.")
)

func main() {
	if *configFile == "" {
		panic("Missing config file (-c) argument.")
	}

	config, err := server.LoadConfig(*configFile)

	server := server.NewServer(config)

	server.Run()
}

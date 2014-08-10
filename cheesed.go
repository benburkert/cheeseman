package main

import (
	"flag"

	"github.com/benburkert/cheeseman/server"
)

var (
	configFile = flag.String("c", "", "Config file.")
)

func main() {
	if *configFile == "" {
		panic("Missing config file (-c) argument.")
	}

	config, _ := server.LoadConfig(*configFile)

	server := server.NewServer(config)

	server.Run()
}

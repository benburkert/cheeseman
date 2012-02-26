package main

import (
	"flag"
	"cheeseman/server"
)

var (
	configFile = flag.String("c", "", "Config file.")
)

func main() {
	if *configFile == "" {
		panic("Missing config file (-c) argument.")
	}

	config := server.LoadConfig(*configFile)

	server := server.NewServer(config)

	server.Run()
}

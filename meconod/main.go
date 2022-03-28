package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/jaksonkallio/mecono/meconod/server"
)

func main() {
	server, err := server.InitServer(5)
	if err != nil {
		log.Printf("Could not initialize server: %s", err)
	}

	interrupt := make(chan os.Signal, 5)
	signal.Notify(interrupt, os.Interrupt, syscall.SIGTERM)
	<-interrupt
	server.Stop()
	os.Exit(0)
}

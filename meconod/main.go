package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/jaksonkallio/mecono/meconod/network"
)

func main() {
	controllers := make([]*network.Controller, 5)

	for i := range controllers {
		controller, err := network.InitController(
			fmt.Sprintf("TN%04d", i),
			"This node is used for testing 🛠️🛠️",
		)

		if err != nil {
			log.Printf("could not initialize controller: %s", err)
		}

		controller.Start()
		controllers[i] = controller
	}

	interrupt := make(chan os.Signal, 5)
	signal.Notify(interrupt, os.Interrupt, syscall.SIGTERM)
	<-interrupt
	log.Println("stopping")
	for _, controller := range controllers {
		controller.Stop()
	}
}

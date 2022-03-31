package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/jaksonkallio/mecono/meconod/pkg/model/server"
)

func main() {
	topology, err := server.InitTopology(
		10,
		[]server.Neighborship{
			{ControllerIndexA: 0, ControllerIndexB: 1},
			{ControllerIndexA: 0, ControllerIndexB: 2},
			{ControllerIndexA: 1, ControllerIndexB: 2},
			{ControllerIndexA: 1, ControllerIndexB: 3},
			{ControllerIndexA: 1, ControllerIndexB: 7},
			{ControllerIndexA: 2, ControllerIndexB: 3},
			{ControllerIndexA: 2, ControllerIndexB: 4},
			{ControllerIndexA: 3, ControllerIndexB: 5},
			{ControllerIndexA: 3, ControllerIndexB: 8},
			{ControllerIndexA: 5, ControllerIndexB: 8},
			{ControllerIndexA: 8, ControllerIndexB: 9},
		},
	)
	if err != nil {
		log.Printf("Could not initialize server: %s", err)
	}

	/*


		server.Controllers[0].StartExchange(
			network.PingOutward,
			[]byte("arbitrary payload"),
			server.Controllers[0].LookupNode(server.Controllers[1].PublicKey),
		)
	*/

	interrupt := make(chan os.Signal, 5)
	signal.Notify(interrupt, os.Interrupt, syscall.SIGTERM)
	<-interrupt
	topology.Stop()
	os.Exit(0)
}

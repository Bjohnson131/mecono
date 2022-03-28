package server

import (
	"fmt"

	"github.com/jaksonkallio/mecono/meconod/network"
)

type Server struct {
	Controllers []*network.Controller
}

func InitServer(controllerCount uint8) (*Server, error) {
	server := &Server{}

	server.Controllers = make([]*network.Controller, controllerCount)

	for i := range server.Controllers {
		controller, err := network.InitController(
			// "TN" is short for "Test Node"
			fmt.Sprintf("TN%04d", i),
			"This node is used for testing 🛠️🛠️",
		)

		if err != nil {
			return nil, fmt.Errorf("could not initialize controller: %s", err)
		}

		controller.Start()
		server.Controllers[i] = controller
	}

	return server, nil
}

// Stops this server, which involves stopping all controllers.
func (server *Server) Stop() {
	for _, controller := range server.Controllers {
		controller.Stop()
	}
}

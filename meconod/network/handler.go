package network

import (
	"context"

	"github.com/jaksonkallio/mecono/meconod/protos"
)

func (controller *Controller) NeighborHealthCheck(ctx context.Context, req *protos.NeighborHealthCheckRequest) (*protos.NeighborHealthCheckResponse, error) {
	return &protos.NeighborHealthCheckResponse{
		Status: "healthy",
	}, nil
}

func (controller *Controller) Transmit(ctx context.Context, req *protos.TransmitRequest) (*protos.TransmitResponse, error) {
	// TODO: implement
	return &protos.TransmitResponse{
		Ok: false,
	}, nil
}

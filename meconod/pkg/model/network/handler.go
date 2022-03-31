package network

import (
	"context"

	"github.com/jaksonkallio/mecono/meconod/pkg/model/healthcheck"
)

func (controller *Controller) NeighborHealthCheck(ctx context.Context, req *healthcheck.NeighborHealthCheckRequest) (*healthcheck.NeighborHealthCheckResponse, error) {
	return &healthcheck.NeighborHealthCheckResponse{
		Status: "healthy",
	}, nil
}

func (controller *Controller) Transmit(ctx context.Context, req *healthcheck.TransmitRequest) (*healthcheck.TransmitResponse, error) {
	// TODO: implement
	return &healthcheck.TransmitResponse{
		Ok: false,
	}, nil
}

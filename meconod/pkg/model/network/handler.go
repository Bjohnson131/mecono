package network

import (
	"context"

	"github.com/jaksonkallio/mecono/meconod/pkg/model/proto"
)

func (controller *Controller) NeighborHealthCheck(ctx context.Context, req *proto.NeighborHealthCheckRequest) (*proto.NeighborHealthCheckResponse, error) {
	return &proto.NeighborHealthCheckResponse{
		Status: "healthy",
	}, nil
}

func (controller *Controller) Transmit(ctx context.Context, req *proto.TransmitRequest) (*proto.TransmitResponse, error) {
	// TODO: implement
	return &proto.TransmitResponse{
		Ok: false,
	}, nil
}

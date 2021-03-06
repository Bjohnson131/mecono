// Code generated by protoc-gen-go-grpc. DO NOT EDIT.

package proto

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.32.0 or later.
const _ = grpc.SupportPackageIsVersion7

// MeconodServiceClient is the client API for MeconodService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type MeconodServiceClient interface {
	Transmit(ctx context.Context, in *TransmitRequest, opts ...grpc.CallOption) (*TransmitResponse, error)
	NeighborHealthCheck(ctx context.Context, in *NeighborHealthCheckRequest, opts ...grpc.CallOption) (*NeighborHealthCheckResponse, error)
}

type meconodServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewMeconodServiceClient(cc grpc.ClientConnInterface) MeconodServiceClient {
	return &meconodServiceClient{cc}
}

func (c *meconodServiceClient) Transmit(ctx context.Context, in *TransmitRequest, opts ...grpc.CallOption) (*TransmitResponse, error) {
	out := new(TransmitResponse)
	err := c.cc.Invoke(ctx, "/meconod.MeconodService/Transmit", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *meconodServiceClient) NeighborHealthCheck(ctx context.Context, in *NeighborHealthCheckRequest, opts ...grpc.CallOption) (*NeighborHealthCheckResponse, error) {
	out := new(NeighborHealthCheckResponse)
	err := c.cc.Invoke(ctx, "/meconod.MeconodService/NeighborHealthCheck", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// MeconodServiceServer is the server API for MeconodService service.
// All implementations must embed UnimplementedMeconodServiceServer
// for forward compatibility
type MeconodServiceServer interface {
	Transmit(context.Context, *TransmitRequest) (*TransmitResponse, error)
	NeighborHealthCheck(context.Context, *NeighborHealthCheckRequest) (*NeighborHealthCheckResponse, error)
	mustEmbedUnimplementedMeconodServiceServer()
}

// UnimplementedMeconodServiceServer must be embedded to have forward compatible implementations.
type UnimplementedMeconodServiceServer struct {
}

func (UnimplementedMeconodServiceServer) Transmit(context.Context, *TransmitRequest) (*TransmitResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Transmit not implemented")
}
func (UnimplementedMeconodServiceServer) NeighborHealthCheck(context.Context, *NeighborHealthCheckRequest) (*NeighborHealthCheckResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method NeighborHealthCheck not implemented")
}
func (UnimplementedMeconodServiceServer) mustEmbedUnimplementedMeconodServiceServer() {}

// UnsafeMeconodServiceServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to MeconodServiceServer will
// result in compilation errors.
type UnsafeMeconodServiceServer interface {
	mustEmbedUnimplementedMeconodServiceServer()
}

func RegisterMeconodServiceServer(s grpc.ServiceRegistrar, srv MeconodServiceServer) {
	s.RegisterService(&MeconodService_ServiceDesc, srv)
}

func _MeconodService_Transmit_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(TransmitRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(MeconodServiceServer).Transmit(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/meconod.MeconodService/Transmit",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(MeconodServiceServer).Transmit(ctx, req.(*TransmitRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _MeconodService_NeighborHealthCheck_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(NeighborHealthCheckRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(MeconodServiceServer).NeighborHealthCheck(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/meconod.MeconodService/NeighborHealthCheck",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(MeconodServiceServer).NeighborHealthCheck(ctx, req.(*NeighborHealthCheckRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// MeconodService_ServiceDesc is the grpc.ServiceDesc for MeconodService service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var MeconodService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "meconod.MeconodService",
	HandlerType: (*MeconodServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Transmit",
			Handler:    _MeconodService_Transmit_Handler,
		},
		{
			MethodName: "NeighborHealthCheck",
			Handler:    _MeconodService_NeighborHealthCheck_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "protos/api.proto",
}

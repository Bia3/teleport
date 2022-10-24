// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.2.0
// - protoc             (unknown)
// source: teleport/lib/multiplexer/test/ping.proto

package test

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

// PingerClient is the client API for Pinger service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type PingerClient interface {
	Ping(ctx context.Context, in *Request, opts ...grpc.CallOption) (*Response, error)
}

type pingerClient struct {
	cc grpc.ClientConnInterface
}

func NewPingerClient(cc grpc.ClientConnInterface) PingerClient {
	return &pingerClient{cc}
}

func (c *pingerClient) Ping(ctx context.Context, in *Request, opts ...grpc.CallOption) (*Response, error) {
	out := new(Response)
	err := c.cc.Invoke(ctx, "/teleport.lib.multiplexer.test.Pinger/Ping", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// PingerServer is the server API for Pinger service.
// All implementations must embed UnimplementedPingerServer
// for forward compatibility
type PingerServer interface {
	Ping(context.Context, *Request) (*Response, error)
	mustEmbedUnimplementedPingerServer()
}

// UnimplementedPingerServer must be embedded to have forward compatible implementations.
type UnimplementedPingerServer struct {
}

func (UnimplementedPingerServer) Ping(context.Context, *Request) (*Response, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Ping not implemented")
}
func (UnimplementedPingerServer) mustEmbedUnimplementedPingerServer() {}

// UnsafePingerServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to PingerServer will
// result in compilation errors.
type UnsafePingerServer interface {
	mustEmbedUnimplementedPingerServer()
}

func RegisterPingerServer(s grpc.ServiceRegistrar, srv PingerServer) {
	s.RegisterService(&Pinger_ServiceDesc, srv)
}

func _Pinger_Ping_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(Request)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(PingerServer).Ping(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/teleport.lib.multiplexer.test.Pinger/Ping",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(PingerServer).Ping(ctx, req.(*Request))
	}
	return interceptor(ctx, in, info, handler)
}

// Pinger_ServiceDesc is the grpc.ServiceDesc for Pinger service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var Pinger_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "teleport.lib.multiplexer.test.Pinger",
	HandlerType: (*PingerServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Ping",
			Handler:    _Pinger_Ping_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "teleport/lib/multiplexer/test/ping.proto",
}

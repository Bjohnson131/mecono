#!/bin/sh

cd $(pwd)
protoc --proto_path="../" --go_out="../" --go-grpc_out=paths=source_relative:"../" --go_opt=paths=source_relative "../protos/api.proto"
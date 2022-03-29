#!/bin/sh

cd $(pwd)
protoc --proto_path="../" --go_out="../protos" "../protos/api.proto"
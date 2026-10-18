#!/bin/sh
set -eu

# 在仓库根目录执行；生成结果仅写入当前仓库。
make swagger
protoc --go-grpc_out="require_unimplemented_servers=false:." --go_out="." proto/*.proto

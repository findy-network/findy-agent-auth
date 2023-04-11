#!/bin/bash

GOPATH=${GOPATH:-`go env GOPATH`}

# MEMORY_ prefix is a memory db, not saved to file
enclaveFile="MEMORY_enclave.bolt" 

go run .. \
	$@ \
	-agency "localhost" \
	-logging "-logtostderr -v=3" \
	-origin http://localhost:8090 \
	-cert-path $GOPATH/src/github.com/findy-network/findy-agent/grpc/cert \
	-sec-file "$enclaveFile" \
	-sec-backup-interval 100 \
	-port 8090

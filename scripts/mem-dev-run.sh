#!/bin/bash

AUTH=${AUTH:-"go run .."}
GOPATH=${GOPATH:-`go env GOPATH`}
CERT_PATH=${CERT_PATH:-""}

echo "CERT_PATH: $CERT_PATH"

# MEMORY_ prefix is a memory db, not saved to file
enclaveFile="MEMORY_enclave.bolt" 

go run .. \
	-agency "localhost" \
	-logging "-logtostderr -v=3" \
	-origin http://localhost:8090 \
	-cert-path=$CERT_PATH \
	-sec-file "$enclaveFile" \
	-sec-backup-interval 100 \
	-port 8090 $@ 

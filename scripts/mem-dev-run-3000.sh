#!/bin/bash

# MEMORY_ prefix is a memory db, not saved to file
enclaveFile="MEMORY_enclave.bolt" 
port=${port:="3000"}

go run .. \
	-agency "localhost" \
	-logging "-logtostderr -v=5" \
	-origin "http://localhost:$port" \
	-cert-path $GOPATH/src/github.com/findy-network/findy-common-go/cert \
	-sec-file "$enclaveFile" \
	-sec-backup-interval 100 \
	-port "$port" \
	$@ 

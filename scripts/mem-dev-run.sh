#!/bin/bash

enclaveFile="mem-enclave.bolt" 
rm -v "$enclaveFile"

go run .. \
	$@ \
	-agency "localhost" \
	-logging "-logtostderr -v=3" \
	-origin http://localhost:8090 \
	-cert-path $GOPATH/src/github.com/findy-network/findy-common-go/cert \
	-sec-file "$enclaveFile" \
	-sec-backup-interval 100 \
	-port 8090

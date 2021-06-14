#!/bin/bash

go run .. \
	$@ \
	-logging "-logtostderr -v=3" \
	-origin http://localhost:8090 \
	-cert-path $GOPATH/src/github.com/findy-network/findy-common-go/cert \
	-port 8090

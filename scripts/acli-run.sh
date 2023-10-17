#!/bin/bash

auth \
	-logging "-logtostderr -v=3" \
	-origin https://localhost:8090 \
	-cert-path $GOPATH/src/github.com/findy-network/findy-common-go/cert \
	-port 8090 \
	$@ 

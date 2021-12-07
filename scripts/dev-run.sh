#!/bin/bash

go run .. \
	$@ \
	-agency "localhost" \
	-logging "-logtostderr -v=3" \
	-origin http://localhost:8090 \
	-cert-path $GOPATH/src/github.com/findy-network/findy-common-go/cert \
	-sec-backup-interval 100 \
	-port 8090

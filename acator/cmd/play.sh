#!/bin/bash

url=${FCLI_URL:-"http://localhost:3000"}
lvl=${lvl:-"-logtostderr=false -v=0"}

go run main.go -url "$url" \
	-logging "$lvl" \
 \
	-log-begin-met 'POST' \
	-log-begin '%s/assertion/options' \
	-log-finish '%s/assertion/result' \
	-log-begin-pl '{"username":"%s"}' \
	-log-begin-pl-middle '{"publicKey": %s}' \
 \
	-reg-begin-met 'POST' \
	-reg-begin '%s/attestation/options' \
	-reg-finish '%s/attestation/result' \
	-reg-begin-pl '{"username":"%s"}' \
	-reg-begin-pl-middle '{"publicKey": %s}' \
	$@

module github.com/findy-network/findy-agent-auth

go 1.16

require (
	github.com/duo-labs/webauthn v0.0.0-20200714211715-1daaee874e43
	github.com/duo-labs/webauthn.io v0.0.0-20200929144140-c031a3e0f95d
	github.com/findy-network/findy-agent-api v0.0.0-20210203142917-ee7d471ffd4b // indirect
	github.com/findy-network/findy-common-go v0.1.2-0.20210421160228-49a5213c3ab5
	github.com/findy-network/findy-wrapper-go v0.0.0-20210302063517-bb98c7f07ea4
	github.com/fxamacker/cbor/v2 v2.2.0
	github.com/golang/glog v0.0.0-20160126235308-23def4e6c14b
	github.com/google/uuid v1.2.0
	github.com/gorilla/mux v1.8.0
	github.com/lainio/err2 v0.6.1
	github.com/rs/cors v1.7.0
	github.com/stretchr/testify v1.7.0
	golang.org/x/net v0.0.0-20210226172049-e18ecbb05110
)

replace github.com/findy-network/findy-common-go => ../findy-common-go

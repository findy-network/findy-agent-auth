S3_TOOL_ASSET_PATH := https://$(HTTPS_PREFIX)api.github.com/repos/findy-network/findy-common-go/releases/assets/34026533

API_BRANCH=$(shell ./branch.sh ../findy-agent-api/)
COMM_BRANCH=$(shell ./branch.sh ../findy-common-go/)

scan:
	@./scan.sh $(ARGS)

drop_comm:
	go mod edit -dropreplace github.com/findy-network/findy-common-go

drop_api:
	go mod edit -dropreplace github.com/findy-network/findy-agent-api

drop_all: drop_api drop_comm

repl_comm:
	go mod edit -replace github.com/findy-network/findy-common-go=../findy-common-go

repl_api:
	go mod edit -replace github.com/findy-network/findy-agent-api=../findy-agent-api

repl_all: repl_api repl_comm

modules: modules_comm modules_api

modules_comm: drop_comm
	@echo Syncing modules: findy-common-api/$(COMM_BRANCH)
	go get github.com/findy-network/findy-common-go@$(COMM_BRANCH)

modules_api: drop_api
	@echo Syncing modules: findy-agent-api/$(API_BRANCH)
	go get github.com/findy-network/findy-agent-api@$(API_BRANCH)

build:
	go build ./...

vet:
	go vet ./...

shadow:
	@echo Running govet
	go vet -vettool=$(GOPATH)/bin/shadow ./...
	@echo Govet success

check_fmt:
	$(eval GOFILES = $(shell find . -name '*.go'))
	@gofmt -l $(GOFILES)

lint:
	@golangci-lint run

lint_e:
	@$(GOPATH)/bin/golint ./... | grep -v export | cat

test:
	go test -v -p 1 -failfast ./...

logged_test:
	go test -v -p 1 -failfast ./... -args -logtostderr=true -v=10

test_cov:
	go test -v -p 1 -failfast -coverprofile=c.out ./... && go tool cover -html=c.out

check: check_fmt vet shadow

dclean:
	-docker rmi findy-agent-auth

dbuild:
	@[ "${HTTPS_PREFIX}" ] || ( echo "ERROR: HTTPS_PREFIX <{githubUser}:{githubToken}@> is not set"; exit 1 )
	mkdir -p .docker
	curl -L -H "Accept:application/octet-stream" "$(S3_TOOL_ASSET_PATH)" > .docker/s3-copy
	docker build \
		--build-arg HTTPS_PREFIX=$(HTTPS_PREFIX) \
		-t findy-agent-auth \
		.

drun:
	docker run -it --rm -p 8888:8888 findy-agent-auth

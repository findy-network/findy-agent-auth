COMM_BRANCH=$(shell ./scripts/branch.sh ../findy-common-go/)
SCAN_SCRIPT_URL="https://raw.githubusercontent.com/findy-network/setup-go-action/master/scanner/cp_scan.sh"

auth:
	go build -o $(GOPATH)/bin/auth

cli: auth

scan:
	@curl -s $(SCAN_SCRIPT_URL) | bash

scan_and_report:
	@curl -s $(SCAN_SCRIPT_URL) | bash -s v > licenses.txt

drop_comm:
	go mod edit -dropreplace github.com/findy-network/findy-common-go

drop_all: drop_comm

repl_comm:
	go mod edit -replace github.com/findy-network/findy-common-go=../findy-common-go

repl_all: repl_comm

modules: modules_comm

modules_comm: drop_comm
	@echo Syncing modules: findy-common-go/$(COMM_BRANCH)
	go get github.com/findy-network/findy-common-go@$(COMM_BRANCH)

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

test_cov_out:
	go test \
		-coverpkg=github.com/findy-network/findy-agent-auth/... \
		-coverprofile=coverage.txt  \
		-covermode=atomic \
		./...


test_cov: test_cov_out
	go tool cover -html=coverage.txt

check: check_fmt vet shadow

dclean:
	-docker rmi findy-agent-auth

dbuild:
	docker build -t findy-agent-auth .

drun:
	docker run -it --rm -p 8888:8888 findy-agent-auth

release:
	gh workflow run do-release.yml

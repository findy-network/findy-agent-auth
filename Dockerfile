FROM golang:1.16-alpine3.13

ARG HTTPS_PREFIX

ENV GOPRIVATE "github.com/findy-network"

RUN apk update && \
    apk add git && \
    git config --global url."https://"${HTTPS_PREFIX}"github.com/".insteadOf "https://github.com/"

WORKDIR /work

COPY go.* ./
RUN go mod download

COPY . ./

RUN go build -o /go/bin/findy-agent-auth

FROM alpine:3.13

COPY --from=0 /go/bin/findy-agent-auth /findy-agent-auth

COPY .docker/s3-copy /s3-copy

RUN chmod a+x /s3-copy

# override when running
ENV FAA_PORT "8888"
ENV FAA_AGENCY_ADDR "localhost"
ENV FAA_AGENCY_PORT "50051"
ENV FAA_DOMAIN "localhost"
ENV FAA_ORIGIN "http://localhost:8888"
ENV FAA_JWT_VERIFICATION_KEY "mySuperSecretKeyLol"

RUN echo '/s3-copy $STARTUP_FILE_STORAGE_S3 grpc /' > /start.sh && \
    echo '/findy-agent-auth \
    --port $FAA_PORT \
    --agency $FAA_AGENCY_ADDR \
    --gport $FAA_AGENCY_PORT \
    --domain $FAA_DOMAIN \
    --origin $FAA_ORIGIN \
    --sec-file "/data/fido-enclave.bolt" \
    --cert-path /grpc \
    --logging "-logtostderr=true -v=3" \
    --jwt-secret $FAA_JWT_VERIFICATION_KEY' >> /start.sh && chmod a+x /start.sh


ENTRYPOINT ["/bin/sh", "-c", "/start.sh"]

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

FROM  ghcr.io/findy-network/findy-base:alpine-3.13

COPY --from=0 /go/bin/findy-agent-auth /findy-agent-auth

# override when running
ENV FAA_PORT "8888"
ENV FAA_AGENCY_ADDR "localhost"
ENV FAA_AGENCY_PORT "50051"
ENV FAA_AGENCY_ADMIN_ID "findy-root"
ENV FAA_DOMAIN "localhost"
ENV FAA_ORIGIN "http://localhost:8888"
ENV FAA_JWT_VERIFICATION_KEY "mySuperSecretKeyLol"
ENV FAA_SEC_KEY "15308490f1e4026284594dd08d31291bc8ef2aeac730d0daf6ff87bb92d4336c"

RUN echo '/s3-copy $STARTUP_FILE_STORAGE_S3 grpc /' > /start.sh && \
    echo '/findy-agent-auth \
    --port $FAA_PORT \
    --agency $FAA_AGENCY_ADDR \
    --gport $FAA_AGENCY_PORT \
    --admin $FAA_AGENCY_ADMIN_ID \
    --domain $FAA_DOMAIN \
    --origin $FAA_ORIGIN \
    --sec-file "/data/fido-enclave.bolt" \
    --sec-key $FAA_SEC_KEY \
    --cert-path /grpc \
    --logging "-logtostderr=true -v=3" \
    --jwt-secret $FAA_JWT_VERIFICATION_KEY' >> /start.sh && chmod a+x /start.sh


ENTRYPOINT ["/bin/sh", "-c", "/start.sh"]

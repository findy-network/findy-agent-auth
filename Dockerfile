FROM golang:1.21-alpine3.18

ARG GOBUILD_ARGS=""

WORKDIR /work

COPY go.* ./
RUN go mod download

COPY . ./

RUN go build ${GOBUILD_ARGS} -o /go/bin/findy-agent-auth

FROM alpine:3.18

LABEL org.opencontainers.image.source https://github.com/findy-network/findy-agent-auth

# used when running instrumented binary
ENV GOCOVERDIR /coverage

COPY --from=0 /go/bin/findy-agent-auth /findy-agent-auth

# override when running
ENV FAA_PORT "8888"
ENV FAA_AGENCY_ADDR "localhost"
ENV FAA_AGENCY_PORT "50051"
ENV FAA_AGENCY_INSECURE "false"
ENV FAA_AGENCY_ADMIN_ID "findy-root"
ENV FAA_DOMAIN "localhost"
ENV FAA_ORIGIN "http://localhost:8888"
ENV FAA_JWT_VERIFICATION_KEY "mySuperSecretKeyLol"
ENV FAA_SEC_KEY "15308490f1e4026284594dd08d31291bc8ef2aeac730d0daf6ff87bb92d4336c"
ENV FAA_LOG_LEVEL "3"
ENV FAA_ENABLE_CORS "false"
ENV FAA_LOCAL_TLS "false"
ENV FAA_TIMEOUT_SECS "30"
ENV FAA_CERT_PATH "/grpc"

RUN echo '#!/bin/sh' > /start.sh && \
  echo 'exec /findy-agent-auth \
  --port="$FAA_PORT" \
  --agency="$FAA_AGENCY_ADDR" \
  --agency-insecure="$FAA_AGENCY_INSECURE" \
  --gport="$FAA_AGENCY_PORT" \
  --admin="$FAA_AGENCY_ADMIN_ID" \
  --domain="$FAA_DOMAIN" \
  --origin="$FAA_ORIGIN" \
  --sec-file="/data/fido-enclave.bolt" \
  --sec-key="$FAA_SEC_KEY" \
  --cert-path="$FAA_CERT_PATH" \
  --logging="-logtostderr=true -v=$FAA_LOG_LEVEL" \
  --cors="$FAA_ENABLE_CORS" \
  --local-tls="$FAA_LOCAL_TLS" \
  --jwt-secret="$FAA_JWT_VERIFICATION_KEY" \
  --timeout="$FAA_TIMEOUT_SECS"' >> /start.sh && chmod a+x /start.sh


ENTRYPOINT ["/bin/sh", "-c", "/start.sh"]

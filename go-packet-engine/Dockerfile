FROM golang:1.22-alpine AS builder
RUN apk add --no-cache libpcap-dev gcc musl-dev
WORKDIR /build
COPY . .
RUN go mod tidy && CGO_ENABLED=1 GOOS=linux go build -ldflags="-w -s" \
    -o /bin/packet-engine ./cmd/engine

FROM alpine:3.19
RUN apk add --no-cache libpcap libcap
COPY --from=builder /bin/packet-engine /bin/packet-engine
ENTRYPOINT ["/bin/packet-engine"]

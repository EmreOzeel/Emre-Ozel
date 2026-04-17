FROM golang:1.22-alpine AS builder
RUN apk add --no-cache gcc musl-dev libpcap-dev
WORKDIR /build
COPY . .
RUN go mod tidy && CGO_ENABLED=1 GOOS=linux go build -ldflags="-w -s" \
    -o /bin/go-backend ./cmd/server

FROM alpine:3.19
RUN apk add --no-cache libpcap tshark ca-certificates
RUN adduser -D -u 1000 appuser
USER appuser
EXPOSE 8000
COPY --from=builder /bin/go-backend /bin/go-backend
ENTRYPOINT ["/bin/go-backend"]

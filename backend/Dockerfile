FROM golang:1.21-alpine AS builder

# Install libpcap build dependencies
RUN apk add --no-cache gcc musl-dev libpcap-dev

WORKDIR /app

COPY . .
RUN go mod tidy
RUN CGO_ENABLED=1 GOOS=linux go build -mod=mod -o /app/server .

# -------------------------
FROM alpine:3.19

# Runtime dependencies
RUN apk add --no-cache libpcap ca-certificates tzdata

WORKDIR /app

COPY --from=builder /app/server .

# Create data directory
RUN mkdir -p /data/uploads

EXPOSE 8080

CMD ["./server"]

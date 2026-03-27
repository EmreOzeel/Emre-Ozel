FROM golang:1.21-alpine AS builder

WORKDIR /app

COPY . .
RUN go mod tidy && CGO_ENABLED=0 GOOS=linux go build -mod=mod -o /app/server .

# -------------------------
FROM alpine:3.19

RUN apk add --no-cache ca-certificates tzdata

WORKDIR /app

COPY --from=builder /app/server .

RUN mkdir -p /data/uploads

EXPOSE 8080

CMD ["./server"]

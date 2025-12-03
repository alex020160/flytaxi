# build stage
FROM golang:1.22-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN go build -o api ./cmd/api

# run stage
FROM alpine:3.19

WORKDIR /app
COPY --from=builder /app/api /app/api

ENV HTTP_PORT=8080

EXPOSE 8080

CMD ["/app/api"]

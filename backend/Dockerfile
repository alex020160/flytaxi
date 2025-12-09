FROM golang:1.24 AS builder

ENV GOFLAGS=
ENV GOTOOLCHAIN=auto

WORKDIR /app

# Сначала только go.mod/go.sum — лучше кэшируются зависимости
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Приводим зависимости в порядок (если что-то поменялось в коде)
RUN go mod tidy

# Собираем бинарник
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o api ./cmd/api

# финальный образ
FROM gcr.io/distroless/base-debian12

WORKDIR /app
COPY --from=builder /app/api /app/api

ENV HTTP_PORT=8080
EXPOSE 8080

CMD ["/app/api"]

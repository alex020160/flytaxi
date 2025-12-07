# ====================== API (backend) ======================

# Берём свежий Go, который подходит всем зависимостям (>=1.24)
FROM golang:1.24 AS builder

# На всякий случай не даём Go использовать -mod=readonly из внешних переменных
ENV GOFLAGS=
ENV GOTOOLCHAIN=auto

WORKDIR /app

# Сначала только go.mod/go.sum — лучше кэшируются зависимости
COPY go.mod go.sum ./
RUN go mod download

# Теперь копируем весь остальной код
COPY . .

# Приводим зависимости в порядок (если что-то поменялось в коде)
RUN go mod tidy

# Собираем бинарник
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o api ./cmd/api

# ----- финальный образ (можно оставить одноступенчатый, но сделаем slim) -----
FROM gcr.io/distroless/base-debian12

WORKDIR /app
COPY --from=builder /app/api /app/api

ENV HTTP_PORT=8080
EXPOSE 8080

CMD ["/app/api"]

# pp/Dockerfile
FROM golang:1.23-alpine AS builder

WORKDIR /app

# Копируем зависимости
COPY go.mod go.sum ./
RUN go mod download

# Копируем весь код
COPY . .

# Сборка: указываем путь к main.go
RUN CGO_ENABLED=0 GOOS=linux go build -o main ./cmd/main.go

# Финальный образ
FROM alpine:latest

WORKDIR /app

# Копируем бинарник
COPY --from=builder /app/main .

# Копируем .env (если нужен)
COPY .env ./

EXPOSE 8080

CMD ["./main"]
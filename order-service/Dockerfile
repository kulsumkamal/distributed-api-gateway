FROM golang:1.24

WORKDIR /app

COPY . .

RUN go mod tidy

RUN go build -o order-service .

EXPOSE 8002

CMD ["./order-service"]
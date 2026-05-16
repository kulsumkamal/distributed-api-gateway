FROM golang:1.24

WORKDIR /app

COPY . .

RUN go mod tidy

RUN go build -o user-service .

EXPOSE 8001

CMD ["./user-service"]
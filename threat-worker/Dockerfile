FROM golang:1.24

WORKDIR /app

COPY . .

RUN go mod tidy

RUN go build -o threat-worker .

EXPOSE 8000

CMD ["./threat-worker"]
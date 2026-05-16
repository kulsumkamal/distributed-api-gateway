package main

import (
	"context"
	"encoding/json"
	"log"
	"time"

	amqp "github.com/rabbitmq/amqp091-go"
	"github.com/redis/go-redis/v9"
)

type SecurityEvent struct {
	IP        string `json:"ip"`
	Path      string `json:"path"`
	EventType string `json:"event_type"`
	Timestamp string `json:"timestamp"`
}

var ctx = context.Background()

func main() {

	// Redis
	rdb := redis.NewClient(&redis.Options{
		Addr: "redis:6379",
	})

	// RabbitMQ
	conn, _ := amqp.Dial("amqp://guest:guest@rabbitmq:5672/")
	ch, _ := conn.Channel()

	msgs, _ := ch.Consume(
		"security_events",
		"",
		true,
		false,
		false,
		false,
		nil,
	)

	log.Println("Threat worker started...")

	for msg := range msgs {

		var event SecurityEvent

		json.Unmarshal(msg.Body, &event)

		log.Printf(
			"[THREAT EVENT] IP=%s Type=%s",
			event.IP,
			event.EventType,
		)

		// Example action:
		if event.EventType == "suspicious_payload" {

			rdb.Set(
				ctx,
				"blocked:"+event.IP,
				"true",
				time.Minute*15,
			)

			log.Printf("[BLOCKED] %s", event.IP)
		}
	}
}

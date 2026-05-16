package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	amqp "github.com/rabbitmq/amqp091-go"
	"github.com/redis/go-redis/v9"
)

var jwtSecret = []byte("my-secret-key")

var ctx = context.Background()

var rdb = redis.NewClient(&redis.Options{
	Addr: "redis:6379",
})

var (
	requestCount = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "gateway_requests_total",
			Help: "Total number of requests",
		},
		[]string{"method", "endpoint"},
	)

	requestLatency = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "gateway_request_latency_seconds",
			Help:    "Request latency",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"endpoint"},
	)

	blockedRequests = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "gateway_blocked_requests_total",
			Help: "Total blocked requests",
		},
	)
)

type SecurityEvent struct {
	IP        string `json:"ip"`
	Path      string `json:"path"`
	EventType string `json:"event_type"`
	Timestamp string `json:"timestamp"`
}

type responseRecorder struct {
	http.ResponseWriter
	statusCode int
	startTime  time.Time
}

func failOnError(err error, msg string) {
	if err != nil {
		log.Fatal("%s: %s", msg, err)
	}
}

func (r *responseRecorder) WriteHeader(statusCode int) {
	r.statusCode = statusCode
	r.ResponseWriter.WriteHeader(statusCode)
}

func getIP(r *http.Request) string {
	ip := strings.Split(r.RemoteAddr, ":")[0]
	return ip
}

// create reverse proxy
func createProxy(target string) *httputil.ReverseProxy {
	url, _ := url.Parse(target)
	return httputil.NewSingleHostReverseProxy(url)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	// Fake user validation (replace later with DB)
	username := r.URL.Query().Get("username")

	if username == "" {
		http.Error(w, "Missing username", http.StatusBadRequest)
		return
	}

	// Create token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"username": username,
		"exp":      time.Now().Add(time.Hour * 1).Unix(),
	})

	tokenString, err := token.SignedString(jwtSecret)
	if err != nil {
		http.Error(w, "Error generating token", http.StatusInternalServerError)
		return
	}

	w.Write([]byte(tokenString))
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		requestID := time.Now().UnixNano()

		rec := &responseRecorder{
			ResponseWriter: w,
			statusCode:     200,
			startTime:      time.Now(),
		}

		next.ServeHTTP(rec, r)

		latency := time.Since(rec.startTime)

		requestCount.WithLabelValues(
			r.Method,
			r.URL.Path,
		).Inc()

		requestLatency.WithLabelValues(
			r.URL.Path,
		).Observe(latency.Seconds())

		log.Printf(
			"[REQUEST][ID: %d] %s %s | Status: %d | Latency: %v | IP: %s",
			requestID,
			r.Method,
			r.URL.Path,
			rec.statusCode,
			latency,
			r.RemoteAddr,
		)
	})
}

func jwtMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		authHeader := r.Header.Get("Authorization")

		if authHeader == "" {
			http.Error(w, "Missing token", http.StatusUnauthorized)
			return
		}

		if !strings.HasPrefix(authHeader, "Bearer ") {
			http.Error(w, "Invalid format", http.StatusUnauthorized)
			return
		}

		// Expected format: "Bearer <token>"
		tokenString := authHeader[len("Bearer "):]

		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			return jwtSecret, nil
		})

		if err != nil || !token.Valid {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			key := "failed_auth:" + getIP(r)

			count, _ := rdb.Incr(ctx, key).Result()

			if count == 1 {
				rdb.Expire(ctx, key, time.Minute*5)
			}

			if count > 5 {
				log.Printf("[THREAT] Brute force detected from %s", getIP(r))

				rdb.Set(ctx,
					"blocked:"+getIP(r),
					"true",
					time.Minute*15,
				)
			}
			return
		}

		claims := token.Claims.(jwt.MapClaims)
		username := claims["username"]
		w.Header().Set("X-User", username.(string))

		next.ServeHTTP(w, r)
	})
}

func rateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		claims := r.Context().Value("user")
		user := claims.(string)

		if user == "" {
			user = getIP(r) // fallback to IP
		}

		key := "rate_limit:" + user

		// increment request count
		count, err := rdb.Incr(ctx, key).Result()
		if err != nil {
			http.Error(w, "Redis error", http.StatusInternalServerError)
			return
		}

		// set expiry (1 minute window)
		if count == 1 {
			rdb.Expire(ctx, key, time.Minute)
		}

		// limit check
		if count > 10 {
			http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func securityMiddleware(next http.Handler, ch *amqp.Channel, q amqp.Queue) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		ip := getIP(r)

		// Check blacklist
		blocked, err := rdb.Get(ctx, "blocked:"+ip).Result()

		if err == nil && blocked == "true" {
			http.Error(w, "IP blocked", http.StatusForbidden)
			return
		}

		// Detect malicious payloads
		query := r.URL.RawQuery

		suspiciousPatterns := []string{
			"' OR 1=1",
			"<script>",
			"DROP TABLE",
		}

		for _, pattern := range suspiciousPatterns {
			if strings.Contains(strings.ToUpper(query), strings.ToUpper(pattern)) {

				log.Printf("[THREAT] Suspicious payload from %s | Pattern: %s",
					ip, pattern)

				// 3. Publish async event
				event := SecurityEvent{
					IP:        ip,
					Path:      r.URL.Path,
					EventType: "suspicious_payload",
					Timestamp: time.Now().Format(time.RFC3339),
				}

				body, _ := json.Marshal(event)

				err := ch.Publish(
					"",
					q.Name,
					false,
					false,
					amqp.Publishing{
						ContentType: "application/json",
						Body:        body,
					},
				)

				if err != nil {
					log.Printf("RabbitMQ publish error: %v", err)
				}

				blockedRequests.Inc()

				http.Error(w, "Suspicious request detected", http.StatusForbidden)
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}

func main() {
	userService := createProxy("http://http://user-service:8001")
	orderService := createProxy("http://http://order-service:8002")

	prometheus.MustRegister(
		requestCount,
		requestLatency,
		blockedRequests,
	)

	conn, err := amqp.Dial("amqp://guest:guest@rabbitmq:5672/")
	failOnError(err, "Failed to connect to RabbitMQ")

	ch, err := conn.Channel()
	failOnError(err, "Failed to open a channel")

	q, err := ch.QueueDeclare(
		"security_events",
		true,
		false,
		false,
		false,
		nil,
	)
	failOnError(err, "Failed to declare queue")

	http.HandleFunc("/login", loginHandler)

	http.Handle("/users",
		loggingMiddleware(
			securityMiddleware(
				jwtMiddleware(
					rateLimitMiddleware(
						http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
							userService.ServeHTTP(w, r)
						}),
					),
				),
				ch,
				q,
			),
		),
	)

	http.Handle("/orders",
		loggingMiddleware(
			jwtMiddleware(
				rateLimitMiddleware(
					http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						log.Println("Routing to order-service")
						orderService.ServeHTTP(w, r)
					}),
				),
			),
		),
	)

	http.Handle("/metrics", promhttp.Handler())

	log.Println("Gateway running on port 8000")
	http.ListenAndServe(":8000", nil)
}

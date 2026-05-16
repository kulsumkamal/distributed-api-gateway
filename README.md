# Distributed API Gateway & Threat Detection Platform

## Overview

This project is a distributed API gateway and security platform built in Go. It simulates how modern production-grade infrastructure systems protect backend services from abuse, malicious traffic, and unauthorized access.

The system acts as a centralized gateway that:

* Routes requests to backend microservices
* Authenticates users using JWT
* Applies distributed rate limiting with Redis
* Detects suspicious traffic patterns
* Processes security events asynchronously using RabbitMQ
* Blocks malicious IPs in real time
* Exposes observability metrics using Prometheus
* Visualizes metrics through Grafana

---

# Features

## API Gateway

* Reverse proxy request routing
* Routes requests to backend microservices
* Centralized request handling

## Authentication

* JWT-based authentication
* Middleware-based request validation
* Protected endpoints

## Rate Limiting

* Redis-backed distributed rate limiting
* Per-client request throttling
* Abuse prevention

## Threat Detection

* SQL injection pattern detection
* XSS pattern detection
* Brute-force attack detection
* Real-time IP blacklisting

## Asynchronous Security Processing

* RabbitMQ-based event pipeline
* Security events processed asynchronously
* Decoupled threat analysis architecture

## Observability

* Prometheus metrics exposure
* Request latency tracking
* Request count monitoring
* Blocked request metrics
* Grafana dashboards

## Containerization

* Dockerized services
* Docker Compose orchestration
* Multi-service local deployment

---

# System Architecture

```text
                ┌─────────────┐
                │   Client    │
                └──────┬──────┘
                       │
                       ▼
              ┌─────────────────┐
              │   API Gateway   │
              └──────┬──────────┘
                     │
      ┌──────────────┼──────────────┐
      │              │              │
      ▼              ▼              ▼
┌──────────┐   ┌──────────┐   ┌────────────┐
│ Logging  │   │ JWT Auth │   │ Rate Limit │
└──────────┘   └──────────┘   └────────────┘
      │
      ▼
┌─────────────────────┐
│ Threat Detection    │
│ Middleware          │
└──────────┬──────────┘
           │
           ▼
     ┌─────────────┐
     │ RabbitMQ    │
     └──────┬──────┘
            │
            ▼
     ┌─────────────┐
     │ Threat      │
     │ Worker      │
     └──────┬──────┘
            │
            ▼
        ┌───────┐
        │ Redis │
        └───────┘

```

---

# Tech Stack

| Category              | Technologies       |
| --------------------- | ------------------ |
| Language              | Go                 |
| API Gateway           | net/http, httputil |
| Authentication        | JWT                |
| Cache / Rate Limiting | Redis              |
| Message Broker        | RabbitMQ           |
| Monitoring            | Prometheus         |
| Visualization         | Grafana            |
| Containerization      | Docker             |
| Orchestration         | Docker Compose     |

---

# Request Flow

## Normal Request

```text
Client Request
    ↓
API Gateway
    ↓
JWT Validation
    ↓
Rate Limiting
    ↓
Threat Detection
    ↓
Backend Service
```

## Malicious Request

```text
Malicious Request
       ↓
Threat Detection Middleware
       ↓
RabbitMQ Security Event
       ↓
Threat Worker
       ↓
Redis Blacklist Update
       ↓
Future Requests Blocked
```

---

# Setup Instructions

## Prerequisites

Install:

* Docker
* Docker Compose

Optional:

* Go 1.24+
* Postman

---

# Running the Project

## 1. Clone Repository

```bash
git clone <your-repo-url>
cd api-gateway-project
```

---

## 2. Build and Start Services

```bash
docker compose up --build
```

This starts:

* API Gateway
* User Service
* Order Service
* Threat Worker
* Redis
* RabbitMQ
* Prometheus
* Grafana

---

# Service URLs

| Service            | URL                                              |
| ------------------ | ------------------------------------------------ |
| API Gateway        | [http://localhost:8000](http://localhost:8000)   |
| User Service       | [http://localhost:8001](http://localhost:8001)   |
| Order Service      | [http://localhost:8002](http://localhost:8002)   |
| RabbitMQ Dashboard | [http://localhost:15672](http://localhost:15672) |
| Prometheus         | [http://localhost:9090](http://localhost:9090)   |
| Grafana            | [http://localhost:3000](http://localhost:3000)   |

RabbitMQ credentials:

```text
username: guest
password: guest
```

Grafana default credentials:

```text
username: admin
password: admin
```

---

# Authentication Flow

## Generate JWT Token

```http
GET /login?username=test
```

Response:

```text
<jwt-token>
```

---

## Access Protected Endpoint

Add header:

```text
Authorization: Bearer <token>
```

Example:

```http
GET /users
```

---

# Threat Detection Examples

## SQL Injection Attempt

```http
GET /users?id=' OR 1=1
```

## XSS Attempt

```http
GET /users?q=<script>alert(1)</script>
```

These requests:

* trigger threat detection
* publish security events to RabbitMQ
* update Redis blacklist
* block future requests

---

# Monitoring

## Prometheus Metrics

Metrics endpoint:

```text
http://localhost:8000/metrics
```

Example metrics:

* request count
* request latency
* blocked requests
* auth failures

---

## Grafana Dashboards

Grafana visualizes:

* traffic volume
* latency trends
* blocked IPs
* attack frequency
* request throughput

---

# Example Security Events

```text
[THREAT EVENT] Suspicious payload from 192.168.1.10
```

```text
[BLOCKED] 192.168.1.10
```

---

# Future Improvements

Planned enhancements:

* Kubernetes deployment
* Distributed tracing
* Sliding-window rate limiting
* Token bucket algorithm
* Kafka integration
* Persistent threat analytics
* Machine-learning anomaly detection
* Centralized log aggregation
* TLS termination
* Role-based access control (RBAC)

---
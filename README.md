# AI-Powered Behavioral Cyber Threat Detection Platform

A self-hosted, real-time behavioral cyber threat detection and compromise assessment platform.

## Mission

The system learns normal behavior across users, systems, hosts, IPs, firewalls, routers, and applications. It detects suspicious deviations that can indicate account compromise, insider misuse, reconnaissance, lateral movement, command-and-control activity, compromised servers, or data exfiltration.

## Architecture

- Apache Kafka (KRaft) and Schema Registry: event backbone and data contracts
- Apache Flink: real-time event-time feature engineering
- OpenSearch and Dashboards: hot logs and investigation
- ClickHouse: behavioral feature and analytical tables
- Apache Iceberg, MinIO, and Nessie: versioned historical lakehouse
- PostgreSQL: metadata, alerts, configuration, and RBAC
- Neo4j: entity graph and attack-path analysis
- Python ML and Go services: detection, scoring, APIs, and collection
- React + TypeScript: SOC dashboard
- Docker Compose, k3s, Helm, Terraform, Prometheus, and Grafana: deployment and observability

## Current phase

Phase 0: local environment, repository foundation, data contracts, and minimal infrastructure.

## Repository layout

- `schemas/avro/`: Kafka Avro schema definitions
- `infra/compose/`: phased Docker Compose environments
- `db/migrations/`: PostgreSQL migrations
- `flink-jobs/`: Java/Scala Flink applications
- `services/`: Go, Python API, ML, and worker services
- `agents/`: custom Go log collector
- `frontend/`: React SOC dashboard
- `tests/`: schema contract and integration tests

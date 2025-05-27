TwinEdge Gateway - High-Level Design Document
Executive Summary
TwinEdge  is a configuration-driven W3C WoT servient /TD Processor that unifies HTTP serving (via embedded Caddy) and high-throughput streaming (via Redpanda) into a single, dynamically configurable application. The system translates W3C Web of Things (WoT) Thing Descriptions into both HTTP API endpoints and streaming data pipelines, providing a unified interface for IoT and edge computing scenarios.
System Architecture Overview
Core Architectural Pattern: WoT Binding-Driven Gateway
┌─────────────────────────────────────────────────────────────┐
│                    TwinEdge Gateway                         │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────────┐    ┌─────────────────┐                │
│  │   WoT Service   │    │ Binding Engine  │                │
│  │   (TD Parser)   │───▶│ (Protocol Map)  │                │
│  └─────────────────┘    └─────────────────┘                │
│                                │                            │
│         ┌──────────────────────┼──────────────────────┐     │
│         ▼                      ▼                      ▼     │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐     │
│  │   Security  │    │    Caddy    │    │  Benthos    │     │
│  │ (OPA+Lic)  │───▶│  (HTTP/S)   │    │(Connectors) │     │
│  └─────────────┘    └─────────────┘    └─────────────┘     │
│         │                   │                   │           │
│         └───────────────────┼───────────────────┘           │
│                             ▼                               │
│                    ┌─────────────┐                          │
│                    │   DuckDB    │                          │
│                    │ (Metadata)  │                          │
│                    └─────────────┘                          │
└─────────────────────────────────────────────────────────────┘
Key Design Principles
1. WoT Binding Templates: Extensible protocol binding system for custom protocol mappings
2. License-Based Access: JWT/paseto based file 
3. Connector Architecture: Benthos connectors handle WoT binding protocol implementation 
4. Edge/Cloud Hybrid: Edge gateway or cloud device Shadow option
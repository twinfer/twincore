twincore Gateway - High-Level Design Document
Executive Summary
twincore  is a configuration-driven W3C WoT servient /TD Processor that unifies HTTP serving (via embedded Caddy) and high-throughput streaming (via Redpanda) into a single, dynamically configurable application. The system translates W3C Web of Things (WoT) Thing Descriptions into both HTTP API endpoints and streaming data pipelines, providing a unified interface for IoT and edge computing scenarios.
System Architecture Overview
Core Architectural Pattern: WoT Binding-Driven Gateway
┌─────────────────────────────────────────────────────────────┐
│                    twincore Gateway                         │
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
│                    │(State/Cfg)  │                          │
│                    └─────────────┘                          │
└─────────────────────────────────────────────────────────────┘

**Component Descriptions:**

*   **WoT Service (TD Parser):** Responsible for parsing W3C Web of Things (WoT) Thing Descriptions (TDs). It now uses a comprehensive set of internal Go types based on the W3C WoT Thing Description 1.1 specification, located in `pkg/wot/core.go`, enhancing type safety and spec alignment.
*   **Binding Engine (Protocol Map):** Translates parsed TDs into executable configurations for Caddy (HTTP) and Benthos (Streams), based on WoT Binding Templates.
*   **Security (OPA+Lic / go-authcrunch):** 
    *   HTTP security for API endpoints and WoT interactions is handled by the embedded Caddy server. This is configured using `go-authcrunch` structures (defined in `pkg/types/config.go` as `types.SecurityConfig`). This provides authentication (e.g., local DB-backed users, JWT, SAML) and authorization policies.
    *   License validation is planned to use OPA (Open Policy Agent) against Rego policies (current implementation has a placeholder for this).
*   **Caddy (HTTP/S):** Embedded Caddy server for handling all HTTP/S interactions, including WoT property reads/writes, action invocations, and event subscriptions (e.g., via SSE). Dynamically configured by the Binding Engine.
*   **Benthos (Connectors):** Embedded Benthos instance for managing streaming data pipelines. Dynamically configured by the Binding Engine based on WoT binding templates for protocols like Kafka, MQTT, etc.
*   **DuckDB (State/Config Store):** 
    *   Stores Thing Descriptions, Caddy configurations, and other operational metadata.
    *   Stores latest-value snapshots of Thing property states (in the `property_state` table) for fast reads by the `StateManager`.
    *   Stores local user credentials (username, hashed password, roles) in the `local_users` table when local authentication is configured for HTTP endpoints.
    *   (Future/Design) Intended to act as a query engine over historical property state data stored in external Parquet files.

Key Design Principles
1.  **WoT Binding Templates:** Extensible protocol binding system where `form` data within WoT Thing Descriptions is used to generate Benthos YAML snippets for custom protocol mappings.
2.  **License-Based Access:** JWT/Paseto based license files control access to features and services. OPA is planned for fine-grained license validation.
3.  **Connector Architecture:** Benthos, with its wide range of connectors, is the primary engine for implementing WoT protocol bindings for streaming interactions. Forms in TDs directly generate Benthos pipeline configurations.
4.  **Edge/Cloud Hybrid:** Designed to function as an edge gateway or a cloud-based device shadow.

Data Persistence for Property States
twincore employs a hybrid approach for managing property state data to balance fast access to current states with durable historical logging:

*   **Historical Data (Source of Truth):**
    *   All property state updates are written to Apache Parquet files on disk.
    *   These files are typically partitioned by day (e.g., `props_YYYY-MM-DD.parquet`) and stored in a configurable base path (e.g., `./twincore_data/property_states_parquet/`).
    *   This append-only, columnar storage is optimized for analytics and serves as the long-term source of truth for property history.
    *   This Parquet-based logging approach is planned for future extension to event data and action invocation history.

*   **Current State Snapshot (Fast Reads):**
    *   The `property_state` table in DuckDB stores only the latest known value for each property.
    *   This table acts as a snapshot or cache, enabling rapid retrieval of current property values.

*   **Operation:**
    *   When `StateManager.SetProperty` is called, the state change is written to the daily Parquet file, and then the `property_state` table in DuckDB is updated (INSERT OR REPLACE) with the new value.
    *   When `StateManager.GetProperty` is called, it reads directly from the DuckDB `property_state` table for low-latency access.

HTTP Security Configuration
The security for HTTP-based WoT interactions and other API endpoints provided by twincore is managed via its embedded Caddy server. The configuration for Caddy's security features is derived from the `types.SecurityConfig` structure, which is designed to align closely with `go-authcrunch`, the underlying library powering Caddy's advanced authentication and authorization capabilities.

*   **Configuration Structure**: The `types.SecurityConfig` (typically part of the gateway's main configuration file) allows defining:
    *   `AuthenticationPortals`: Define how users authenticate (e.g., login forms, UI settings).
    *   `IdentityStores`: Configure sources of user credentials (e.g., local database, LDAP).
    *   `TokenValidators`: Define how access tokens (e.g., JWTs) are validated.
    *   `AuthorizationGatekeepers`: Define policies for controlling access to resources.

*   **DB-Backed Local User Store**:
    *   twincore supports a local identity store backed by the DuckDB database. This is configured by including an `authn.IdentityStoreConfig` in the `types.SecurityConfig.IdentityStores` array with its `Kind` field set to `"local"`.
    *   When a "local" identity store is specified, user credentials (username, bcrypt/scrypt hashed password, roles, email, etc.) are loaded by the `HTTPService` from the `local_users` table in DuckDB at startup.
    *   **Operational Note**: Passwords in the `local_users` table must be hashed using a format compatible with `go-authcrunch` (e.g., bcrypt, scrypt). Populating and managing users in this table can be done via direct SQL initially, with plans for future administrative APIs.
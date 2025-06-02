# TwinCore Gateway

## Overview

TwinCore Gateway is a software solution designed to manage and interact with Web of Things (WoT) enabled devices. It provides capabilities for Thing Description processing, dynamic generation of data streams (using Benthos), HTTP API exposure for device interactions, configuration management, and service lifecycle management, all integrated within a Caddy web server environment.

The system allows for:
- Registration and management of Thing Descriptions (TDs).
- Dynamic creation of data processing streams based on TD affordances (properties, actions, events).
- HTTP APIs for interacting with Things.
- Centralized configuration and state management.
- Extensible service architecture.

## Project Structure

The project is organized into several key packages:

-   **`cmd/twincore/`**: Main application entry point.
-   **`internal/`**: Core internal logic of the TwinCore application.
    -   **`api/`**: Defines core service interfaces and API endpoint handlers.
    -   **`caddy_app/`**: Custom Caddy application module to integrate TwinCore services.
    -   **`config/`**: Manages application configuration, including Thing registry and Caddy/Benthos configurations.
    -   **`container/`**: Implements the main dependency injection container.
    -   **`models/`**: Defines application-level data models, especially for logging and eventing.
    -   **`security/`**: Handles security aspects like device management and license checking.
-   **`pkg/`**: Shared libraries and types.
    -   **`types/`**: Basic shared types, constants, and core service/configuration interfaces.
    -   **`wot/`**: Defines data structures for Web of Things (WoT) Thing Descriptions and related forms processing.
    -   **`license/`**: Components for license checking.
-   **`service/`**: Implementations of various services managed by the TwinCore (e.g., HTTP service, Stream service, WoT service).
-   **`portal/`**: Contains the frontend portal application.
-   **`configs/`**: Default configurations, Benthos stream examples, etc.

## Building and Running (Assumed)

This project is written in Go.

**Build:**
(Standard Go build commands would apply, e.g.)
```bash
go build ./cmd/twincore
```

**Running:**
The `twincore` executable takes several command-line flags. Some common ones might be:
```bash
./twincore --db ./twincore.db --license ./license.jwt --log-level debug
```
Refer to `cmd/twincore/main.go` for available flags:
-   `--license`: Path to license file.
-   `--db`: Path to database file (e.g., `./twincore.db`).
-   `--log-level`: Logging level (debug, info, warn, error).
-   `--api-port`: API server port.
-   `--parquet-log-path`: Path for Parquet log files.
-   `--caddy-mode`: Run as pure Caddy (for external management).

The application integrates with Caddy, which typically serves an admin API on port `2019` and the main application/portal on a port like `8080`.

## Developer Documentation

For more detailed information on the architecture, core interfaces, key data flows, and component responsibilities, please refer to the [Developer Guide](./docs/DEVELOPER_GUIDE.md).

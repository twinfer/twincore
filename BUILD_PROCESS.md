# TwinCore Build Process

## Overview

TwinCore uses a multi-stage build process that:
1. Builds the web portal (React/Vue/Svelte)
2. Embeds the portal into the Go binary
3. Builds a custom Caddy with caddy-security
4. Creates a single, self-contained binary

## Directory Structure

```
twincore/
├── portal/                    # Web portal source
│   ├── src/                  # React/Vue source files
│   ├── public/               # Static assets
│   ├── package.json          # Node.js dependencies
│   ├── vite.config.js        # Build configuration
│   └── dist/                 # Built artifacts (generated)
│
├── cmd/twincore/             # Main binary
│   └── main.go              # Entry point with embedded portal
│
├── configs/                  # Default configuration templates
│   ├── auth/                # Authentication templates
│   ├── benthos/             # Stream processing configs
│   └── caddy/               # HTTP routing configs
│
└── Makefile                 # Build automation
```

## Build Steps

### 1. Portal Build (Node.js → Static Files)

```bash
# Install dependencies
cd portal
npm install

# Build for production
npm run build

# Output: portal/dist/ contains optimized static files
```

### 2. Go Binary Build (Embed Portal → Custom Caddy)

```bash
# Build with embedded portal
go build -o twincore ./cmd/twincore/

# The binary includes:
# - Caddy server with caddy-security
# - Embedded portal static files
# - Configuration management API
# - First-time setup flow
```

### 3. Complete Build Process

```bash
# Option A: Manual build
make portal
make twincore

# Option B: Full build
make all

# Option C: Docker build
make docker
```

## Portal Structure

### Frontend Framework Choice

We recommend **React + Vite** for the portal:

```json
// portal/package.json
{
  "name": "twincore-portal",
  "version": "1.0.0",
  "scripts": {
    "dev": "vite",
    "build": "vite build",
    "preview": "vite preview"
  },
  "dependencies": {
    "react": "^18.2.0",
    "react-dom": "^18.2.0",
    "react-router-dom": "^6.8.0",
    "@tanstack/react-query": "^4.24.0",
    "axios": "^1.3.0"
  },
  "devDependencies": {
    "@vitejs/plugin-react": "^3.1.0",
    "vite": "^4.1.0"
  }
}
```

### Portal Pages

```
portal/src/
├── pages/
│   ├── Setup.tsx            # First-time setup wizard
│   ├── Dashboard.tsx        # Main dashboard
│   ├── Things.tsx           # Thing management
│   ├── Streams.tsx          # Stream monitoring
│   ├── Config.tsx           # Configuration
│   └── Auth.tsx             # Authentication settings
│
├── components/
│   ├── SetupWizard/         # Multi-step setup
│   ├── ThingCard/           # Thing display
│   ├── StreamMonitor/       # Real-time stream status
│   └── ConfigForm/          # Dynamic configuration forms
│
└── api/
    ├── client.ts            # API client
    ├── auth.ts              # Authentication
    └── types.ts             # TypeScript types
```

## Makefile

```makefile
# Build targets
.PHONY: all portal twincore clean docker

all: portal twincore

portal:
	@echo "Building portal..."
	cd portal && npm ci && npm run build

twincore:
	@echo "Building TwinCore binary..."
	go mod tidy
	go build -ldflags="-s -w" -o bin/twincore ./cmd/twincore/

clean:
	rm -rf portal/dist/
	rm -f bin/twincore

docker:
	docker build -t twincore:latest .

# Development targets
dev-portal:
	cd portal && npm run dev

dev-twincore:
	go run ./cmd/twincore/

# Install dependencies
deps:
	cd portal && npm install
	go mod download

# Testing
test:
	go test ./...
	cd portal && npm test

# Release build
release: clean all
	@echo "Building release..."
	CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o bin/twincore-linux ./cmd/twincore/
	CGO_ENABLED=0 GOOS=darwin go build -ldflags="-s -w" -o bin/twincore-darwin ./cmd/twincore/
	CGO_ENABLED=0 GOOS=windows go build -ldflags="-s -w" -o bin/twincore-windows.exe ./cmd/twincore/
```

## Docker Build

```dockerfile
# Dockerfile
FROM node:18-alpine AS portal-build
WORKDIR /app/portal
COPY portal/package*.json ./
RUN npm ci
COPY portal/ ./
RUN npm run build

FROM golang:1.21-alpine AS go-build
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=portal-build /app/portal/dist ./portal/dist
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o twincore ./cmd/twincore/

FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /root/
COPY --from=go-build /app/twincore ./
COPY --from=go-build /app/configs ./configs
EXPOSE 80 443 2019
CMD ["./twincore"]
```

## First-Time Setup Integration

### 1. Setup Detection

```go
// In main.go
func init() {
    if !isSetupComplete() {
        // Serve setup wizard
        registerSetupRoutes()
    } else {
        // Serve full portal
        registerPortalRoutes()
    }
}
```

### 2. Setup Wizard Flow

```typescript
// portal/src/pages/Setup.tsx
const SetupWizard = () => {
  const [step, setStep] = useState(1);
  
  const steps = [
    { id: 1, title: "License", component: LicenseStep },
    { id: 2, title: "Authentication", component: AuthStep },
    { id: 3, title: "Admin User", component: AdminStep },
    { id: 4, title: "Complete", component: CompleteStep },
  ];
  
  return (
    <div className="setup-wizard">
      <StepIndicator steps={steps} current={step} />
      <StepContent step={step} onNext={() => setStep(step + 1)} />
    </div>
  );
};
```

### 3. Dynamic Configuration

```typescript
// portal/src/components/AuthStep.tsx
const AuthStep = ({ onNext }) => {
  const [providers, setProviders] = useState([]);
  const [selected, setSelected] = useState(null);
  
  useEffect(() => {
    // Fetch available providers based on license
    api.get('/setup/auth-providers').then(setProviders);
  }, []);
  
  return (
    <div>
      <h2>Choose Authentication</h2>
      {providers.map(provider => (
        <AuthProviderCard 
          key={provider.id}
          provider={provider}
          selected={selected === provider.id}
          onSelect={() => setSelected(provider.id)}
        />
      ))}
      {selected && <AuthConfigForm provider={selected} onSubmit={onNext} />}
    </div>
  );
};
```

## Development Workflow

### 1. Start Development

```bash
# Terminal 1: Start portal dev server
make dev-portal

# Terminal 2: Start TwinCore
make dev-twincore

# Portal: http://localhost:5173
# TwinCore: http://localhost:8080
```

### 2. Build for Production

```bash
# Build everything
make all

# Run production binary
./bin/twincore
```

### 3. Release Process

```bash
# Create release builds
make release

# Upload to GitHub releases or package registry
```

## Benefits

1. **Single Binary**: Everything embedded, easy deployment
2. **Professional UI**: Modern web portal for management
3. **Flexible Auth**: Choose provider during setup
4. **Self-Contained**: No external dependencies
5. **Easy Updates**: Single binary to replace

This architecture provides a professional, enterprise-ready gateway with a built-in management interface that can be configured flexibly based on customer needs and license levels.
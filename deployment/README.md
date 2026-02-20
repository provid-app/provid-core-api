# Deployment Directory

This directory contains the production deployment configuration for the CI/CD Helper service.

## Files

### `Dockerfile`
Optimized multi-stage Dockerfile for building the Go application.

**Features:**
- Multi-stage build (builder + distroless runner)
- ~93% smaller image size (~20MB vs ~400MB)
- Security hardened (runs as non-root, no shell)
- Build optimizations (-ldflags, -trimpath)
- Proper layer caching

**Build Context:** Project root (`.`)

### `docker-compose.yml`
Production docker-compose configuration used by Ansible for deployments.

**Features:**
- Pulls latest image from GitLab Container Registry
- Volume mounts for logs and config
- Auto-restart policy
- Log rotation (10MB max, 3 files)
- Production environment variables

## Deployment Flow

```
GitLab CI Build Stage:
  ├─> docker buildx build -f deployment/Dockerfile
  ├─> Pushes to $CI_REGISTRY_IMAGE:latest
  └─> Image ready in GitLab Container Registry

Ansible Deploy Stage:
  ├─> Downloads inventory from MinIO
  ├─> SSH to target servers
  ├─> cd deployment/
  ├─> docker compose down
  ├─> docker compose pull (gets :latest)
  └─> docker compose up -d
```

## Server Setup Requirements

On each target server, ensure this structure exists:

```
/path/to/deployment/
├── docker-compose.yml     # This file (deployed via your method)
├── config/                # Configuration files
│   └── .env.production   # Environment variables
└── logs/                  # Application logs (created automatically)
```

## Environment Variables

The docker-compose.yml uses:
- `${CI_REGISTRY_IMAGE}` - Set by GitLab CI or in .env file

Example `.env` file for local testing:
```bash
CI_REGISTRY_IMAGE=registry.gitlab.com/your-group/your-project
```

## Image Details

**Base Image:** `gcr.io/distroless/static-debian12:nonroot`
- No shell, no package manager
- Runs as non-root user (UID 65532)
- Only contains your binary + CA certificates
- Minimal attack surface

**Size:** ~20-30MB (was ~400-500MB with alpine)

## Security

✅ Runs as non-root user (nonroot:nonroot)
✅ No shell or debugging tools in production
✅ Minimal dependencies
✅ Read-only config volume
✅ Isolated network

## Monitoring

Since distroless doesn't support traditional health checks:
- Monitor via application logs in `./logs/`
- Use external monitoring (Prometheus, Grafana)
- Container restart policy handles crashes

## Troubleshooting

### Image pull fails
```bash
# Login to GitLab Container Registry
docker login registry.gitlab.com
# Enter your GitLab credentials or deploy token
```

### Permission denied on volumes
```bash
# Distroless runs as UID 65532
sudo chown -R 65532:65532 ./logs ./config
```

### Check running container
```bash
docker compose ps
docker compose logs -f helper-service
```

### Restart service
```bash
docker compose restart helper-service
```

---

**Last Updated:** November 2025
**Optimized for:** Production deployments with security and size in mind


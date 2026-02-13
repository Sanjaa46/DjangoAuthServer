#!/bin/bash

# Deployment script for Django SSO Server
# Usage: ./deploy.sh [staging|production]

set -e

ENVIRONMENT=${1:-staging}
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="/opt/sso-server"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Validate environment
if [[ "$ENVIRONMENT" != "staging" && "$ENVIRONMENT" != "production" ]]; then
    log_error "Invalid environment. Use 'staging' or 'production'"
    exit 1
fi

log_info "Starting deployment to ${ENVIRONMENT}..."

# Check if .env file exists
if [ ! -f "${PROJECT_DIR}/.env.${ENVIRONMENT}" ]; then
    log_error ".env.${ENVIRONMENT} file not found!"
    exit 1
fi
log_info "Creating database backup..."
BACKUP_DIR="${PROJECT_DIR}/backups"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
mkdir -p ${BACKUP_DIR}

if docker-compose ps | grep -q "Up"; then
    docker-compose exec -T web python manage.py dumpdata --natural-foreign --natural-primary \
        -e contenttypes -e auth.Permission > "${BACKUP_DIR}/db_backup_${TIMESTAMP}.json" || log_warn "Database backup failed"
fi

# Pull latest images
log_info "Pulling latest Docker images..."
docker-compose -f docker-compose.production.yml pull

# Stop existing containers
log_info "Stopping existing containers..."
docker-compose -f docker-compose.production.yml down

# Start new containers
log_info "Starting new containers..."
docker-compose -f docker-compose.production.yml --env-file .env.${ENVIRONMENT} up -d

# Wait for services to be ready
log_info "Waiting for services to start..."
sleep 10

# Run migrations
log_info "Running database migrations..."
docker-compose -f docker-compose.production.yml exec -T web python manage.py migrate --noinput

# Collect static files
log_info "Collecting static files..."
docker-compose -f docker-compose.production.yml exec -T web python manage.py collectstatic --noinput

# Generate keys if they don't exist
log_info "Checking RSA keys..."
docker-compose -f docker-compose.production.yml exec -T web python manage.py genkeys || log_info "Keys already exist"

# Health check
log_info "Performing health check..."
sleep 5
if curl -f http://localhost/admin/login/ > /dev/null 2>&1; then
    log_info "Health check passed!"
else
    log_error "Health check failed!"
    log_info "Rolling back..."
    docker-compose -f docker-compose.production.yml down
    exit 1
fi

# Clean up old images
log_info "Cleaning up old Docker images..."
docker image prune -f

# Show container status
log_info "Container status:"
docker-compose -f docker-compose.production.yml ps

log_info "Deployment to ${ENVIRONMENT} completed successfully!"
log_info "Application is accessible via Cloudflare Tunnel"

# Keep last 7 backups
log_info "Cleaning old backups (keeping last 7)..."
ls -t ${BACKUP_DIR}/db_backup_*.json | tail -n +8 | xargs -r rm

log_info "Deployment complete!"

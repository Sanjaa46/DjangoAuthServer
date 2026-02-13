# CI/CD Setup Guide - Django OAuth2 SSO Server

This guide explains how to set up and use the GitLab CI/CD pipeline for the Django OAuth2 SSO Server.

## Table of Contents

1. [Overview](#overview)
2. [Prerequisites](#prerequisites)
3. [GitLab Configuration](#gitlab-configuration)
4. [Pipeline Stages](#pipeline-stages)
5. [Deployment Setup](#deployment-setup)
6. [Environment Variables](#environment-variables)
7. [Running Deployments](#running-deployments)
8. [Troubleshooting](#troubleshooting)

---

## Overview

The CI/CD pipeline automates:
- ✅ Code quality checks (linting, formatting)
- ✅ Security scanning
- ✅ Unit and integration tests
- ✅ Docker image building
- ✅ Automated deployment to staging and production
- ✅ Rollback capabilities

### Pipeline Architecture

```
┌─────────┐    ┌─────────┐    ┌─────────┐
│  TEST   │ -> │  BUILD  │ -> │  DEPLOY │
└─────────┘    └─────────┘    └─────────┘
    │              │               │
    ├── Lint       ├── Docker      ├── Staging
    ├── Security   │   Image       └── Production
    └── Unit Tests └── Push to
                      Registry
```

---

## Prerequisites

### 1. GitLab Account & Repository

- GitLab account with CI/CD runners enabled
- Repository with the SSO Server code
- GitLab Container Registry enabled

### 2. Deployment Servers

**Staging Server:**
- Ubuntu 20.04+ or similar Linux distribution
- Docker and Docker Compose installed
- SSH access configured
- Minimum 2GB RAM, 2 CPU cores

**Production Server:**
- Ubuntu 20.04+ or similar Linux distribution
- Docker and Docker Compose installed
- SSH access configured
- Minimum 4GB RAM, 4 CPU cores
- SSL certificate (Let's Encrypt recommended)

### 3. External Services

- **MySQL Database**: External MySQL 8.0+ instance
- **Redis**: Can run as Docker container or external service
- **SMS Gateway**: Configured for OTP delivery

---

## GitLab Configuration

### Step 1: Enable GitLab CI/CD

1. Go to your GitLab project
2. Navigate to **Settings** → **CI/CD**
3. Expand **Runners** section
4. Enable shared runners or register a specific runner

### Step 2: Configure CI/CD Variables

Navigate to **Settings** → **CI/CD** → **Variables** and add the following:

#### Registry Variables
```
CI_REGISTRY_USER = gitlab-ci-token (automatic)
CI_REGISTRY_PASSWORD = <your-gitlab-token>
CI_REGISTRY = registry.gitlab.com
```

#### Deployment Variables

**Common Variables:**
```
SECRET_KEY = <generate-strong-secret-key>
DB_NAME = sso_production_db
DB_USER = sso_user
DB_PASSWORD = <database-password>
DB_HOST = <mysql-host>
DB_PORT = 3306
```

**Staging Environment:**
```
STAGING_SERVER = staging.yourdomain.com
STAGING_USER = deploy
SSH_PRIVATE_KEY = <staging-ssh-private-key>
```

**Production Environment:**
```
PRODUCTION_SERVER = sso.yourdomain.com
PRODUCTION_USER = deploy
SSH_PRIVATE_KEY = <production-ssh-private-key>
```

### Step 3: Generate SSH Keys for Deployment

On your local machine:

```bash
# Generate SSH key pair
ssh-keygen -t ed25519 -C "gitlab-ci-deploy" -f gitlab-deploy-key

# Copy public key to deployment servers
ssh-copy-id -i gitlab-deploy-key.pub deploy@staging.yourdomain.com
ssh-copy-id -i gitlab-deploy-key.pub deploy@sso.yourdomain.com

# Copy private key content to GitLab CI/CD variable SSH_PRIVATE_KEY
cat gitlab-deploy-key
```

---

## Pipeline Stages

### Stage 1: Test

#### 1.1 Lint Check (`test:lint`)
- **Purpose**: Enforce code quality and style
- **Tools**: flake8, black, isort
- **When**: On merge requests, develop, and main branches
- **Allows Failure**: Yes (won't block pipeline)

**What it checks:**
- PEP 8 compliance
- Code formatting consistency
- Import ordering

#### 1.2 Security Check (`test:security`)
- **Purpose**: Identify security vulnerabilities
- **Tools**: bandit, safety
- **When**: On merge requests, develop, and main branches
- **Allows Failure**: Yes (generates report)

**What it checks:**
- Common security issues in Python code
- Known vulnerabilities in dependencies

#### 1.3 Unit Tests (`test:unit`)
- **Purpose**: Verify code functionality
- **Tools**: pytest, pytest-django, pytest-cov
- **Services**: MySQL, Redis
- **When**: On merge requests, develop, and main branches
- **Coverage**: Generates code coverage report

**What it tests:**
- Model creation and validation
- View authentication and authorization
- OAuth flow endpoints
- Token generation and validation

### Stage 2: Build

#### 2.1 Docker Build (`build:docker`)
- **Purpose**: Build and push Docker image to registry
- **When**: On develop, main, and tags
- **Image Tags**: 
  - `latest` - Always points to most recent build
  - `<commit-sha>` - Specific version tag

**Build Process:**
1. Authenticate with GitLab Container Registry
2. Build Docker image from Dockerfile
3. Tag image with commit SHA and latest
4. Push to registry

### Stage 3: Deploy

#### 3.1 Staging Deployment (`deploy:staging`)
- **Purpose**: Deploy to staging environment for testing
- **When**: Manual trigger on develop branch
- **Environment URL**: https://sso-staging.yourdomain.com

**Deployment Steps:**
1. SSH to staging server
2. Pull latest Docker images
3. Recreate containers
4. Run database migrations
5. Collect static files

#### 3.2 Production Deployment (`deploy:production`)
- **Purpose**: Deploy to production environment
- **When**: Manual trigger on main branch or tags
- **Environment URL**: https://sso.yourdomain.com
- **Requires**: Successful build stage

**Deployment Steps:**
1. SSH to production server
2. Pull latest Docker images
3. Recreate containers
4. Run database migrations
5. Collect static files
6. Generate RSA keys (if not exist)

#### 3.3 Production Rollback (`rollback:production`)
- **Purpose**: Quickly revert production to previous version
- **When**: Manual trigger on main branch
- **Action**: Pulls and starts previous Docker image version

---

## Deployment Setup

### Server Preparation

#### 1. Install Docker and Docker Compose

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh

# Install Docker Compose
sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose

# Add deploy user to docker group
sudo usermod -aG docker deploy
```

#### 2. Create Project Directory

```bash
# Create directory structure
sudo mkdir -p /opt/sso-server
sudo chown -R deploy:deploy /opt/sso-server
cd /opt/sso-server

# Create necessary subdirectories
mkdir -p nginx/conf.d nginx/ssl backups
```

#### 3. Upload Configuration Files

```bash
# Copy docker-compose.production.yml
scp docker-compose.production.yml deploy@sso.yourdomain.com:/opt/sso-server/docker-compose.yml

# Copy nginx configuration
scp nginx/conf.d/default.conf deploy@sso.yourdomain.com:/opt/sso-server/nginx/conf.d/

# Copy environment file
scp .env.production deploy@sso.yourdomain.com:/opt/sso-server/.env.production
```

#### 4. Configure SSL Certificates

**Option A: Using Let's Encrypt (Recommended)**

```bash
# Install certbot
sudo apt install certbot

# Generate certificate
sudo certbot certonly --standalone -d sso.yourdomain.com

# Copy certificates
sudo cp /etc/letsencrypt/live/sso.yourdomain.com/fullchain.pem /opt/sso-server/nginx/ssl/
sudo cp /etc/letsencrypt/live/sso.yourdomain.com/privkey.pem /opt/sso-server/nginx/ssl/
sudo chown -R deploy:deploy /opt/sso-server/nginx/ssl/
```

**Option B: Self-Signed Certificate (Development)**

```bash
cd /opt/sso-server/nginx/ssl
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout privkey.pem \
  -out fullchain.pem \
  -subj "/CN=sso.yourdomain.com"
```

#### 5. Initialize Database

```bash
# SSH to server
ssh deploy@sso.yourdomain.com

cd /opt/sso-server

# Start only the web service to run migrations
docker-compose --env-file .env.production up -d web

# Run initial migrations
docker-compose exec web python manage.py migrate

# Create superuser
docker-compose exec web python manage.py createsuperuser

# Generate RSA keys
docker-compose exec web python manage.py genkeys

# Start all services
docker-compose --env-file .env.production up -d
```

---

## Environment Variables

### Required Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `SECRET_KEY` | Django secret key | `your-secret-key-here` |
| `DEBUG` | Debug mode (False in production) | `False` |
| `ALLOWED_HOSTS` | Allowed hostnames | `sso.yourdomain.com` |
| `DB_NAME` | Database name | `sso_production_db` |
| `DB_USER` | Database username | `sso_user` |
| `DB_PASSWORD` | Database password | `secure-password` |
| `DB_HOST` | Database host | `mysql.yourdomain.com` |
| `DB_PORT` | Database port | `3306` |
| `REDIS_HOST` | Redis hostname | `redis` |
| `REDIS_PORT` | Redis port | `6379` |
| `REDIS_PASSWORD` | Redis password (optional) | `redis-password` |
| `SSO_ISS` | Token issuer URL | `https://sso.yourdomain.com` |

### Optional Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `SSO_ACCESS_TOKEN_EXP` | Access token lifetime (seconds) | `900` |
| `SSO_REFRESH_TOKEN_EXP` | Refresh token lifetime (seconds) | `2592000` |
| `CORS_ALLOWED_ORIGINS` | Allowed CORS origins | `http://localhost:8080` |

---

## Running Deployments

### Automatic Pipeline Trigger

The pipeline automatically runs on:
- Push to any branch (runs tests only)
- Push to `develop` (runs tests + builds image)
- Push to `main` (runs tests + builds image)
- Creating a tag (runs tests + builds image)

### Manual Deployment

#### Deploy to Staging

1. Go to your GitLab project
2. Navigate to **CI/CD** → **Pipelines**
3. Find the pipeline for your develop branch
4. Click on the `deploy:staging` job
5. Click **Play** button (▶️)
6. Monitor deployment progress
7. Verify at https://sso-staging.yourdomain.com

#### Deploy to Production

1. Merge `develop` branch to `main`
2. Navigate to **CI/CD** → **Pipelines**
3. Find the pipeline for main branch
4. Click on the `deploy:production` job
5. Click **Play** button (▶️)
6. Monitor deployment progress
7. Verify at https://sso.yourdomain.com

#### Rollback Production

1. Navigate to **CI/CD** → **Pipelines**
2. Find the pipeline with the working version
3. Click on the `rollback:production` job
4. Click **Play** button (▶️)
5. Confirm rollback

### Using Deployment Script

For manual deployment from server:

```bash
# SSH to server
ssh deploy@sso.yourdomain.com

cd /opt/sso-server

# Deploy to staging
./deploy.sh staging

# Deploy to production
./deploy.sh production
```

---

## Monitoring and Health Checks

### Application Health Check

```bash
# Check if application is responding
curl https://sso.yourdomain.com/admin/login/

# Expected: 200 OK
```

### Docker Container Status

```bash
# Check running containers
docker-compose ps

# Check container logs
docker-compose logs -f web
docker-compose logs -f nginx
docker-compose logs -f redis

# Check container resource usage
docker stats
```

### Database Connection

```bash
# Test database connection
docker-compose exec web python manage.py dbshell

# Run database migrations check
docker-compose exec web python manage.py showmigrations
```

---

## Troubleshooting

### Common Issues

#### 1. Pipeline Fails on Test Stage

**Problem**: Tests fail with database connection errors

**Solution**:
```bash
# Check if MySQL service is running in pipeline
# Ensure environment variables are correctly set
# Verify database credentials in GitLab CI/CD variables
```

#### 2. Docker Image Build Fails

**Problem**: Build fails with permission errors

**Solution**:
```bash
# Check GitLab Container Registry permissions
# Verify CI_REGISTRY_PASSWORD is correct
# Ensure runner has Docker-in-Docker enabled
```

#### 3. Deployment Fails with SSH Errors

**Problem**: Cannot connect to deployment server

**Solution**:
```bash
# Verify SSH_PRIVATE_KEY in GitLab variables
# Check server firewall allows SSH (port 22)
# Ensure deploy user has correct permissions
# Test SSH connection manually:
ssh deploy@sso.yourdomain.com
```

#### 4. Application Not Starting After Deployment

**Problem**: Containers fail to start

**Solution**:
```bash
# Check container logs
docker-compose logs

# Verify environment variables
docker-compose config

# Check if ports are already in use
sudo netstat -tulpn | grep :8000

# Restart services
docker-compose restart
```

#### 5. Database Migration Errors

**Problem**: Migrations fail during deployment

**Solution**:
```bash
# Check migration status
docker-compose exec web python manage.py showmigrations

# Create migrations if needed
docker-compose exec web python manage.py makemigrations

# Apply migrations one by one
docker-compose exec web python manage.py migrate ssoAuthServer

# Fake migration if necessary (careful!)
docker-compose exec web python manage.py migrate --fake ssoAuthServer 0001
```

### Debug Mode

To enable debug output during deployment:

```bash
# In .env file, temporarily set:
DEBUG=True

# Restart containers
docker-compose restart

# Check detailed logs
docker-compose logs -f web
```

**⚠️ Remember to set DEBUG=False after debugging!**

---

## Best Practices

### 1. Version Tagging

Use semantic versioning for production releases:

```bash
git tag -a v1.0.0 -m "Production release v1.0.0"
git push origin v1.0.0
```

### 2. Branch Strategy

- `main` - Production-ready code
- `develop` - Integration branch
- `feature/*` - Feature development
- `hotfix/*` - Emergency fixes

### 3. Database Backups

Always backup before deploying:

```bash
# Manual backup before deployment
docker-compose exec web python manage.py dumpdata > backup_$(date +%Y%m%d).json

# Automated backups (add to crontab)
0 2 * * * cd /opt/sso-server && docker-compose exec -T web python manage.py dumpdata > /opt/backups/db_$(date +\%Y\%m\%d).json
```

### 4. Secret Rotation

Rotate secrets regularly:

```bash
# Generate new SECRET_KEY
python -c "from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())"

# Update in GitLab CI/CD variables
# Redeploy application
```

### 5. Monitoring

Set up monitoring for:
- Application uptime (e.g., UptimeRobot)
- Error tracking (e.g., Sentry)
- Performance monitoring (e.g., New Relic)
- Log aggregation (e.g., ELK stack)

---

## Security Checklist

- [ ] SSL/TLS certificates configured and valid
- [ ] `DEBUG=False` in production
- [ ] Strong `SECRET_KEY` configured
- [ ] Database credentials secured
- [ ] SSH keys properly managed
- [ ] Firewall rules configured
- [ ] Regular security updates applied
- [ ] CORS origins properly restricted
- [ ] Rate limiting enabled
- [ ] Backup strategy in place

---

## Support and Resources

- **Documentation**: See `README.md` and `API_DOCUMENTATION.md`
- **Issues**: Report on GitLab Issues
- **GitLab CI/CD Docs**: https://docs.gitlab.com/ee/ci/
- **Docker Docs**: https://docs.docker.com/

---

## Quick Reference

### Useful Commands

```bash
# View pipeline status
gitlab-runner list

# Check Docker images
docker images | grep sso-server

# View container logs
docker-compose logs -f --tail=100 web

# Execute Django commands
docker-compose exec web python manage.py <command>

# Backup database
docker-compose exec web python manage.py dumpdata > backup.json

# Restore database
docker-compose exec -T web python manage.py loaddata < backup.json
```

### Pipeline Variables

View in GitLab: **Settings** → **CI/CD** → **Variables**

```
CI_COMMIT_SHA - Current commit hash
CI_COMMIT_SHORT_SHA - Short commit hash
CI_PIPELINE_ID - Pipeline ID
CI_JOB_NAME - Current job name
```

---

**Last Updated**: 2025-02-13  
**Version**: 1.0

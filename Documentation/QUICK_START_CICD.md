# CI/CD Quick Start Checklist

Follow these steps to get your CI/CD pipeline up and running quickly.

> **📘 Note**: This guide includes traditional deployment with SSL certificates. If you're using **Cloudflare Tunnel**, see `CLOUDFLARE_TUNNEL_GUIDE.md` for simplified setup without SSL certificates or port exposure.

## Prerequisites Setup (30 minutes)

### 1. GitLab Repository Setup
- [ ] Create GitLab repository or push existing code
- [ ] Enable GitLab Container Registry
  - Go to **Settings** → **General** → **Visibility** → Enable Container Registry
- [ ] Enable GitLab CI/CD
  - Go to **Settings** → **CI/CD** → Runners → Enable shared runners

### 2. Prepare Deployment Servers

**On both Staging and Production servers:**

```bash
# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh

# Install Docker Compose
sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" \
  -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose

# Create deploy user
sudo useradd -m -s /bin/bash deploy
sudo usermod -aG docker deploy
sudo usermod -aG sudo deploy

# Create project directory
sudo mkdir -p /opt/sso-server
sudo chown -R deploy:deploy /opt/sso-server
```

### 3. Generate SSH Keys

```bash
# On your local machine
ssh-keygen -t ed25519 -C "gitlab-ci-deploy" -f ~/.ssh/gitlab-deploy-key

# Copy public key to servers
ssh-copy-id -i ~/.ssh/gitlab-deploy-key.pub deploy@staging.yourdomain.com
ssh-copy-id -i ~/.ssh/gitlab-deploy-key.pub deploy@sso.yourdomain.com

# Get private key content (you'll need this for GitLab)
cat ~/.ssh/gitlab-deploy-key
```

## GitLab Configuration (15 minutes)

### 1. Add CI/CD Files to Repository

Copy these files to your repository root:
- [ ] `.gitlab-ci.yml`
- [ ] `docker-compose.production.yml`
- [ ] `deploy.sh` (make executable: `chmod +x deploy.sh`)
- [ ] `pytest.ini`
- [ ] `.env.production.example`
- [ ] `nginx/conf.d/default.conf`

### 2. Configure GitLab CI/CD Variables

Go to **Settings** → **CI/CD** → **Variables** and add:

#### Required Variables (All Environments)

| Variable | Type | Value | Protected | Masked |
|----------|------|-------|-----------|--------|
| `SECRET_KEY` | Variable | [Generate new](https://djecrety.ir/) | ✓ | ✓ |
| `DB_NAME` | Variable | `sso_production_db` | ✓ | ✗ |
| `DB_USER` | Variable | `sso_user` | ✓ | ✗ |
| `DB_PASSWORD` | Variable | [Your DB password] | ✓ | ✓ |
| `DB_HOST` | Variable | `your-mysql-host.com` | ✓ | ✗ |
| `DB_PORT` | Variable | `3306` | ✗ | ✗ |

#### Staging Deployment Variables

| Variable | Type | Value | Protected | Masked |
|----------|------|-------|-----------|--------|
| `STAGING_SERVER` | Variable | `staging.yourdomain.com` | ✗ | ✗ |
| `STAGING_USER` | Variable | `deploy` | ✗ | ✗ |

#### Production Deployment Variables

| Variable | Type | Value | Protected | Masked |
|----------|------|-------|-----------|--------|
| `PRODUCTION_SERVER` | Variable | `sso.yourdomain.com` | ✓ | ✗ |
| `PRODUCTION_USER` | Variable | `deploy` | ✓ | ✗ |

#### SSH Key Variable (Both Environments)

| Variable | Type | Value | Protected | Masked |
|----------|------|-------|-----------|--------|
| `SSH_PRIVATE_KEY` | File | [Content of gitlab-deploy-key] | ✓ | ✗ |

**To add SSH key:**
1. Click **Add Variable**
2. Key: `SSH_PRIVATE_KEY`
3. Type: **File**
4. Value: Paste entire private key content including `-----BEGIN OPENSSH PRIVATE KEY-----` and `-----END OPENSSH PRIVATE KEY-----`
5. Check **Protected**
6. Click **Add variable**

### 3. Commit and Push CI/CD Files

```bash
git add .gitlab-ci.yml docker-compose.production.yml deploy.sh pytest.ini
git add nginx/conf.d/default.conf .env.production.example
git commit -m "Add CI/CD pipeline configuration"
git push origin main
```

## Server Setup (20 minutes per server)

### 1. Upload Configuration Files

**For Staging:**
```bash
# Create necessary directories on server
ssh deploy@staging.yourdomain.com "mkdir -p /opt/sso-server/nginx/conf.d /opt/sso-server/nginx/ssl /opt/sso-server/backups"

# Copy docker-compose file
scp docker-compose.production.yml deploy@staging.yourdomain.com:/opt/sso-server/docker-compose.yml

# Copy nginx config
scp nginx/conf.d/default.conf deploy@staging.yourdomain.com:/opt/sso-server/nginx/conf.d/

# Copy and configure environment file
cp .env.production.example .env.staging
# Edit .env.staging with staging-specific values
scp .env.staging deploy@staging.yourdomain.com:/opt/sso-server/.env.staging
```

**For Production:**
```bash
# Repeat above steps for production server
ssh deploy@sso.yourdomain.com "mkdir -p /opt/sso-server/nginx/conf.d /opt/sso-server/nginx/ssl /opt/sso-server/backups"
scp docker-compose.production.yml deploy@sso.yourdomain.com:/opt/sso-server/docker-compose.yml
scp nginx/conf.d/default.conf deploy@sso.yourdomain.com:/opt/sso-server/nginx/conf.d/
cp .env.production.example .env.production
# Edit .env.production with production-specific values
scp .env.production deploy@sso.yourdomain.com:/opt/sso-server/.env.production
```

### 2. Configure SSL Certificates

> **🚀 Cloudflare Tunnel Users**: Skip this section entirely! See `CLOUDFLARE_TUNNEL_GUIDE.md` for simplified setup with no SSL certificates needed.

**For Production (Let's Encrypt):**
```bash
ssh deploy@sso.yourdomain.com

# Install certbot
sudo apt update
sudo apt install certbot

# Generate certificate
sudo certbot certonly --standalone -d sso.yourdomain.com

# Copy certificates (NOT needed for Cloudflare Tunnel)
sudo cp /etc/letsencrypt/live/sso.yourdomain.com/fullchain.pem /opt/sso-server/nginx/ssl/
sudo cp /etc/letsencrypt/live/sso.yourdomain.com/privkey.pem /opt/sso-server/nginx/ssl/
sudo chown -R deploy:deploy /opt/sso-server/nginx/ssl/
```

**For Staging (Self-Signed):**
```bash
ssh deploy@staging.yourdomain.com
cd /opt/sso-server/nginx/ssl
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout privkey.pem -out fullchain.pem \
  -subj "/CN=staging.yourdomain.com"
```

### 3. Initialize Database and Services

**On both servers:**
```bash
ssh deploy@[server]
cd /opt/sso-server

# Pull images
docker-compose pull

# Start services
docker-compose --env-file .env.[environment] up -d

# Run migrations
docker-compose exec web python manage.py migrate

# Generate RSA keys
docker-compose exec web python manage.py genkeys

# Create superuser
docker-compose exec web python manage.py createsuperuser

# Collect static files
docker-compose exec web python manage.py collectstatic --noinput
```

## First Deployment (10 minutes)

### 1. Trigger Pipeline

```bash
# Create develop branch if it doesn't exist
git checkout -b develop
git push origin develop

# Or push to main
git checkout main
git push origin main
```

### 2. Monitor Pipeline

1. Go to GitLab → **CI/CD** → **Pipelines**
2. Click on the running pipeline
3. Watch test stages complete
4. Wait for build stage to finish

### 3. Deploy to Staging

1. In the pipeline view, find `deploy:staging` job
2. Click the **Play** button (▶️)
3. Monitor deployment logs
4. Once complete, verify: https://staging.yourdomain.com

### 4. Deploy to Production (when ready)

1. Merge develop to main (if using develop branch)
2. In the main pipeline, find `deploy:production` job
3. Click the **Play** button (▶️)
4. Monitor deployment logs
5. Verify: https://sso.yourdomain.com

## Verification Checklist

### After Each Deployment:

- [ ] Application loads at the domain
- [ ] Admin panel accessible: https://[domain]/admin/
- [ ] Login page loads: https://[domain]/login
- [ ] JWKS endpoint works: https://[domain]/.well-known/jwks.json
- [ ] No errors in logs: `docker-compose logs web`
- [ ] Database migrations applied
- [ ] Static files served correctly

### Test OAuth Flow:

- [ ] Visit test client: https://[domain]:8080/test-client.html
- [ ] Click "Start Login Flow"
- [ ] Complete authentication
- [ ] Receive tokens successfully
- [ ] User info endpoint works

## Troubleshooting Quick Fixes

### Pipeline Fails on Tests
```bash
# Check test logs in GitLab
# Ensure all environment variables are set
# Verify database credentials
```

### Docker Build Fails
```bash
# Check GitLab Container Registry is enabled
# Verify CI_REGISTRY_PASSWORD in variables
```

### SSH Connection Fails
```bash
# Verify SSH_PRIVATE_KEY is correctly added
# Test SSH manually: ssh deploy@[server]
# Check firewall allows SSH (port 22)
```

### Application Won't Start
```bash
# SSH to server
ssh deploy@[server]
cd /opt/sso-server

# Check logs
docker-compose logs web

# Verify environment file
cat .env.[environment]

# Restart services
docker-compose restart
```

### Database Migration Errors
```bash
docker-compose exec web python manage.py showmigrations
docker-compose exec web python manage.py migrate --fake-initial
```

## Next Steps

After successful deployment:

1. **Configure OAuth Clients**
   - Access admin panel
   - Create OAuth client applications
   - Configure redirect URIs

2. **Set Up Monitoring**
   - Configure uptime monitoring
   - Set up error tracking (Sentry)
   - Enable log aggregation

3. **Backup Strategy**
   - Configure automated database backups
   - Set up backup retention policy
   - Test restore procedures

4. **Security Hardening**
   - Review firewall rules
   - Enable rate limiting
   - Configure fail2ban
   - Set up regular security updates

5. **Performance Tuning**
   - Configure Redis caching
   - Optimize database queries
   - Set up CDN for static files
   - Monitor resource usage

## Common Commands

```bash
# View pipeline status
gitlab-ci-multi-runner list

# Manual deployment
ssh deploy@[server]
cd /opt/sso-server
./deploy.sh [staging|production]

# View logs
docker-compose logs -f web

# Restart services
docker-compose restart

# Run Django commands
docker-compose exec web python manage.py [command]

# Database backup
docker-compose exec web python manage.py dumpdata > backup.json
```

## Support

- Full Documentation: `CI_CD_SETUP_GUIDE.md`
- API Documentation: `API_DOCUMENTATION.md`
- Project README: `README.md`

---

**Estimated Total Setup Time**: 1.5 - 2 hours

**Status**: ✅ Ready for production deployment

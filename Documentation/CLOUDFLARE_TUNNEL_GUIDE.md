# Cloudflare Tunnel Deployment Guide

This guide covers deploying the SSO Server with Cloudflare Tunnel instead of traditional SSL certificates.

## Overview

With Cloudflare Tunnel, you don't need:
- ❌ Public IP addresses
- ❌ SSL certificate management
- ❌ Port forwarding
- ❌ Domain DNS configuration beyond Cloudflare

Cloudflare Tunnel provides:
- ✅ Automatic SSL/TLS encryption
- ✅ DDoS protection
- ✅ Access from anywhere
- ✅ No exposed ports
- ✅ Easy setup

## Architecture

```
Internet → Cloudflare Edge → Cloudflare Tunnel → Your Server (localhost:80) → Nginx → Django
         (HTTPS)            (Encrypted)           (HTTP)                  (HTTP)   (HTTP)
```

## Prerequisites

1. Cloudflare account (free tier works)
2. Domain added to Cloudflare
3. Server with Docker and Docker Compose installed
4. `cloudflared` installed on your server

## Step 1: Install Cloudflare Tunnel (cloudflared)

### On Ubuntu/Debian:

```bash
# Add Cloudflare GPG key
curl -L https://pkg.cloudflare.com/cloudflare-main.gpg | sudo tee /usr/share/keyrings/cloudflare-archive-keyring.gpg >/dev/null

# Add repository
echo "deb [signed-by=/usr/share/keyrings/cloudflare-archive-keyring.gpg] https://pkg.cloudflare.com/cloudflared $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/cloudflared.list

# Install
sudo apt update
sudo apt install cloudflared
```

### Verify Installation:

```bash
cloudflared --version
```

## Step 2: Authenticate Cloudflare

```bash
# This will open a browser for authentication
cloudflared tunnel login
```

This creates a certificate at `~/.cloudflared/cert.pem`

## Step 3: Create a Tunnel

```bash
# Create a tunnel named "sso-server"
cloudflared tunnel create sso-server
```

This will:
- Generate a tunnel ID (save this!)
- Create credentials file at `~/.cloudflared/<TUNNEL-ID>.json`

**Important**: Save your tunnel ID. You'll need it!

## Step 4: Configure DNS

Route your domain through the tunnel:

```bash
# Replace YOUR-TUNNEL-ID with your actual tunnel ID
# Replace sso.yourdomain.com with your domain
cloudflared tunnel route dns sso-server sso.yourdomain.com
```

This automatically creates a CNAME record in Cloudflare DNS.

## Step 5: Create Tunnel Configuration

Create config file at `~/.cloudflared/config.yml`:

```yaml
tunnel: YOUR-TUNNEL-ID
credentials-file: /home/YOUR-USER/.cloudflared/YOUR-TUNNEL-ID.json

ingress:
  # Route sso.yourdomain.com to local nginx
  - hostname: sso.yourdomain.com
    service: http://localhost:80
    originRequest:
      noTLSVerify: true
  
  # Catch-all rule (required)
  - service: http_status:404
```

**Replace:**
- `YOUR-TUNNEL-ID` with your tunnel ID
- `YOUR-USER` with your username
- `sso.yourdomain.com` with your domain

## Step 6: Deploy Your Application

### 6.1 Prepare Server Directory

```bash
sudo mkdir -p /opt/sso-server
sudo chown -R $USER:$USER /opt/sso-server
cd /opt/sso-server
```

### 6.2 Upload Files

From your local machine:

```bash
# Upload docker-compose file
scp docker-compose.production.yml user@yourserver:/opt/sso-server/docker-compose.yml

# Upload nginx configuration
scp -r nginx user@yourserver:/opt/sso-server/

# Upload environment file
cp .env.production.example .env.production
# Edit .env.production with your settings
scp .env.production user@yourserver:/opt/sso-server/
```

### 6.3 Update Environment Variables

Edit `/opt/sso-server/.env.production`:

```bash
# IMPORTANT: Set ALLOWED_HOSTS to your Cloudflare domain
ALLOWED_HOSTS=sso.yourdomain.com,localhost,127.0.0.1

# Set SSO_ISS to your public HTTPS URL (Cloudflare provides this)
SSO_ISS=https://sso.yourdomain.com

# Add your application domains to CORS
CORS_ALLOWED_ORIGINS=https://app.yourdomain.com,https://another-app.com
```

### 6.4 Start Application

```bash
cd /opt/sso-server

# Start services
docker-compose --env-file .env.production up -d

# Run migrations
docker-compose exec web python manage.py migrate

# Generate keys
docker-compose exec web python manage.py genkeys

# Create superuser
docker-compose exec web python manage.py createsuperuser

# Collect static files
docker-compose exec web python manage.py collectstatic --noinput
```

### 6.5 Verify Application is Running

```bash
# Check containers
docker-compose ps

# Check if nginx responds
curl http://localhost:80/admin/login/

# Should return HTML content
```

## Step 7: Start Cloudflare Tunnel

### Option A: Run as Foreground Process (Testing)

```bash
cloudflared tunnel run sso-server
```

### Option B: Run as System Service (Production)

```bash
# Install as system service
sudo cloudflared service install

# Start the service
sudo systemctl start cloudflared

# Enable on boot
sudo systemctl enable cloudflared

# Check status
sudo systemctl status cloudflared
```

## Step 8: Verify Everything Works

1. **Check Cloudflare Dashboard**
   - Go to Cloudflare Dashboard → Zero Trust → Access → Tunnels
   - Your tunnel should show as "Healthy"

2. **Test Public Access**
   ```bash
   curl https://sso.yourdomain.com/admin/login/
   ```

3. **Test OAuth Flow**
   - Visit `https://sso.yourdomain.com/login`
   - Should load login page with HTTPS

4. **Check Logs**
   ```bash
   # Application logs
   docker-compose logs -f web
   
   # Cloudflare tunnel logs
   sudo journalctl -u cloudflared -f
   ```

## GitLab CI/CD Integration

Update your GitLab CI/CD variables:

### Remove These Variables:
- ❌ `SSH_PRIVATE_KEY` (if using Cloudflare Tunnel exclusively)
- ❌ `STAGING_SERVER` / `PRODUCTION_SERVER` (if tunneling from localhost)

### Update Deployment Strategy:

If using Cloudflare Tunnel, you have two options:

#### Option 1: Deploy via SSH (Recommended)

Keep the existing CI/CD pipeline but ensure:

```yaml
# In .gitlab-ci.yml, the deploy script runs:
deploy:production:
  script:
    - ssh user@yourserver << 'EOF'
        cd /opt/sso-server
        docker-compose pull
        docker-compose up -d --force-recreate
        docker-compose exec -T web python manage.py migrate
      EOF
```

#### Option 2: Deploy via Cloudflare API (Advanced)

Use Cloudflare API to update tunnel configuration remotely.

## Configuration Files Summary

### Required Files on Server:

```
/opt/sso-server/
├── docker-compose.yml
├── .env.production
├── nginx/
│   ├── nginx.conf
│   └── conf.d/
│       └── default.conf
└── backups/ (created automatically)

~/.cloudflared/
├── cert.pem
├── config.yml
└── <TUNNEL-ID>.json
```

## Troubleshooting

### Tunnel Shows as Unhealthy

```bash
# Check cloudflared logs
sudo journalctl -u cloudflared -n 50

# Common issues:
# 1. Wrong tunnel ID in config.yml
# 2. Credentials file path incorrect
# 3. Application not running on localhost:80
```

### Application Returns 502 Bad Gateway

```bash
# Check if nginx is running
docker-compose ps nginx

# Check nginx logs
docker-compose logs nginx

# Check if web container is running
docker-compose ps web

# Verify nginx can reach web container
docker-compose exec nginx wget -O- http://web:8000/admin/login/
```

### DNS Not Resolving

```bash
# Check Cloudflare DNS settings
# Ensure CNAME record exists for your domain

# Test DNS resolution
nslookup sso.yourdomain.com

# Should point to a Cloudflare IP (starting with 104.*, 172.*, etc.)
```

### CORS Errors

Update `ALLOWED_HOSTS` and `CORS_ALLOWED_ORIGINS` in `.env.production`:

```bash
ALLOWED_HOSTS=sso.yourdomain.com,localhost
CORS_ALLOWED_ORIGINS=https://app.yourdomain.com,https://app2.yourdomain.com
```

Then restart:

```bash
docker-compose restart web
```

### SSL/TLS Errors

Cloudflare handles SSL. Ensure:

1. Cloudflare SSL mode is "Full" or "Full (Strict)" in dashboard
2. Application runs on HTTP (port 80)
3. Nginx config has `X-Forwarded-Proto https` header

## Security Considerations

### 1. Firewall Configuration

Since Cloudflare Tunnel doesn't expose ports:

```bash
# Block all incoming except SSH
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow ssh
sudo ufw enable
```

### 2. Cloudflare Access (Optional)

Add authentication before reaching your SSO:

1. Go to Cloudflare Dashboard → Zero Trust → Access → Applications
2. Create new application
3. Add authentication rules (email domain, etc.)

### 3. Rate Limiting

Configure in Cloudflare Dashboard → Security → WAF

## Advanced: Multiple Services

Route multiple services through one tunnel:

```yaml
# ~/.cloudflared/config.yml
tunnel: YOUR-TUNNEL-ID
credentials-file: /home/user/.cloudflared/YOUR-TUNNEL-ID.json

ingress:
  # SSO Server
  - hostname: sso.yourdomain.com
    service: http://localhost:80
  
  # Another service
  - hostname: app.yourdomain.com
    service: http://localhost:3000
  
  # Catch-all
  - service: http_status:404
```

## Monitoring

### Check Tunnel Health

```bash
# Via systemd
sudo systemctl status cloudflared

# Via cloudflared
cloudflared tunnel info sso-server
```

### Application Health

```bash
# Quick health check
curl http://localhost:80/admin/login/

# Full OAuth check
curl https://sso.yourdomain.com/.well-known/jwks.json
```

## Backup and Restore

### Backup Tunnel Credentials

```bash
# Backup tunnel credentials
sudo cp ~/.cloudflared/config.yml ~/config.yml.backup
sudo cp ~/.cloudflared/*.json ~/tunnel-credentials.backup.json

# Store securely (encrypted)
```

### Restore Tunnel

```bash
# Copy credentials back
cp ~/tunnel-credentials.backup.json ~/.cloudflared/
cp ~/config.yml.backup ~/.cloudflared/config.yml

# Restart tunnel
sudo systemctl restart cloudflared
```

## Performance Tips

1. **Enable Cloudflare Caching** for static files
2. **Use Argo Smart Routing** (paid) for faster routes
3. **Enable HTTP/3** in Cloudflare Dashboard → Network
4. **Optimize nginx** worker processes based on CPU cores

## Cost Considerations

- **Cloudflare Tunnel**: Free ✅
- **Cloudflare DNS**: Free ✅
- **Cloudflare SSL**: Free ✅
- **Cloudflare CDN**: Free (with limits) ✅
- **Argo Smart Routing**: Paid (optional)
- **Cloudflare Access**: Free for 50 users, paid beyond

## Quick Reference

```bash
# Tunnel management
cloudflared tunnel list
cloudflared tunnel info sso-server
cloudflared tunnel cleanup sso-server

# Service management
sudo systemctl start cloudflared
sudo systemctl stop cloudflared
sudo systemctl restart cloudflared
sudo systemctl status cloudflared

# Logs
sudo journalctl -u cloudflared -f
docker-compose logs -f web nginx
```

## Resources

- [Cloudflare Tunnel Docs](https://developers.cloudflare.com/cloudflare-one/connections/connect-apps/)
- [Cloudflared GitHub](https://github.com/cloudflare/cloudflared)
- [Cloudflare Dashboard](https://dash.cloudflare.com/)

---

**Setup Time**: ~30 minutes  
**Difficulty**: Easy  
**Cost**: Free

✅ No SSL certificates to manage  
✅ No port forwarding needed  
✅ Automatic DDoS protection  
✅ Global CDN included

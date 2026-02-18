# Multi-Frames Cloud Setup Guide

Manage multiple Multi-Frames installations remotely with a centralized cloud dashboard.

## Features

- **Modern Dashboard**: Responsive design with Inter font and sidebar navigation
- **Google Workspace Auth**: Secure login with your organization's Google accounts
- **Config Sync**: Push/pull configuration to 50+ devices simultaneously
- **Firmware Management**: Upload and deploy firmware updates to devices remotely
- **Real-time Status**: Monitor device health, uptime, and temperature
- **Full Portal Branding**: Logo upload (base64), favicon, iOS/Android home screen icons
- **Widget Templates**: Create, manage, and push widget templates to devices
- **Historical Metrics**: CPU temp, memory, disk, CPU usage with 24h/7d/30d charts
- **Mobile Friendly**: Hamburger menu, touch-optimized uploads, web app manifest

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    CLOUDFLARE                                │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐ │
│  │   Worker    │  │     KV      │  │      Dashboard      │ │
│  │   (API)     │  │  (Storage)  │  │   (Embedded HTML)   │ │
│  └─────────────┘  └─────────────┘  └─────────────────────┘ │
└───────────────────────────┬─────────────────────────────────┘
                            │ HTTPS
        ┌───────────────────┼───────────────────┐
        ▼                   ▼                   ▼
   ┌─────────┐         ┌─────────┐         ┌─────────┐
   │ Pi #1   │         │ Pi #2   │         │ Pi #N   │
   └─────────┘         └─────────┘         └─────────┘
```

## Setup Instructions

### Step 1: Create Cloudflare Account

1. Go to [cloudflare.com](https://cloudflare.com) and create a free account
2. Navigate to **Workers & Pages** in the dashboard

### Step 2: Create KV Namespaces

Create three KV namespaces in the Cloudflare dashboard:

1. **Workers & Pages** → **KV** → **Create namespace**
2. Create these namespaces:
   - `multi-frames-devices`
   - `multi-frames-configs`
   - `multi-frames-sessions`
3. Note down the namespace IDs

### Step 3: Set Up Google OAuth

1. Go to [Google Cloud Console](https://console.cloud.google.com)
2. Create a new project or select existing
3. Navigate to **APIs & Services** → **Credentials**
4. Click **Create Credentials** → **OAuth 2.0 Client IDs**
5. Choose **Web application**
6. Add authorized redirect URI: `https://your-worker.workers.dev/auth/google/callback`
7. Note down **Client ID** and **Client Secret**

### Step 4: Deploy the Worker

```bash
# Install Wrangler CLI
npm install -g wrangler

# Login to Cloudflare
wrangler login

# Navigate to cloud directory
cd cloud

# Copy the example config and edit with your KV namespace IDs
cp wrangler.toml.example wrangler.toml
nano wrangler.toml

# Set secrets
wrangler secret put GOOGLE_CLIENT_ID
wrangler secret put GOOGLE_CLIENT_SECRET
wrangler secret put ALLOWED_DOMAIN  # e.g., "yourcompany.com"
wrangler secret put JWT_SECRET      # Generate a random string

# Deploy
wrangler deploy
```

### Step 5: Configure Multi-Frames Devices

1. Access your Multi-Frames admin panel
2. Go to **System** → **Cloud Settings**
3. Enter:
   - **Cloud URL**: `https://your-worker.workers.dev`
   - **Device Key**: (Get this from the cloud dashboard after registering)
4. Click **Enable Cloud Sync**

### Step 6: Register Devices

1. Open your cloud dashboard: `https://your-worker.workers.dev`
2. Sign in with your Google Workspace account
3. Click **Add Device**
4. Enter a name for the device
5. Copy the generated **Device Key**
6. Paste the key into your Multi-Frames device settings

## Configuration

### wrangler.toml

```toml
name = "multi-frames-cloud"
main = "worker.js"
compatibility_date = "2024-01-01"

[[kv_namespaces]]
binding = "DEVICES"
id = "your-devices-kv-id"

[[kv_namespaces]]
binding = "CONFIGS"
id = "your-configs-kv-id"

[[kv_namespaces]]
binding = "SESSIONS"
id = "your-sessions-kv-id"
```

### Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `GOOGLE_CLIENT_ID` | Google OAuth client ID | Yes |
| `GOOGLE_CLIENT_SECRET` | Google OAuth client secret | Yes |
| `ALLOWED_DOMAIN` | Restrict to Google Workspace domain | Recommended |
| `JWT_SECRET` | Secret for signing auth tokens | Yes |

## API Endpoints

### Authentication

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/auth/google/url` | GET | Get Google OAuth URL |
| `/auth/google/callback` | GET | OAuth callback handler |
| `/auth/verify` | GET | Verify auth token |

### Devices

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/devices` | GET | List all devices |
| `/api/devices/register` | POST | Register new device |
| `/api/devices/heartbeat` | POST | Device heartbeat (device auth) |
| `/api/devices/{id}` | GET | Get device details |
| `/api/devices/{id}` | DELETE | Remove device |

### Configuration

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/config/pull` | GET | Device pulls config (device auth) |
| `/api/config/push` | POST | Device pushes config (device auth) |
| `/api/config/{id}` | GET | Get device config (user auth) |
| `/api/config/{id}` | PUT | Push config to device (user auth) |
| `/api/config/{id}/request` | POST | Request device to push its config (user auth) |
| `/api/config/bulk-push` | POST | Push config to multiple devices |

### Firmware

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/firmware` | GET | Get firmware metadata (user auth) |
| `/api/firmware/upload` | POST | Upload firmware file (user auth) |
| `/api/firmware/download` | GET | Device downloads firmware (device auth) |
| `/api/firmware/deploy` | POST | Queue firmware for devices (user auth) |

### Branding & Assets

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/branding` | GET | Get dashboard branding settings |
| `/api/branding` | PUT | Update branding with logo/icon uploads (user auth) |
| `/api/branding/logo` | GET | Serve uploaded logo image |
| `/api/branding/favicon` | GET | Serve uploaded favicon |
| `/api/branding/apple-touch-icon` | GET | Serve iOS home screen icon |
| `/api/branding/android-icon` | GET | Serve Android home screen icon |

### Widget Templates

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/widget-templates` | GET | List all widget templates (user auth) |
| `/api/widget-templates` | POST | Create widget template (user auth) |
| `/api/widget-templates/{id}` | PUT | Update widget template (user auth) |
| `/api/widget-templates/{id}` | DELETE | Delete widget template (user auth) |
| `/api/widget-templates/push` | POST | Push template to devices (user auth) |

### Metrics / Historical Data

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/metrics/record` | POST | Device records metrics (device auth) |
| `/api/metrics/{deviceId}` | GET | Query device metrics with range/metric params (user auth) |
| `/api/metrics/{deviceId}/latest` | GET | Get latest metric snapshot (user auth) |

## Usage

### Push Config to All Devices

```javascript
// From the dashboard, select multiple devices and push a template config
POST /api/config/bulk-push
{
  "device_ids": ["device-1", "device-2", "device-3"],
  "config": {
    "iframes": [...],
    "settings": {...}
  }
}
```

### Device Auto-Sync

Devices automatically:
1. Send heartbeat every 60 seconds
2. Check for config updates and pull new configs when available
3. Check for firmware updates and apply them (with automatic backup and restart)
4. Push config to cloud when requested by an admin via "Refresh" button

### Customize Branding

Navigate to **Settings** in the dashboard sidebar. The settings page has three tabs:

**Branding Tab:**
- **Company Name**: Displayed in the header and page title
- **Logo Upload**: Upload PNG/JPG/SVG logo (max 2MB, recommended 200x200px+)
- **Logo URL**: Fallback URL if no file uploaded

**App Icons Tab:**
- **Favicon**: Browser tab icon (ICO/PNG, max 512KB)
- **iOS Icon**: Apple Touch Icon for "Add to Home Screen" (180x180px PNG)
- **Android Icon**: Android icon + Web App Manifest (192x192px PNG)

**Colors & Theme Tab:**
- **Primary Color**: Main UI color (buttons, links, active states)
- **Accent Color**: Secondary color for gradients and highlights
- **Dark Mode**: Toggle dark/light theme

### Widget Templates

Navigate to **Widgets** in the sidebar to manage widget templates:

1. Create templates for any of the 8 widget types
2. Configure colors, size, border radius, and type-specific settings
3. Push templates to selected devices to add widgets to their dashboards

### Device Metrics

Navigate to **Metrics** in the sidebar to view historical device data:

1. Select a device to view its metrics
2. Choose a metric: CPU Temp, Memory %, CPU Usage, Hours Online
3. Select time range: 24 hours, 7 days, or 30 days
4. Interactive SVG chart shows trends over time

Devices automatically report metrics every 5 minutes. Data is stored with:
- Hourly granularity: 30-day retention
- Daily summaries: 90-day retention

## Security

- **Google Workspace Auth**: Only users from your domain can access
- **Device Keys**: Each device has a unique API key
- **HTTPS Only**: All communication is encrypted
- **No Password Storage**: Auth handled by Google

## Troubleshooting

### Device shows "Offline"

- Check device has internet connectivity
- Verify Cloud URL is correct in device settings
- Ensure Device Key is properly configured

### "Unauthorized" errors

- Check ALLOWED_DOMAIN matches your Google Workspace domain
- Verify GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET are correct
- Ensure redirect URI is configured in Google Console

### Config not syncing

- Check device is online (green status)
- Verify config version is incrementing
- Check device logs for sync errors

## Pricing

Cloudflare Workers free tier includes:
- 100,000 requests/day
- 10ms CPU time per request
- 1GB KV storage

This is sufficient for **50+ devices** with 60-second heartbeats.

## Support

For issues, please open a GitHub issue at:
https://github.com/LTS-Inc/Multi-Frames/issues

/**
 * Multi-Frames Cloud API - Cloudflare Worker
 *
 * This worker provides the cloud management API for Multi-Frames devices.
 * Deploy to Cloudflare Workers with KV namespace bindings.
 *
 * Required KV Namespaces:
 *   - DEVICES: Device registry and status
 *   - CONFIGS: Device configurations
 *   - SESSIONS: User sessions
 *
 * Required Environment Variables:
 *   - GOOGLE_CLIENT_ID: Google OAuth client ID
 *   - GOOGLE_CLIENT_SECRET: Google OAuth client secret
 *   - ALLOWED_DOMAIN: Google Workspace domain (e.g., "company.com")
 *   - JWT_SECRET: Secret for signing tokens
 */

const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Device-Key',
  'Access-Control-Max-Age': '86400',
};

// Helper: JSON response
function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...CORS_HEADERS }
  });
}

// Helper: Error response
function errorResponse(message, status = 400) {
  return jsonResponse({ error: message }, status);
}

// Helper: Generate device key
function generateDeviceKey() {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let key = 'mf_';
  for (let i = 0; i < 32; i++) {
    key += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return key;
}

// Helper: Verify JWT token
async function verifyToken(token, env) {
  try {
    const [header, payload, signature] = token.split('.');
    const data = JSON.parse(atob(payload));

    // Check expiration
    if (data.exp && data.exp < Date.now() / 1000) {
      return null;
    }

    // Verify domain if set
    if (env.ALLOWED_DOMAIN && data.hd !== env.ALLOWED_DOMAIN) {
      return null;
    }

    return data;
  } catch (e) {
    return null;
  }
}

// Helper: Create JWT token
async function createToken(payload, env) {
  const header = btoa(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const data = btoa(JSON.stringify({
    ...payload,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 86400 * 7 // 7 days
  }));
  // Simple signature (in production, use proper HMAC)
  const signature = btoa(env.JWT_SECRET + '.' + data);
  return `${header}.${data}.${signature}`;
}

// Verify device key
async function verifyDeviceKey(request, env) {
  const deviceKey = request.headers.get('X-Device-Key');
  if (!deviceKey) return null;

  const device = await env.DEVICES.get(`key:${deviceKey}`, 'json');
  return device;
}

// Verify user authentication
async function verifyAuth(request, env) {
  const auth = request.headers.get('Authorization');
  if (!auth || !auth.startsWith('Bearer ')) return null;

  const token = auth.substring(7);
  return await verifyToken(token, env);
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    // Handle CORS preflight
    if (method === 'OPTIONS') {
      return new Response(null, { headers: CORS_HEADERS });
    }

    try {
      // ============== AUTH ROUTES ==============

      // Google OAuth callback
      if (path === '/auth/google/callback' && method === 'GET') {
        const code = url.searchParams.get('code');
        if (!code) return errorResponse('Missing code', 400);

        // Exchange code for tokens
        const tokenResponse = await fetch('https://oauth2.googleapis.com/token', {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({
            code,
            client_id: env.GOOGLE_CLIENT_ID,
            client_secret: env.GOOGLE_CLIENT_SECRET,
            redirect_uri: `${url.origin}/auth/google/callback`,
            grant_type: 'authorization_code'
          })
        });

        const tokens = await tokenResponse.json();
        if (tokens.error) return errorResponse(tokens.error_description, 401);

        // Get user info
        const userResponse = await fetch('https://www.googleapis.com/oauth2/v2/userinfo', {
          headers: { Authorization: `Bearer ${tokens.access_token}` }
        });
        const user = await userResponse.json();

        // Check domain restriction
        if (env.ALLOWED_DOMAIN && user.hd !== env.ALLOWED_DOMAIN) {
          return errorResponse(`Access restricted to ${env.ALLOWED_DOMAIN} domain`, 403);
        }

        // Create session token
        const sessionToken = await createToken({
          sub: user.id,
          email: user.email,
          name: user.name,
          picture: user.picture,
          hd: user.hd
        }, env);

        // Redirect to dashboard with token
        return Response.redirect(`${url.origin}/dashboard?token=${sessionToken}`, 302);
      }

      // Get Google OAuth URL
      if (path === '/auth/google/url' && method === 'GET') {
        const authUrl = new URL('https://accounts.google.com/o/oauth2/v2/auth');
        authUrl.searchParams.set('client_id', env.GOOGLE_CLIENT_ID);
        authUrl.searchParams.set('redirect_uri', `${url.origin}/auth/google/callback`);
        authUrl.searchParams.set('response_type', 'code');
        authUrl.searchParams.set('scope', 'openid email profile');
        authUrl.searchParams.set('hd', env.ALLOWED_DOMAIN || '*');

        return jsonResponse({ url: authUrl.toString() });
      }

      // Verify token
      if (path === '/auth/verify' && method === 'GET') {
        const user = await verifyAuth(request, env);
        if (!user) return errorResponse('Invalid token', 401);
        return jsonResponse({ valid: true, user });
      }

      // ============== DEVICE ROUTES ==============

      // Register new device
      if (path === '/api/devices/register' && method === 'POST') {
        const user = await verifyAuth(request, env);
        if (!user) return errorResponse('Unauthorized', 401);

        const body = await request.json();
        const { name, hostname, ip_address, version } = body;

        if (!name) return errorResponse('Device name required', 400);

        const deviceId = crypto.randomUUID();
        const deviceKey = generateDeviceKey();

        const device = {
          id: deviceId,
          name,
          hostname: hostname || 'unknown',
          ip_address: ip_address || 'unknown',
          version: version || 'unknown',
          registered_by: user.email,
          registered_at: new Date().toISOString(),
          last_seen: new Date().toISOString(),
          status: 'offline',
          config_version: 0
        };

        // Store device
        await env.DEVICES.put(`device:${deviceId}`, JSON.stringify(device));
        await env.DEVICES.put(`key:${deviceKey}`, JSON.stringify({ id: deviceId }));

        // Add to device list
        const deviceList = await env.DEVICES.get('device_list', 'json') || [];
        deviceList.push(deviceId);
        await env.DEVICES.put('device_list', JSON.stringify(deviceList));

        return jsonResponse({
          success: true,
          device_id: deviceId,
          device_key: deviceKey,
          message: 'Device registered. Add this key to your Multi-Frames cloud settings.'
        });
      }

      // Device heartbeat (called by Multi-Frames instances)
      if (path === '/api/devices/heartbeat' && method === 'POST') {
        const deviceAuth = await verifyDeviceKey(request, env);
        if (!deviceAuth) return errorResponse('Invalid device key', 401);

        const body = await request.json();
        const device = await env.DEVICES.get(`device:${deviceAuth.id}`, 'json');

        if (!device) return errorResponse('Device not found', 404);

        // Update device status
        device.last_seen = new Date().toISOString();
        device.status = 'online';
        device.hostname = body.hostname || device.hostname;
        device.ip_address = body.ip_address || device.ip_address;
        device.version = body.version || device.version;
        device.uptime = body.uptime;
        device.memory_used = body.memory_used;
        device.cpu_temp = body.cpu_temp;
        device.local_config_version = body.config_version;

        await env.DEVICES.put(`device:${deviceAuth.id}`, JSON.stringify(device));

        // Check if config update available
        const cloudConfig = await env.CONFIGS.get(`config:${deviceAuth.id}`, 'json');
        const configUpdateAvailable = cloudConfig && cloudConfig.version > (body.config_version || 0);

        return jsonResponse({
          success: true,
          config_update_available: configUpdateAvailable,
          config_version: cloudConfig?.version || 0
        });
      }

      // List all devices
      if (path === '/api/devices' && method === 'GET') {
        const user = await verifyAuth(request, env);
        if (!user) return errorResponse('Unauthorized', 401);

        const deviceList = await env.DEVICES.get('device_list', 'json') || [];
        const devices = [];

        for (const deviceId of deviceList) {
          const device = await env.DEVICES.get(`device:${deviceId}`, 'json');
          if (device) {
            // Check if device is offline (no heartbeat in 2 minutes)
            const lastSeen = new Date(device.last_seen);
            if (Date.now() - lastSeen.getTime() > 120000) {
              device.status = 'offline';
            }
            devices.push(device);
          }
        }

        return jsonResponse({ devices });
      }

      // Get single device
      if (path.match(/^\/api\/devices\/[\w-]+$/) && method === 'GET') {
        const user = await verifyAuth(request, env);
        if (!user) return errorResponse('Unauthorized', 401);

        const deviceId = path.split('/').pop();
        const device = await env.DEVICES.get(`device:${deviceId}`, 'json');

        if (!device) return errorResponse('Device not found', 404);
        return jsonResponse({ device });
      }

      // Delete device
      if (path.match(/^\/api\/devices\/[\w-]+$/) && method === 'DELETE') {
        const user = await verifyAuth(request, env);
        if (!user) return errorResponse('Unauthorized', 401);

        const deviceId = path.split('/').pop();

        // Remove from device list
        const deviceList = await env.DEVICES.get('device_list', 'json') || [];
        const newList = deviceList.filter(id => id !== deviceId);
        await env.DEVICES.put('device_list', JSON.stringify(newList));

        // Delete device data
        await env.DEVICES.delete(`device:${deviceId}`);
        await env.CONFIGS.delete(`config:${deviceId}`);

        return jsonResponse({ success: true });
      }

      // ============== CONFIG ROUTES ==============

      // Get device config (for devices)
      if (path === '/api/config/pull' && method === 'GET') {
        const deviceAuth = await verifyDeviceKey(request, env);
        if (!deviceAuth) return errorResponse('Invalid device key', 401);

        const config = await env.CONFIGS.get(`config:${deviceAuth.id}`, 'json');
        return jsonResponse({ config: config?.data || null, version: config?.version || 0 });
      }

      // Push config to device (from dashboard)
      if (path.match(/^\/api\/config\/[\w-]+$/) && method === 'PUT') {
        const user = await verifyAuth(request, env);
        if (!user) return errorResponse('Unauthorized', 401);

        const deviceId = path.split('/').pop();
        const body = await request.json();

        const existingConfig = await env.CONFIGS.get(`config:${deviceId}`, 'json');
        const newVersion = (existingConfig?.version || 0) + 1;

        await env.CONFIGS.put(`config:${deviceId}`, JSON.stringify({
          data: body.config,
          version: newVersion,
          updated_by: user.email,
          updated_at: new Date().toISOString()
        }));

        return jsonResponse({ success: true, version: newVersion });
      }

      // Get device config (for dashboard)
      if (path.match(/^\/api\/config\/[\w-]+$/) && method === 'GET') {
        const user = await verifyAuth(request, env);
        if (!user) return errorResponse('Unauthorized', 401);

        const deviceId = path.split('/').pop();
        const config = await env.CONFIGS.get(`config:${deviceId}`, 'json');

        return jsonResponse({ config: config?.data || null, version: config?.version || 0 });
      }

      // Sync config from device to cloud
      if (path === '/api/config/push' && method === 'POST') {
        const deviceAuth = await verifyDeviceKey(request, env);
        if (!deviceAuth) return errorResponse('Invalid device key', 401);

        const body = await request.json();

        const existingConfig = await env.CONFIGS.get(`config:${deviceAuth.id}`, 'json');
        const newVersion = (existingConfig?.version || 0) + 1;

        await env.CONFIGS.put(`config:${deviceAuth.id}`, JSON.stringify({
          data: body.config,
          version: newVersion,
          updated_by: 'device',
          updated_at: new Date().toISOString()
        }));

        return jsonResponse({ success: true, version: newVersion });
      }

      // ============== BULK OPERATIONS ==============

      // Push config to multiple devices
      if (path === '/api/config/bulk-push' && method === 'POST') {
        const user = await verifyAuth(request, env);
        if (!user) return errorResponse('Unauthorized', 401);

        const body = await request.json();
        const { device_ids, config } = body;

        if (!device_ids || !Array.isArray(device_ids)) {
          return errorResponse('device_ids array required', 400);
        }

        const results = [];
        for (const deviceId of device_ids) {
          const existingConfig = await env.CONFIGS.get(`config:${deviceId}`, 'json');
          const newVersion = (existingConfig?.version || 0) + 1;

          await env.CONFIGS.put(`config:${deviceId}`, JSON.stringify({
            data: config,
            version: newVersion,
            updated_by: user.email,
            updated_at: new Date().toISOString()
          }));

          results.push({ device_id: deviceId, version: newVersion });
        }

        return jsonResponse({ success: true, results });
      }

      // ============== DASHBOARD ==============

      // Serve dashboard (basic HTML that loads the React app)
      if (path === '/dashboard' || path === '/' || path === '') {
        return new Response(DASHBOARD_HTML, {
          headers: { 'Content-Type': 'text/html' }
        });
      }

      // 404 for unknown routes
      return errorResponse('Not found', 404);

    } catch (error) {
      console.error('Error:', error);
      return errorResponse('Internal server error: ' + error.message, 500);
    }
  }
};

// Dashboard HTML (embedded for simplicity)
const DASHBOARD_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Multi-Frames Cloud</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    :root {
      --bg-primary: #0a0a0a;
      --bg-secondary: #141414;
      --bg-tertiary: #1a1a1a;
      --text-primary: #ffffff;
      --text-secondary: #888888;
      --accent: #3b82f6;
      --success: #22c55e;
      --warning: #f59e0b;
      --error: #ef4444;
      --border: #2a2a2a;
    }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: var(--bg-primary);
      color: var(--text-primary);
      min-height: 100vh;
    }
    .container { max-width: 1400px; margin: 0 auto; padding: 2rem; }
    .header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 2rem;
      padding-bottom: 1rem;
      border-bottom: 1px solid var(--border);
    }
    .header h1 { font-size: 1.5rem; display: flex; align-items: center; gap: 0.5rem; }
    .user-info { display: flex; align-items: center; gap: 1rem; }
    .user-info img { width: 32px; height: 32px; border-radius: 50%; }
    .btn {
      padding: 0.5rem 1rem;
      border: none;
      border-radius: 0.5rem;
      cursor: pointer;
      font-size: 0.9rem;
      transition: all 0.2s;
    }
    .btn-primary { background: var(--accent); color: white; }
    .btn-primary:hover { background: #2563eb; }
    .btn-secondary { background: var(--bg-tertiary); color: var(--text-primary); border: 1px solid var(--border); }
    .btn-danger { background: var(--error); color: white; }
    .login-container {
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      min-height: 80vh;
      gap: 1rem;
    }
    .login-container h2 { font-size: 2rem; margin-bottom: 1rem; }
    .google-btn {
      display: flex;
      align-items: center;
      gap: 0.75rem;
      padding: 0.75rem 1.5rem;
      background: white;
      color: #333;
      border-radius: 0.5rem;
      font-size: 1rem;
      cursor: pointer;
      border: none;
    }
    .devices-grid {
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(320px, 1fr));
      gap: 1.5rem;
    }
    .device-card {
      background: var(--bg-secondary);
      border: 1px solid var(--border);
      border-radius: 0.75rem;
      padding: 1.25rem;
      transition: all 0.2s;
    }
    .device-card:hover { border-color: var(--accent); }
    .device-header {
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      margin-bottom: 1rem;
    }
    .device-name { font-weight: 600; font-size: 1.1rem; }
    .device-status {
      padding: 0.25rem 0.5rem;
      border-radius: 1rem;
      font-size: 0.75rem;
      font-weight: 500;
    }
    .status-online { background: rgba(34, 197, 94, 0.2); color: var(--success); }
    .status-offline { background: rgba(239, 68, 68, 0.2); color: var(--error); }
    .device-info { color: var(--text-secondary); font-size: 0.85rem; margin-bottom: 1rem; }
    .device-info div { margin-bottom: 0.25rem; }
    .device-stats {
      display: grid;
      grid-template-columns: repeat(3, 1fr);
      gap: 0.5rem;
      padding-top: 1rem;
      border-top: 1px solid var(--border);
    }
    .stat { text-align: center; }
    .stat-value { font-weight: 600; font-size: 1rem; }
    .stat-label { font-size: 0.7rem; color: var(--text-secondary); }
    .device-actions {
      display: flex;
      gap: 0.5rem;
      margin-top: 1rem;
      padding-top: 1rem;
      border-top: 1px solid var(--border);
    }
    .device-actions .btn { flex: 1; font-size: 0.8rem; padding: 0.4rem; }
    .modal-overlay {
      position: fixed;
      top: 0;
      left: 0;
      right: 0;
      bottom: 0;
      background: rgba(0,0,0,0.8);
      display: flex;
      align-items: center;
      justify-content: center;
      z-index: 1000;
    }
    .modal {
      background: var(--bg-secondary);
      border: 1px solid var(--border);
      border-radius: 0.75rem;
      padding: 1.5rem;
      width: 90%;
      max-width: 500px;
      max-height: 80vh;
      overflow-y: auto;
    }
    .modal h3 { margin-bottom: 1rem; }
    .form-group { margin-bottom: 1rem; }
    .form-group label { display: block; margin-bottom: 0.5rem; color: var(--text-secondary); font-size: 0.9rem; }
    .form-group input, .form-group textarea {
      width: 100%;
      padding: 0.75rem;
      background: var(--bg-tertiary);
      border: 1px solid var(--border);
      border-radius: 0.5rem;
      color: var(--text-primary);
      font-size: 0.9rem;
    }
    .form-group textarea { min-height: 200px; font-family: monospace; }
    .modal-actions { display: flex; gap: 0.5rem; justify-content: flex-end; margin-top: 1.5rem; }
    .copy-box {
      background: var(--bg-tertiary);
      padding: 1rem;
      border-radius: 0.5rem;
      font-family: monospace;
      font-size: 0.85rem;
      word-break: break-all;
      margin: 1rem 0;
    }
    .empty-state {
      text-align: center;
      padding: 4rem 2rem;
      color: var(--text-secondary);
    }
    .empty-state h3 { color: var(--text-primary); margin-bottom: 0.5rem; }
    .refresh-btn { background: none; border: none; color: var(--text-secondary); cursor: pointer; font-size: 1.2rem; }
    .refresh-btn:hover { color: var(--text-primary); }
    @keyframes spin { to { transform: rotate(360deg); } }
    .spinning { animation: spin 1s linear infinite; }
  </style>
</head>
<body>
  <div id="app"></div>
  <script>
    // Multi-Frames Cloud Dashboard
    const API_BASE = window.location.origin;
    let authToken = null;
    let currentUser = null;
    let devices = [];
    let refreshInterval = null;

    // Initialize
    async function init() {
      // Check for token in URL or localStorage
      const urlParams = new URLSearchParams(window.location.search);
      const urlToken = urlParams.get('token');

      if (urlToken) {
        authToken = urlToken;
        localStorage.setItem('mf_token', urlToken);
        window.history.replaceState({}, '', '/dashboard');
      } else {
        authToken = localStorage.getItem('mf_token');
      }

      if (authToken) {
        const verified = await verifyToken();
        if (verified) {
          await loadDevices();
          startAutoRefresh();
        }
      }

      render();
    }

    // API calls
    async function api(path, options = {}) {
      const headers = { 'Content-Type': 'application/json', ...options.headers };
      if (authToken) headers['Authorization'] = 'Bearer ' + authToken;

      const response = await fetch(API_BASE + path, { ...options, headers });
      return response.json();
    }

    async function verifyToken() {
      try {
        const result = await api('/auth/verify');
        if (result.valid) {
          currentUser = result.user;
          return true;
        }
      } catch (e) {}
      authToken = null;
      localStorage.removeItem('mf_token');
      return false;
    }

    async function loadDevices() {
      const result = await api('/api/devices');
      devices = result.devices || [];
      render();
    }

    function startAutoRefresh() {
      if (refreshInterval) clearInterval(refreshInterval);
      refreshInterval = setInterval(loadDevices, 30000);
    }

    async function login() {
      const result = await api('/auth/google/url');
      window.location.href = result.url;
    }

    function logout() {
      authToken = null;
      currentUser = null;
      localStorage.removeItem('mf_token');
      if (refreshInterval) clearInterval(refreshInterval);
      render();
    }

    // Modal state
    let modalState = { show: false, type: null, data: null };

    function showModal(type, data = null) {
      modalState = { show: true, type, data };
      render();
    }

    function hideModal() {
      modalState = { show: false, type: null, data: null };
      render();
    }

    // Device actions
    async function registerDevice(e) {
      e.preventDefault();
      const form = e.target;
      const name = form.name.value;

      const result = await api('/api/devices/register', {
        method: 'POST',
        body: JSON.stringify({ name })
      });

      if (result.success) {
        showModal('deviceKey', result);
        await loadDevices();
      } else {
        alert('Error: ' + result.error);
      }
    }

    async function deleteDevice(deviceId) {
      if (!confirm('Are you sure you want to remove this device?')) return;

      await api('/api/devices/' + deviceId, { method: 'DELETE' });
      await loadDevices();
    }

    async function viewConfig(deviceId) {
      const result = await api('/api/config/' + deviceId);
      showModal('viewConfig', { deviceId, config: result.config, version: result.version });
    }

    async function pushConfig(deviceId, config) {
      const result = await api('/api/config/' + deviceId, {
        method: 'PUT',
        body: JSON.stringify({ config: JSON.parse(config) })
      });

      if (result.success) {
        alert('Config pushed! Version: ' + result.version);
        hideModal();
      } else {
        alert('Error: ' + result.error);
      }
    }

    // Render
    function render() {
      const app = document.getElementById('app');

      if (!authToken || !currentUser) {
        app.innerHTML = renderLogin();
      } else {
        app.innerHTML = renderDashboard();
      }
    }

    function renderLogin() {
      return \`
        <div class="login-container">
          <h2>Multi-Frames Cloud</h2>
          <p style="color: var(--text-secondary); margin-bottom: 2rem;">Manage your Multi-Frames devices from anywhere</p>
          <button class="google-btn" onclick="login()">
            <svg width="18" height="18" viewBox="0 0 24 24"><path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"/><path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/><path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"/><path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"/></svg>
            Sign in with Google
          </button>
        </div>
      \`;
    }

    function renderDashboard() {
      return \`
        <div class="container">
          <div class="header">
            <h1>📺 Multi-Frames Cloud</h1>
            <div class="user-info">
              <button class="refresh-btn" onclick="loadDevices(); this.classList.add('spinning'); setTimeout(() => this.classList.remove('spinning'), 1000);">🔄</button>
              <img src="\${currentUser.picture}" alt="Profile">
              <span>\${currentUser.name}</span>
              <button class="btn btn-secondary" onclick="logout()">Logout</button>
            </div>
          </div>

          <div style="margin-bottom: 1.5rem;">
            <button class="btn btn-primary" onclick="showModal('addDevice')">+ Add Device</button>
          </div>

          \${devices.length === 0 ? \`
            <div class="empty-state">
              <h3>No devices registered</h3>
              <p>Click "Add Device" to register your first Multi-Frames instance</p>
            </div>
          \` : \`
            <div class="devices-grid">
              \${devices.map(renderDeviceCard).join('')}
            </div>
          \`}
        </div>
        \${modalState.show ? renderModal() : ''}
      \`;
    }

    function renderDeviceCard(device) {
      const isOnline = device.status === 'online';
      const lastSeen = new Date(device.last_seen).toLocaleString();

      return \`
        <div class="device-card">
          <div class="device-header">
            <div class="device-name">\${device.name}</div>
            <div class="device-status \${isOnline ? 'status-online' : 'status-offline'}">
              \${isOnline ? '● Online' : '○ Offline'}
            </div>
          </div>
          <div class="device-info">
            <div>📍 \${device.hostname} (\${device.ip_address})</div>
            <div>📦 Version \${device.version}</div>
            <div>🕐 Last seen: \${lastSeen}</div>
          </div>
          \${isOnline ? \`
            <div class="device-stats">
              <div class="stat">
                <div class="stat-value">\${device.uptime || '-'}</div>
                <div class="stat-label">Uptime</div>
              </div>
              <div class="stat">
                <div class="stat-value">\${device.memory_used || '-'}</div>
                <div class="stat-label">Memory</div>
              </div>
              <div class="stat">
                <div class="stat-value">\${device.cpu_temp ? device.cpu_temp + '°C' : '-'}</div>
                <div class="stat-label">Temp</div>
              </div>
            </div>
          \` : ''}
          <div class="device-actions">
            <button class="btn btn-secondary" onclick="viewConfig('\${device.id}')">View Config</button>
            <button class="btn btn-danger" onclick="deleteDevice('\${device.id}')">Remove</button>
          </div>
        </div>
      \`;
    }

    function renderModal() {
      let content = '';

      if (modalState.type === 'addDevice') {
        content = \`
          <h3>Register New Device</h3>
          <form onsubmit="registerDevice(event)">
            <div class="form-group">
              <label>Device Name</label>
              <input type="text" name="name" placeholder="e.g., Kitchen Display" required>
            </div>
            <div class="modal-actions">
              <button type="button" class="btn btn-secondary" onclick="hideModal()">Cancel</button>
              <button type="submit" class="btn btn-primary">Register</button>
            </div>
          </form>
        \`;
      } else if (modalState.type === 'deviceKey') {
        content = \`
          <h3>✅ Device Registered!</h3>
          <p style="color: var(--text-secondary); margin-bottom: 1rem;">Add this key to your Multi-Frames cloud settings:</p>
          <div class="copy-box">\${modalState.data.device_key}</div>
          <p style="color: var(--warning); font-size: 0.85rem;">⚠️ Save this key now - it won't be shown again!</p>
          <div class="modal-actions">
            <button class="btn btn-primary" onclick="navigator.clipboard.writeText('\${modalState.data.device_key}'); alert('Copied!')">Copy Key</button>
            <button class="btn btn-secondary" onclick="hideModal()">Done</button>
          </div>
        \`;
      } else if (modalState.type === 'viewConfig') {
        const configStr = modalState.data.config ? JSON.stringify(modalState.data.config, null, 2) : '// No config synced yet';
        content = \`
          <h3>Device Configuration</h3>
          <p style="color: var(--text-secondary); margin-bottom: 0.5rem;">Version: \${modalState.data.version}</p>
          <div class="form-group">
            <textarea id="configEditor">\${configStr}</textarea>
          </div>
          <div class="modal-actions">
            <button class="btn btn-secondary" onclick="hideModal()">Close</button>
            <button class="btn btn-primary" onclick="pushConfig('\${modalState.data.deviceId}', document.getElementById('configEditor').value)">Push to Device</button>
          </div>
        \`;
      }

      return \`
        <div class="modal-overlay" onclick="if(event.target === this) hideModal()">
          <div class="modal">\${content}</div>
        </div>
      \`;
    }

    // Start
    init();
  </script>
</body>
</html>`;

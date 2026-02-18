/**
 * Multi-Frames Cloud API - Cloudflare Worker
 * Modern, Responsive Dashboard with Branding Customization
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

// Helper functions
function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...CORS_HEADERS }
  });
}

function errorResponse(message, status = 400) {
  return jsonResponse({ error: message }, status);
}

function generateDeviceKey() {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let key = 'mf_';
  for (let i = 0; i < 32; i++) {
    key += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return key;
}

async function verifyToken(token, env) {
  try {
    const [header, payload, signature] = token.split('.');
    const data = JSON.parse(atob(payload));
    if (data.exp && data.exp < Date.now() / 1000) return null;
    if (env.ALLOWED_DOMAIN && data.hd !== env.ALLOWED_DOMAIN) return null;
    return data;
  } catch (e) {
    return null;
  }
}

async function createToken(payload, env) {
  const header = btoa(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const data = btoa(JSON.stringify({
    ...payload,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 86400 * 7
  }));
  const signature = btoa(env.JWT_SECRET + '.' + data);
  return `${header}.${data}.${signature}`;
}

async function verifyDeviceKey(request, env) {
  const deviceKey = request.headers.get('X-Device-Key');
  if (!deviceKey) return null;
  const device = await env.DEVICES.get(`key:${deviceKey}`, 'json');
  return device;
}

async function verifyAuth(request, env) {
  const auth = request.headers.get('Authorization');
  if (!auth || !auth.startsWith('Bearer ')) return null;
  return await verifyToken(auth.substring(7), env);
}

// Default branding (expanded with logo/icon uploads and widget templates)
const DEFAULT_BRANDING = {
  companyName: 'Multi-Frames',
  logoUrl: '',
  logoData: '',
  logoMime: '',
  faviconData: '',
  faviconMime: '',
  appleTouchIconData: '',
  appleTouchIconMime: '',
  androidIconData: '',
  androidIconMime: '',
  primaryColor: '#3b82f6',
  accentColor: '#8b5cf6',
  darkMode: true
};

// Default widget templates for portal-managed widgets
const DEFAULT_WIDGET_TEMPLATES = [];

// Max upload sizes
const MAX_LOGO_SIZE = 2 * 1024 * 1024; // 2MB
const MAX_ICON_SIZE = 512 * 1024; // 512KB

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    if (method === 'OPTIONS') {
      return new Response(null, { headers: CORS_HEADERS });
    }

    try {
      // ============== AUTH ROUTES ==============

      if (path === '/auth/google/callback' && method === 'GET') {
        const code = url.searchParams.get('code');
        if (!code) return errorResponse('Missing code', 400);

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

        const userResponse = await fetch('https://www.googleapis.com/oauth2/v2/userinfo', {
          headers: { Authorization: `Bearer ${tokens.access_token}` }
        });
        const user = await userResponse.json();

        if (env.ALLOWED_DOMAIN && user.hd !== env.ALLOWED_DOMAIN) {
          return errorResponse(`Access restricted to ${env.ALLOWED_DOMAIN} domain`, 403);
        }

        const sessionToken = await createToken({
          sub: user.id,
          email: user.email,
          name: user.name,
          picture: user.picture,
          hd: user.hd
        }, env);

        return Response.redirect(`${url.origin}/dashboard?token=${sessionToken}`, 302);
      }

      if (path === '/auth/google/url' && method === 'GET') {
        const authUrl = new URL('https://accounts.google.com/o/oauth2/v2/auth');
        authUrl.searchParams.set('client_id', env.GOOGLE_CLIENT_ID);
        authUrl.searchParams.set('redirect_uri', `${url.origin}/auth/google/callback`);
        authUrl.searchParams.set('response_type', 'code');
        authUrl.searchParams.set('scope', 'openid email profile');
        authUrl.searchParams.set('access_type', 'online');
        authUrl.searchParams.set('prompt', 'select_account');
        if (env.ALLOWED_DOMAIN) {
          authUrl.searchParams.set('hd', env.ALLOWED_DOMAIN);
        }
        return jsonResponse({ url: authUrl.toString() });
      }

      if (path === '/auth/verify' && method === 'GET') {
        const user = await verifyAuth(request, env);
        if (!user) return errorResponse('Invalid token', 401);
        return jsonResponse({ valid: true, user });
      }

      // ============== BRANDING ROUTES ==============

      if (path === '/api/branding' && method === 'GET') {
        const branding = await env.CONFIGS.get('branding', 'json') || DEFAULT_BRANDING;
        return jsonResponse({ branding });
      }

      if (path === '/api/branding' && method === 'PUT') {
        const user = await verifyAuth(request, env);
        if (!user) return errorResponse('Unauthorized', 401);

        const body = await request.json();
        const existing = await env.CONFIGS.get('branding', 'json') || DEFAULT_BRANDING;
        const branding = {
          companyName: body.companyName || DEFAULT_BRANDING.companyName,
          logoUrl: body.logoUrl !== undefined ? body.logoUrl : (existing.logoUrl || ''),
          logoData: body.logoData !== undefined ? body.logoData : (existing.logoData || ''),
          logoMime: body.logoMime !== undefined ? body.logoMime : (existing.logoMime || ''),
          faviconData: body.faviconData !== undefined ? body.faviconData : (existing.faviconData || ''),
          faviconMime: body.faviconMime !== undefined ? body.faviconMime : (existing.faviconMime || ''),
          appleTouchIconData: body.appleTouchIconData !== undefined ? body.appleTouchIconData : (existing.appleTouchIconData || ''),
          appleTouchIconMime: body.appleTouchIconMime !== undefined ? body.appleTouchIconMime : (existing.appleTouchIconMime || ''),
          androidIconData: body.androidIconData !== undefined ? body.androidIconData : (existing.androidIconData || ''),
          androidIconMime: body.androidIconMime !== undefined ? body.androidIconMime : (existing.androidIconMime || ''),
          primaryColor: body.primaryColor || DEFAULT_BRANDING.primaryColor,
          accentColor: body.accentColor || DEFAULT_BRANDING.accentColor,
          darkMode: body.darkMode !== false
        };

        // Validate upload sizes
        if (branding.logoData && branding.logoData.length > MAX_LOGO_SIZE) {
          return errorResponse('Logo file too large (max 2MB)', 400);
        }
        if (branding.faviconData && branding.faviconData.length > MAX_ICON_SIZE) {
          return errorResponse('Favicon too large (max 512KB)', 400);
        }
        if (branding.appleTouchIconData && branding.appleTouchIconData.length > MAX_ICON_SIZE) {
          return errorResponse('Apple touch icon too large (max 512KB)', 400);
        }
        if (branding.androidIconData && branding.androidIconData.length > MAX_ICON_SIZE) {
          return errorResponse('Android icon too large (max 512KB)', 400);
        }

        await env.CONFIGS.put('branding', JSON.stringify(branding));
        return jsonResponse({ success: true, branding });
      }

      // ============== DEVICE ROUTES ==============

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

        await env.DEVICES.put(`device:${deviceId}`, JSON.stringify(device));
        await env.DEVICES.put(`key:${deviceKey}`, JSON.stringify({ id: deviceId }));

        const deviceList = await env.DEVICES.get('device_list', 'json') || [];
        deviceList.push(deviceId);
        await env.DEVICES.put('device_list', JSON.stringify(deviceList));

        return jsonResponse({
          success: true,
          device_id: deviceId,
          device_key: deviceKey,
          message: 'Device registered successfully'
        });
      }

      if (path === '/api/devices/heartbeat' && method === 'POST') {
        const deviceAuth = await verifyDeviceKey(request, env);
        if (!deviceAuth) return errorResponse('Invalid device key', 401);

        const body = await request.json();
        const device = await env.DEVICES.get(`device:${deviceAuth.id}`, 'json');
        if (!device) return errorResponse('Device not found', 404);

        device.last_seen = new Date().toISOString();
        device.status = 'online';
        device.hostname = body.hostname || device.hostname;
        device.ip_address = body.ip_address || device.ip_address;
        device.version = body.version || device.version;
        device.uptime = body.uptime;
        device.memory_used = body.memory_used;
        device.cpu_temp = body.cpu_temp;
        device.local_config_version = body.config_version;

        // Check for config request flag and clear it
        const configRequested = device.config_requested || false;
        if (configRequested) {
          device.config_requested = false;
        }

        await env.DEVICES.put(`device:${deviceAuth.id}`, JSON.stringify(device));

        const cloudConfig = await env.CONFIGS.get(`config:${deviceAuth.id}`, 'json');
        const configUpdateAvailable = cloudConfig && cloudConfig.version > (body.config_version || 0);

        // Check for pending firmware update
        const firmwareUpdateAvailable = device.firmware_pending || false;

        const heartbeatResponse = {
          success: true,
          config_update_available: configUpdateAvailable,
          config_version: cloudConfig?.version || 0,
          config_requested: configRequested
        };

        if (firmwareUpdateAvailable) {
          const firmware = await env.CONFIGS.get('firmware:latest', 'json');
          if (firmware) {
            heartbeatResponse.firmware_update_available = true;
            heartbeatResponse.firmware_version = firmware.version;
          }
        }

        return jsonResponse(heartbeatResponse);
      }

      if (path === '/api/devices' && method === 'GET') {
        const user = await verifyAuth(request, env);
        if (!user) return errorResponse('Unauthorized', 401);

        const deviceList = await env.DEVICES.get('device_list', 'json') || [];
        const devices = [];

        for (const deviceId of deviceList) {
          const device = await env.DEVICES.get(`device:${deviceId}`, 'json');
          if (device) {
            const lastSeen = new Date(device.last_seen);
            if (Date.now() - lastSeen.getTime() > 120000) {
              device.status = 'offline';
            }
            devices.push(device);
          }
        }

        return jsonResponse({ devices });
      }

      if (path.match(/^\/api\/devices\/[\w-]+$/) && method === 'GET') {
        const user = await verifyAuth(request, env);
        if (!user) return errorResponse('Unauthorized', 401);

        const deviceId = path.split('/').pop();
        const device = await env.DEVICES.get(`device:${deviceId}`, 'json');
        if (!device) return errorResponse('Device not found', 404);
        return jsonResponse({ device });
      }

      if (path.match(/^\/api\/devices\/[\w-]+$/) && method === 'DELETE') {
        const user = await verifyAuth(request, env);
        if (!user) return errorResponse('Unauthorized', 401);

        const deviceId = path.split('/').pop();
        const deviceList = await env.DEVICES.get('device_list', 'json') || [];
        const newList = deviceList.filter(id => id !== deviceId);
        await env.DEVICES.put('device_list', JSON.stringify(newList));
        await env.DEVICES.delete(`device:${deviceId}`);
        await env.CONFIGS.delete(`config:${deviceId}`);

        return jsonResponse({ success: true });
      }

      // ============== CONFIG ROUTES ==============

      if (path === '/api/config/pull' && method === 'GET') {
        const deviceAuth = await verifyDeviceKey(request, env);
        if (!deviceAuth) return errorResponse('Invalid device key', 401);

        const config = await env.CONFIGS.get(`config:${deviceAuth.id}`, 'json');
        return jsonResponse({ config: config?.data || null, version: config?.version || 0 });
      }

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

      if (path.match(/^\/api\/config\/[\w-]+$/) && method === 'GET') {
        const user = await verifyAuth(request, env);
        if (!user) return errorResponse('Unauthorized', 401);

        const deviceId = path.split('/').pop();
        const config = await env.CONFIGS.get(`config:${deviceId}`, 'json');
        return jsonResponse({ config: config?.data || null, version: config?.version || 0 });
      }

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

      if (path.match(/^\/api\/config\/[\w-]+\/request$/) && method === 'POST') {
        const user = await verifyAuth(request, env);
        if (!user) return errorResponse('Unauthorized', 401);

        const deviceId = path.split('/')[3];
        const device = await env.DEVICES.get(`device:${deviceId}`, 'json');
        if (!device) return errorResponse('Device not found', 404);

        device.config_requested = true;
        await env.DEVICES.put(`device:${deviceId}`, JSON.stringify(device));

        return jsonResponse({ success: true, message: 'Config refresh requested. Device will sync on next heartbeat.' });
      }

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

      // ============== FIRMWARE ROUTES ==============

      if (path === '/api/firmware/upload' && method === 'POST') {
        const user = await verifyAuth(request, env);
        if (!user) return errorResponse('Unauthorized', 401);

        const body = await request.json();
        const { version, content, notes } = body;

        if (!content) return errorResponse('Firmware content required', 400);
        if (!version) return errorResponse('Firmware version required', 400);

        const firmwareId = crypto.randomUUID();
        const firmware = {
          id: firmwareId,
          version,
          notes: notes || '',
          content,
          uploaded_by: user.email,
          uploaded_at: new Date().toISOString(),
          size: content.length
        };

        await env.CONFIGS.put('firmware:latest', JSON.stringify(firmware));

        return jsonResponse({
          success: true,
          firmware_id: firmwareId,
          version
        });
      }

      if (path === '/api/firmware' && method === 'GET') {
        const user = await verifyAuth(request, env);
        if (!user) return errorResponse('Unauthorized', 401);

        const firmware = await env.CONFIGS.get('firmware:latest', 'json');
        if (!firmware) return jsonResponse({ firmware: null });

        return jsonResponse({
          firmware: {
            id: firmware.id,
            version: firmware.version,
            notes: firmware.notes,
            uploaded_by: firmware.uploaded_by,
            uploaded_at: firmware.uploaded_at,
            size: firmware.size
          }
        });
      }

      if (path === '/api/firmware/download' && method === 'GET') {
        const deviceAuth = await verifyDeviceKey(request, env);
        if (!deviceAuth) return errorResponse('Invalid device key', 401);

        const firmware = await env.CONFIGS.get('firmware:latest', 'json');
        if (!firmware) return errorResponse('No firmware available', 404);

        const device = await env.DEVICES.get(`device:${deviceAuth.id}`, 'json');
        if (device) {
          device.firmware_pending = false;
          await env.DEVICES.put(`device:${deviceAuth.id}`, JSON.stringify(device));
        }

        return jsonResponse({
          content: firmware.content,
          version: firmware.version
        });
      }

      if (path === '/api/firmware/deploy' && method === 'POST') {
        const user = await verifyAuth(request, env);
        if (!user) return errorResponse('Unauthorized', 401);

        const body = await request.json();
        const { device_ids } = body;

        if (!device_ids || !Array.isArray(device_ids)) {
          return errorResponse('device_ids array required', 400);
        }

        const firmware = await env.CONFIGS.get('firmware:latest', 'json');
        if (!firmware) return errorResponse('No firmware uploaded yet', 400);

        const results = [];
        for (const deviceId of device_ids) {
          const device = await env.DEVICES.get(`device:${deviceId}`, 'json');
          if (device) {
            device.firmware_pending = true;
            device.firmware_target_version = firmware.version;
            await env.DEVICES.put(`device:${deviceId}`, JSON.stringify(device));
            results.push({ device_id: deviceId, status: 'queued' });
          } else {
            results.push({ device_id: deviceId, status: 'not_found' });
          }
        }

        return jsonResponse({ success: true, results });
      }

      // ============== WIDGET TEMPLATE ROUTES ==============

      if (path === '/api/widget-templates' && method === 'GET') {
        const user = await verifyAuth(request, env);
        if (!user) return errorResponse('Unauthorized', 401);

        const templates = await env.CONFIGS.get('widget_templates', 'json') || [];
        return jsonResponse({ templates });
      }

      if (path === '/api/widget-templates' && method === 'POST') {
        const user = await verifyAuth(request, env);
        if (!user) return errorResponse('Unauthorized', 401);

        const body = await request.json();
        if (!body.name || !body.type) return errorResponse('name and type required', 400);

        const templates = await env.CONFIGS.get('widget_templates', 'json') || [];
        const template = {
          id: crypto.randomUUID(),
          name: body.name,
          type: body.type,
          size: body.size || 'medium',
          config: body.config || {},
          bg_color: body.bg_color || '#141416',
          text_color: body.text_color || '#e8e8e8',
          border_radius: body.border_radius || 8,
          created_by: user.email,
          created_at: new Date().toISOString()
        };

        templates.push(template);
        await env.CONFIGS.put('widget_templates', JSON.stringify(templates));
        return jsonResponse({ success: true, template });
      }

      if (path.match(/^\/api\/widget-templates\/[\w-]+$/) && method === 'PUT') {
        const user = await verifyAuth(request, env);
        if (!user) return errorResponse('Unauthorized', 401);

        const templateId = path.split('/').pop();
        const body = await request.json();
        const templates = await env.CONFIGS.get('widget_templates', 'json') || [];
        const idx = templates.findIndex(t => t.id === templateId);
        if (idx === -1) return errorResponse('Template not found', 404);

        templates[idx] = { ...templates[idx], ...body, id: templateId, updated_at: new Date().toISOString() };
        await env.CONFIGS.put('widget_templates', JSON.stringify(templates));
        return jsonResponse({ success: true, template: templates[idx] });
      }

      if (path.match(/^\/api\/widget-templates\/[\w-]+$/) && method === 'DELETE') {
        const user = await verifyAuth(request, env);
        if (!user) return errorResponse('Unauthorized', 401);

        const templateId = path.split('/').pop();
        const templates = await env.CONFIGS.get('widget_templates', 'json') || [];
        const filtered = templates.filter(t => t.id !== templateId);
        await env.CONFIGS.put('widget_templates', JSON.stringify(filtered));
        return jsonResponse({ success: true });
      }

      if (path === '/api/widget-templates/push' && method === 'POST') {
        const user = await verifyAuth(request, env);
        if (!user) return errorResponse('Unauthorized', 401);

        const body = await request.json();
        const { template_id, device_ids } = body;
        if (!template_id || !device_ids || !Array.isArray(device_ids)) {
          return errorResponse('template_id and device_ids array required', 400);
        }

        const templates = await env.CONFIGS.get('widget_templates', 'json') || [];
        const template = templates.find(t => t.id === template_id);
        if (!template) return errorResponse('Template not found', 404);

        const widget = {
          id: crypto.randomUUID(),
          type: template.type,
          name: template.name,
          enabled: true,
          size: template.size,
          config: template.config,
          bg_color: template.bg_color,
          text_color: template.text_color,
          border_radius: template.border_radius
        };

        const results = [];
        for (const deviceId of device_ids) {
          const existing = await env.CONFIGS.get(`config:${deviceId}`, 'json');
          if (existing && existing.data) {
            if (!existing.data.widgets) existing.data.widgets = [];
            existing.data.widgets.push({ ...widget, id: crypto.randomUUID() });
            const newVersion = (existing.version || 0) + 1;
            await env.CONFIGS.put(`config:${deviceId}`, JSON.stringify({
              ...existing,
              data: existing.data,
              version: newVersion,
              updated_by: user.email,
              updated_at: new Date().toISOString()
            }));
            results.push({ device_id: deviceId, status: 'pushed', version: newVersion });
          } else {
            results.push({ device_id: deviceId, status: 'no_config' });
          }
        }

        return jsonResponse({ success: true, results });
      }

      // ============== HISTORICAL DATA / METRICS ROUTES ==============

      if (path === '/api/metrics/record' && method === 'POST') {
        const deviceAuth = await verifyDeviceKey(request, env);
        if (!deviceAuth) return errorResponse('Invalid device key', 401);

        const body = await request.json();
        const timestamp = new Date().toISOString();
        const metrics = {
          timestamp,
          cpu_temp: body.cpu_temp || null,
          memory_used: body.memory_used || null,
          memory_total: body.memory_total || null,
          disk_used: body.disk_used || null,
          disk_total: body.disk_total || null,
          uptime: body.uptime || null,
          cpu_usage: body.cpu_usage || null,
          network_rx: body.network_rx || null,
          network_tx: body.network_tx || null,
          custom: body.custom || {}
        };

        // Store metrics with hour-granularity keys for efficient retrieval
        const hourKey = timestamp.substring(0, 13); // "2026-02-18T14"
        const dayKey = timestamp.substring(0, 10); // "2026-02-18"
        const storageKey = `metrics:${deviceAuth.id}:${hourKey}`;

        const existing = await env.CONFIGS.get(storageKey, 'json') || [];
        existing.push(metrics);

        // Keep max 60 entries per hour (one per minute)
        if (existing.length > 60) existing.splice(0, existing.length - 60);

        await env.CONFIGS.put(storageKey, JSON.stringify(existing), {
          expirationTtl: 60 * 60 * 24 * 30 // 30-day retention
        });

        // Update daily summary
        const summaryKey = `metrics_summary:${deviceAuth.id}:${dayKey}`;
        const summary = await env.CONFIGS.get(summaryKey, 'json') || {
          date: dayKey,
          data_points: 0,
          avg_cpu_temp: null,
          max_cpu_temp: null,
          avg_memory_pct: null,
          avg_cpu_usage: null,
          hours_online: 0,
          hours: {}
        };

        const hour = parseInt(timestamp.substring(11, 13));
        summary.data_points++;
        summary.hours[hour] = true;
        summary.hours_online = Object.keys(summary.hours).length;

        if (metrics.cpu_temp !== null) {
          if (summary.avg_cpu_temp === null) {
            summary.avg_cpu_temp = metrics.cpu_temp;
            summary.max_cpu_temp = metrics.cpu_temp;
          } else {
            summary.avg_cpu_temp = (summary.avg_cpu_temp * (summary.data_points - 1) + metrics.cpu_temp) / summary.data_points;
            summary.max_cpu_temp = Math.max(summary.max_cpu_temp, metrics.cpu_temp);
          }
        }

        if (metrics.memory_used !== null && metrics.memory_total !== null && metrics.memory_total > 0) {
          const memPct = (metrics.memory_used / metrics.memory_total) * 100;
          if (summary.avg_memory_pct === null) {
            summary.avg_memory_pct = memPct;
          } else {
            summary.avg_memory_pct = (summary.avg_memory_pct * (summary.data_points - 1) + memPct) / summary.data_points;
          }
        }

        if (metrics.cpu_usage !== null) {
          if (summary.avg_cpu_usage === null) {
            summary.avg_cpu_usage = metrics.cpu_usage;
          } else {
            summary.avg_cpu_usage = (summary.avg_cpu_usage * (summary.data_points - 1) + metrics.cpu_usage) / summary.data_points;
          }
        }

        await env.CONFIGS.put(summaryKey, JSON.stringify(summary), {
          expirationTtl: 60 * 60 * 24 * 90 // 90-day retention for summaries
        });

        return jsonResponse({ success: true });
      }

      if (path.match(/^\/api\/metrics\/[\w-]+$/) && method === 'GET') {
        const user = await verifyAuth(request, env);
        if (!user) return errorResponse('Unauthorized', 401);

        const deviceId = path.split('/').pop();
        const range = url.searchParams.get('range') || '24h';
        const metric = url.searchParams.get('metric') || 'cpu_temp';

        const now = new Date();
        let dataPoints = [];

        if (range === '24h') {
          // Fetch last 24 hourly keys
          for (let i = 23; i >= 0; i--) {
            const d = new Date(now.getTime() - i * 60 * 60 * 1000);
            const hourKey = d.toISOString().substring(0, 13);
            const data = await env.CONFIGS.get(`metrics:${deviceId}:${hourKey}`, 'json');
            if (data && data.length > 0) {
              // Average the values for this hour
              const values = data.map(m => m[metric]).filter(v => v !== null && v !== undefined);
              if (values.length > 0) {
                const avg = values.reduce((a, b) => a + b, 0) / values.length;
                dataPoints.push({
                  timestamp: hourKey + ':00:00Z',
                  value: Math.round(avg * 10) / 10,
                  count: values.length
                });
              }
            }
          }
        } else if (range === '7d' || range === '30d') {
          const days = range === '7d' ? 7 : 30;
          for (let i = days - 1; i >= 0; i--) {
            const d = new Date(now.getTime() - i * 24 * 60 * 60 * 1000);
            const dayKey = d.toISOString().substring(0, 10);
            const summary = await env.CONFIGS.get(`metrics_summary:${deviceId}:${dayKey}`, 'json');
            if (summary) {
              let value = null;
              if (metric === 'cpu_temp') value = summary.avg_cpu_temp;
              else if (metric === 'memory_pct') value = summary.avg_memory_pct;
              else if (metric === 'cpu_usage') value = summary.avg_cpu_usage;
              else if (metric === 'hours_online') value = summary.hours_online;

              if (value !== null) {
                dataPoints.push({
                  timestamp: dayKey,
                  value: Math.round(value * 10) / 10,
                  data_points: summary.data_points,
                  max_temp: summary.max_cpu_temp
                });
              }
            }
          }
        }

        return jsonResponse({ device_id: deviceId, metric, range, data: dataPoints });
      }

      if (path.match(/^\/api\/metrics\/[\w-]+\/latest$/) && method === 'GET') {
        const user = await verifyAuth(request, env);
        if (!user) return errorResponse('Unauthorized', 401);

        const deviceId = path.split('/')[3];
        const hourKey = new Date().toISOString().substring(0, 13);
        const data = await env.CONFIGS.get(`metrics:${deviceId}:${hourKey}`, 'json') || [];
        const latest = data.length > 0 ? data[data.length - 1] : null;

        return jsonResponse({ device_id: deviceId, latest });
      }

      // ============== BRANDING ASSET ROUTES ==============

      if (path === '/api/branding/logo' && method === 'GET') {
        const branding = await env.CONFIGS.get('branding', 'json') || DEFAULT_BRANDING;
        if (!branding.logoData) return errorResponse('No logo uploaded', 404);

        const binary = Uint8Array.from(atob(branding.logoData), c => c.charCodeAt(0));
        return new Response(binary, {
          headers: {
            'Content-Type': branding.logoMime || 'image/png',
            'Cache-Control': 'public, max-age=3600',
            ...CORS_HEADERS
          }
        });
      }

      if (path === '/api/branding/favicon' && method === 'GET') {
        const branding = await env.CONFIGS.get('branding', 'json') || DEFAULT_BRANDING;
        if (!branding.faviconData) return errorResponse('No favicon uploaded', 404);

        const binary = Uint8Array.from(atob(branding.faviconData), c => c.charCodeAt(0));
        return new Response(binary, {
          headers: {
            'Content-Type': branding.faviconMime || 'image/x-icon',
            'Cache-Control': 'public, max-age=3600',
            ...CORS_HEADERS
          }
        });
      }

      if (path === '/api/branding/apple-touch-icon' && method === 'GET') {
        const branding = await env.CONFIGS.get('branding', 'json') || DEFAULT_BRANDING;
        if (!branding.appleTouchIconData) return errorResponse('No Apple touch icon uploaded', 404);

        const binary = Uint8Array.from(atob(branding.appleTouchIconData), c => c.charCodeAt(0));
        return new Response(binary, {
          headers: {
            'Content-Type': branding.appleTouchIconMime || 'image/png',
            'Cache-Control': 'public, max-age=3600',
            ...CORS_HEADERS
          }
        });
      }

      if (path === '/api/branding/android-icon' && method === 'GET') {
        const branding = await env.CONFIGS.get('branding', 'json') || DEFAULT_BRANDING;
        if (!branding.androidIconData) return errorResponse('No Android icon uploaded', 404);

        const binary = Uint8Array.from(atob(branding.androidIconData), c => c.charCodeAt(0));
        return new Response(binary, {
          headers: {
            'Content-Type': branding.androidIconMime || 'image/png',
            'Cache-Control': 'public, max-age=3600',
            ...CORS_HEADERS
          }
        });
      }

      // ============== DASHBOARD ==============

      if (path === '/dashboard' || path === '/' || path === '') {
        const branding = await env.CONFIGS.get('branding', 'json') || DEFAULT_BRANDING;
        return new Response(getDashboardHTML(branding), {
          headers: { 'Content-Type': 'text/html' }
        });
      }

      return errorResponse('Not found', 404);

    } catch (error) {
      console.error('Error:', error);
      return errorResponse('Internal server error: ' + error.message, 500);
    }
  }
};

function getDashboardHTML(branding) {
  const hasLogo = !!(branding.logoData || branding.logoUrl);
  const logoSrc = branding.logoData
    ? 'data:' + (branding.logoMime || 'image/png') + ';base64,' + branding.logoData
    : branding.logoUrl;
  const hasFavicon = !!branding.faviconData;
  const hasAppleIcon = !!branding.appleTouchIconData;
  const hasAndroidIcon = !!branding.androidIconData;

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta name="apple-mobile-web-app-capable" content="yes">
  <meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
  <meta name="mobile-web-app-capable" content="yes">
  <meta name="theme-color" content="${branding.primaryColor}">
  <title>${branding.companyName} - Cloud Dashboard</title>
  ${hasFavicon ? '<link rel="icon" href="/api/branding/favicon">' : ''}
  ${hasAppleIcon ? '<link rel="apple-touch-icon" sizes="180x180" href="/api/branding/apple-touch-icon">' : ''}
  ${hasAndroidIcon ? '<link rel="icon" sizes="192x192" href="/api/branding/android-icon">' : ''}
  ${hasAndroidIcon ? `<link rel="manifest" href="data:application/json;base64,${btoa(JSON.stringify({
    name: branding.companyName,
    short_name: branding.companyName,
    start_url: '/dashboard',
    display: 'standalone',
    background_color: branding.darkMode ? '#0f0f0f' : '#ffffff',
    theme_color: branding.primaryColor,
    icons: [{ src: '/api/branding/android-icon', sizes: '192x192', type: branding.androidIconMime || 'image/png' }]
  }))}">` : ''}
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }

    :root {
      --primary: ${branding.primaryColor};
      --primary-hover: ${branding.primaryColor}dd;
      --accent: ${branding.accentColor};
      --bg-primary: ${branding.darkMode ? '#0f0f0f' : '#ffffff'};
      --bg-secondary: ${branding.darkMode ? '#1a1a1a' : '#f5f5f5'};
      --bg-tertiary: ${branding.darkMode ? '#252525' : '#e5e5e5'};
      --bg-card: ${branding.darkMode ? '#1a1a1a' : '#ffffff'};
      --text-primary: ${branding.darkMode ? '#ffffff' : '#111111'};
      --text-secondary: ${branding.darkMode ? '#a0a0a0' : '#666666'};
      --text-muted: ${branding.darkMode ? '#666666' : '#999999'};
      --border: ${branding.darkMode ? '#2a2a2a' : '#e0e0e0'};
      --success: #22c55e;
      --warning: #f59e0b;
      --error: #ef4444;
      --shadow: ${branding.darkMode ? '0 4px 24px rgba(0,0,0,0.4)' : '0 4px 24px rgba(0,0,0,0.1)'};
      --shadow-sm: ${branding.darkMode ? '0 2px 8px rgba(0,0,0,0.3)' : '0 2px 8px rgba(0,0,0,0.08)'};
    }

    body {
      font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
      background: var(--bg-primary);
      color: var(--text-primary);
      min-height: 100vh;
      line-height: 1.5;
    }

    /* Scrollbar */
    ::-webkit-scrollbar { width: 8px; height: 8px; }
    ::-webkit-scrollbar-track { background: var(--bg-secondary); }
    ::-webkit-scrollbar-thumb { background: var(--border); border-radius: 4px; }
    ::-webkit-scrollbar-thumb:hover { background: var(--text-muted); }

    /* Layout */
    .app { display: flex; min-height: 100vh; }

    .sidebar {
      width: 280px;
      background: var(--bg-secondary);
      border-right: 1px solid var(--border);
      display: flex;
      flex-direction: column;
      position: fixed;
      height: 100vh;
      z-index: 100;
      transition: transform 0.3s ease;
    }

    .sidebar-header {
      padding: 1.5rem;
      border-bottom: 1px solid var(--border);
      display: flex;
      align-items: center;
      gap: 0.75rem;
    }

    .sidebar-logo {
      width: 40px;
      height: 40px;
      border-radius: 10px;
      object-fit: cover;
    }

    .sidebar-logo-placeholder {
      width: 40px;
      height: 40px;
      border-radius: 10px;
      background: linear-gradient(135deg, var(--primary), var(--accent));
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 1.25rem;
      color: white;
    }

    .sidebar-title {
      font-weight: 600;
      font-size: 1.1rem;
    }

    .sidebar-nav {
      flex: 1;
      padding: 1rem 0;
      overflow-y: auto;
    }

    .nav-item {
      display: flex;
      align-items: center;
      gap: 0.75rem;
      padding: 0.75rem 1.5rem;
      color: var(--text-secondary);
      cursor: pointer;
      transition: all 0.2s;
      border-left: 3px solid transparent;
    }

    .nav-item:hover {
      background: var(--bg-tertiary);
      color: var(--text-primary);
    }

    .nav-item.active {
      background: var(--primary)15;
      color: var(--primary);
      border-left-color: var(--primary);
    }

    .nav-item-icon { font-size: 1.25rem; }

    .sidebar-footer {
      padding: 1rem 1.5rem;
      border-top: 1px solid var(--border);
    }

    .user-card {
      display: flex;
      align-items: center;
      gap: 0.75rem;
      padding: 0.75rem;
      background: var(--bg-tertiary);
      border-radius: 12px;
    }

    .user-avatar {
      width: 36px;
      height: 36px;
      border-radius: 50%;
    }

    .user-info { flex: 1; min-width: 0; }
    .user-name { font-weight: 500; font-size: 0.9rem; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
    .user-email { font-size: 0.75rem; color: var(--text-muted); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }

    .main-content {
      flex: 1;
      margin-left: 280px;
      padding: 2rem;
      max-width: 1400px;
    }

    /* Mobile Sidebar */
    .mobile-header {
      display: none;
      position: fixed;
      top: 0;
      left: 0;
      right: 0;
      height: 60px;
      background: var(--bg-secondary);
      border-bottom: 1px solid var(--border);
      padding: 0 1rem;
      align-items: center;
      gap: 1rem;
      z-index: 99;
    }

    .menu-btn {
      background: none;
      border: none;
      color: var(--text-primary);
      font-size: 1.5rem;
      cursor: pointer;
      padding: 0.5rem;
    }

    .sidebar-overlay {
      display: none;
      position: fixed;
      inset: 0;
      background: rgba(0,0,0,0.5);
      z-index: 99;
    }

    @media (max-width: 768px) {
      .sidebar {
        transform: translateX(-100%);
      }
      .sidebar.open {
        transform: translateX(0);
      }
      .sidebar-overlay.open {
        display: block;
      }
      .mobile-header {
        display: flex;
      }
      .main-content {
        margin-left: 0;
        padding: 80px 1rem 1rem;
      }
    }

    /* Page Header */
    .page-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 2rem;
      flex-wrap: wrap;
      gap: 1rem;
    }

    .page-title {
      font-size: 1.75rem;
      font-weight: 700;
    }

    .page-subtitle {
      color: var(--text-secondary);
      font-size: 0.9rem;
      margin-top: 0.25rem;
    }

    /* Buttons */
    .btn {
      display: inline-flex;
      align-items: center;
      gap: 0.5rem;
      padding: 0.625rem 1.25rem;
      border: none;
      border-radius: 10px;
      font-size: 0.9rem;
      font-weight: 500;
      cursor: pointer;
      transition: all 0.2s;
      font-family: inherit;
    }

    .btn-primary {
      background: linear-gradient(135deg, var(--primary), var(--accent));
      color: white;
      box-shadow: 0 4px 12px var(--primary)40;
    }

    .btn-primary:hover {
      transform: translateY(-1px);
      box-shadow: 0 6px 16px var(--primary)50;
    }

    .btn-secondary {
      background: var(--bg-tertiary);
      color: var(--text-primary);
      border: 1px solid var(--border);
    }

    .btn-secondary:hover {
      background: var(--border);
    }

    .btn-danger {
      background: var(--error);
      color: white;
    }

    .btn-ghost {
      background: transparent;
      color: var(--text-secondary);
    }

    .btn-ghost:hover {
      background: var(--bg-tertiary);
      color: var(--text-primary);
    }

    .btn-sm {
      padding: 0.4rem 0.75rem;
      font-size: 0.8rem;
    }

    .btn-icon {
      padding: 0.5rem;
      border-radius: 8px;
    }

    /* Stats Grid */
    .stats-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 1rem;
      margin-bottom: 2rem;
    }

    .stat-card {
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 16px;
      padding: 1.25rem;
      box-shadow: var(--shadow-sm);
    }

    .stat-icon {
      width: 40px;
      height: 40px;
      border-radius: 10px;
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 1.25rem;
      margin-bottom: 0.75rem;
    }

    .stat-value {
      font-size: 1.75rem;
      font-weight: 700;
      line-height: 1.2;
    }

    .stat-label {
      color: var(--text-secondary);
      font-size: 0.85rem;
      margin-top: 0.25rem;
    }

    /* Device Grid */
    .devices-grid {
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(340px, 1fr));
      gap: 1.25rem;
    }

    .device-card {
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 16px;
      padding: 1.5rem;
      box-shadow: var(--shadow-sm);
      transition: all 0.3s;
    }

    .device-card:hover {
      border-color: var(--primary);
      box-shadow: var(--shadow);
      transform: translateY(-2px);
    }

    .device-header {
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      margin-bottom: 1rem;
    }

    .device-name {
      font-weight: 600;
      font-size: 1.1rem;
      display: flex;
      align-items: center;
      gap: 0.5rem;
    }

    .device-status {
      display: inline-flex;
      align-items: center;
      gap: 0.375rem;
      padding: 0.25rem 0.625rem;
      border-radius: 20px;
      font-size: 0.75rem;
      font-weight: 500;
    }

    .status-online {
      background: var(--success)20;
      color: var(--success);
    }

    .status-offline {
      background: var(--error)20;
      color: var(--error);
    }

    .status-dot {
      width: 6px;
      height: 6px;
      border-radius: 50%;
      background: currentColor;
    }

    .device-info {
      display: flex;
      flex-direction: column;
      gap: 0.5rem;
      margin-bottom: 1rem;
    }

    .device-info-row {
      display: flex;
      align-items: center;
      gap: 0.5rem;
      font-size: 0.85rem;
      color: var(--text-secondary);
    }

    .device-info-row span { color: var(--text-primary); }

    .device-stats {
      display: grid;
      grid-template-columns: repeat(3, 1fr);
      gap: 0.75rem;
      padding-top: 1rem;
      border-top: 1px solid var(--border);
      margin-bottom: 1rem;
    }

    .device-stat {
      text-align: center;
    }

    .device-stat-value {
      font-weight: 600;
      font-size: 1rem;
    }

    .device-stat-label {
      font-size: 0.7rem;
      color: var(--text-muted);
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }

    .device-actions {
      display: flex;
      gap: 0.5rem;
    }

    .device-actions .btn {
      flex: 1;
      justify-content: center;
    }

    /* Empty State */
    .empty-state {
      text-align: center;
      padding: 4rem 2rem;
      background: var(--bg-card);
      border: 2px dashed var(--border);
      border-radius: 16px;
    }

    .empty-state-icon {
      font-size: 4rem;
      margin-bottom: 1rem;
      opacity: 0.5;
    }

    .empty-state h3 {
      font-size: 1.25rem;
      margin-bottom: 0.5rem;
    }

    .empty-state p {
      color: var(--text-secondary);
      margin-bottom: 1.5rem;
    }

    /* Modal */
    .modal-overlay {
      position: fixed;
      inset: 0;
      background: rgba(0,0,0,0.6);
      backdrop-filter: blur(4px);
      display: flex;
      align-items: center;
      justify-content: center;
      z-index: 1000;
      padding: 1rem;
    }

    .modal {
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 20px;
      width: 100%;
      max-width: 500px;
      max-height: 90vh;
      overflow-y: auto;
      box-shadow: var(--shadow);
    }

    .modal-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 1.5rem;
      border-bottom: 1px solid var(--border);
    }

    .modal-title {
      font-size: 1.25rem;
      font-weight: 600;
    }

    .modal-close {
      background: none;
      border: none;
      font-size: 1.5rem;
      color: var(--text-muted);
      cursor: pointer;
      padding: 0.25rem;
      line-height: 1;
    }

    .modal-close:hover { color: var(--text-primary); }

    .modal-body {
      padding: 1.5rem;
    }

    .modal-footer {
      display: flex;
      justify-content: flex-end;
      gap: 0.75rem;
      padding: 1.5rem;
      border-top: 1px solid var(--border);
    }

    /* Forms */
    .form-group {
      margin-bottom: 1.25rem;
    }

    .form-label {
      display: block;
      font-size: 0.875rem;
      font-weight: 500;
      margin-bottom: 0.5rem;
      color: var(--text-secondary);
    }

    .form-input, .form-textarea, .form-select {
      width: 100%;
      padding: 0.75rem 1rem;
      background: var(--bg-tertiary);
      border: 1px solid var(--border);
      border-radius: 10px;
      color: var(--text-primary);
      font-size: 0.9rem;
      font-family: inherit;
      transition: all 0.2s;
    }

    .form-input:focus, .form-textarea:focus, .form-select:focus {
      outline: none;
      border-color: var(--primary);
      box-shadow: 0 0 0 3px var(--primary)20;
    }

    .form-textarea {
      min-height: 200px;
      font-family: 'SF Mono', Monaco, 'Courier New', monospace;
      font-size: 0.85rem;
      resize: vertical;
    }

    .form-hint {
      font-size: 0.75rem;
      color: var(--text-muted);
      margin-top: 0.375rem;
    }

    .form-row {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 1rem;
    }

    @media (max-width: 480px) {
      .form-row { grid-template-columns: 1fr; }
    }

    /* Color Picker */
    .color-input-wrapper {
      display: flex;
      align-items: center;
      gap: 0.75rem;
    }

    .color-preview {
      width: 40px;
      height: 40px;
      border-radius: 10px;
      border: 2px solid var(--border);
      cursor: pointer;
    }

    .color-input {
      position: absolute;
      opacity: 0;
      width: 0;
      height: 0;
    }

    /* Copy Box */
    .copy-box {
      background: var(--bg-tertiary);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 1rem;
      font-family: 'SF Mono', Monaco, 'Courier New', monospace;
      font-size: 0.85rem;
      word-break: break-all;
      position: relative;
    }

    .copy-btn {
      position: absolute;
      top: 0.5rem;
      right: 0.5rem;
    }

    /* Success Badge */
    .success-badge {
      display: inline-flex;
      align-items: center;
      gap: 0.5rem;
      padding: 0.75rem 1rem;
      background: var(--success)15;
      border: 1px solid var(--success)30;
      border-radius: 10px;
      color: var(--success);
      font-weight: 500;
      margin-bottom: 1rem;
    }

    /* Login Page */
    .login-container {
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      min-height: 100vh;
      padding: 2rem;
      text-align: center;
    }

    .login-card {
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 24px;
      padding: 3rem 2.5rem;
      max-width: 400px;
      width: 100%;
      box-shadow: var(--shadow);
    }

    .login-logo {
      width: 80px;
      height: 80px;
      border-radius: 20px;
      margin: 0 auto 1.5rem;
      object-fit: cover;
    }

    .login-logo-placeholder {
      width: 80px;
      height: 80px;
      border-radius: 20px;
      background: linear-gradient(135deg, var(--primary), var(--accent));
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 2.5rem;
      color: white;
      margin: 0 auto 1.5rem;
    }

    .login-title {
      font-size: 1.75rem;
      font-weight: 700;
      margin-bottom: 0.5rem;
    }

    .login-subtitle {
      color: var(--text-secondary);
      margin-bottom: 2rem;
    }

    .google-btn {
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 0.75rem;
      width: 100%;
      padding: 0.875rem 1.5rem;
      background: white;
      color: #333;
      border: 1px solid #ddd;
      border-radius: 12px;
      font-size: 1rem;
      font-weight: 500;
      cursor: pointer;
      transition: all 0.2s;
      font-family: inherit;
    }

    .google-btn:hover {
      background: #f8f8f8;
      box-shadow: 0 4px 12px rgba(0,0,0,0.1);
    }

    /* Settings Page */
    .settings-section {
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 16px;
      padding: 1.5rem;
      margin-bottom: 1.5rem;
    }

    .settings-section-title {
      font-size: 1rem;
      font-weight: 600;
      margin-bottom: 1.25rem;
      display: flex;
      align-items: center;
      gap: 0.5rem;
    }

    /* Loading */
    @keyframes spin {
      to { transform: rotate(360deg); }
    }

    .loading {
      display: inline-block;
      width: 20px;
      height: 20px;
      border: 2px solid var(--border);
      border-top-color: var(--primary);
      border-radius: 50%;
      animation: spin 0.8s linear infinite;
    }

    /* Toast */
    .toast {
      position: fixed;
      bottom: 2rem;
      right: 2rem;
      padding: 1rem 1.5rem;
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 12px;
      box-shadow: var(--shadow);
      display: flex;
      align-items: center;
      gap: 0.75rem;
      z-index: 1001;
      animation: slideIn 0.3s ease;
    }

    @keyframes slideIn {
      from { transform: translateY(100%); opacity: 0; }
      to { transform: translateY(0); opacity: 1; }
    }

    .toast-success { border-left: 4px solid var(--success); }
    .toast-error { border-left: 4px solid var(--error); }

    /* File Upload */
    .upload-zone {
      border: 2px dashed var(--border);
      border-radius: 12px;
      padding: 1.5rem;
      text-align: center;
      cursor: pointer;
      transition: all 0.2s;
      background: var(--bg-tertiary);
    }
    .upload-zone:hover, .upload-zone.dragover {
      border-color: var(--primary);
      background: var(--primary)08;
    }
    .upload-zone-icon { font-size: 2rem; margin-bottom: 0.5rem; opacity: 0.6; }
    .upload-zone-text { color: var(--text-secondary); font-size: 0.85rem; }
    .upload-zone-hint { color: var(--text-muted); font-size: 0.75rem; margin-top: 0.25rem; }
    .upload-preview {
      display: flex;
      align-items: center;
      gap: 1rem;
      padding: 0.75rem;
      background: var(--bg-tertiary);
      border: 1px solid var(--border);
      border-radius: 10px;
      margin-top: 0.75rem;
    }
    .upload-preview img {
      width: 48px;
      height: 48px;
      border-radius: 8px;
      object-fit: cover;
      border: 1px solid var(--border);
    }
    .upload-preview-info { flex: 1; }
    .upload-preview-name { font-weight: 500; font-size: 0.85rem; }
    .upload-preview-size { font-size: 0.75rem; color: var(--text-muted); }

    /* Chart */
    .chart-container {
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 16px;
      padding: 1.5rem;
      margin-bottom: 1.5rem;
    }
    .chart-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 1rem;
      flex-wrap: wrap;
      gap: 0.75rem;
    }
    .chart-title { font-weight: 600; font-size: 1rem; }
    .chart-controls {
      display: flex;
      gap: 0.25rem;
      background: var(--bg-tertiary);
      border-radius: 8px;
      padding: 0.25rem;
    }
    .chart-controls button {
      padding: 0.375rem 0.75rem;
      border: none;
      background: transparent;
      color: var(--text-secondary);
      font-size: 0.8rem;
      border-radius: 6px;
      cursor: pointer;
      font-family: inherit;
      transition: all 0.2s;
    }
    .chart-controls button.active {
      background: var(--primary);
      color: white;
    }
    .chart-svg {
      width: 100%;
      height: 200px;
    }
    .chart-empty {
      text-align: center;
      padding: 3rem 1rem;
      color: var(--text-muted);
      font-size: 0.9rem;
    }

    /* Widget template cards */
    .widget-tmpl-grid {
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
      gap: 1rem;
    }
    .widget-tmpl-card {
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 16px;
      padding: 1.25rem;
      box-shadow: var(--shadow-sm);
      transition: all 0.2s;
    }
    .widget-tmpl-card:hover {
      border-color: var(--primary);
      box-shadow: var(--shadow);
    }
    .widget-tmpl-type {
      display: inline-flex;
      align-items: center;
      gap: 0.375rem;
      padding: 0.25rem 0.625rem;
      border-radius: 20px;
      font-size: 0.75rem;
      font-weight: 500;
      background: var(--primary)15;
      color: var(--primary);
      margin-bottom: 0.75rem;
    }
    .widget-tmpl-name { font-weight: 600; font-size: 1.05rem; margin-bottom: 0.5rem; }
    .widget-tmpl-preview {
      width: 100%;
      height: 80px;
      border-radius: 8px;
      margin-bottom: 0.75rem;
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 2rem;
      opacity: 0.5;
    }
    .widget-tmpl-actions { display: flex; gap: 0.5rem; }
    .widget-tmpl-actions .btn { flex: 1; justify-content: center; }

    /* Tabs for sub-navigation */
    .tab-bar {
      display: flex;
      gap: 0;
      border-bottom: 1px solid var(--border);
      margin-bottom: 1.5rem;
      overflow-x: auto;
      -webkit-overflow-scrolling: touch;
    }
    .tab-item {
      padding: 0.75rem 1.25rem;
      color: var(--text-secondary);
      cursor: pointer;
      font-size: 0.9rem;
      font-weight: 500;
      border-bottom: 2px solid transparent;
      white-space: nowrap;
      transition: all 0.2s;
    }
    .tab-item:hover { color: var(--text-primary); }
    .tab-item.active {
      color: var(--primary);
      border-bottom-color: var(--primary);
    }

    /* Metric badge */
    .metric-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
      gap: 0.75rem;
      margin-bottom: 1.5rem;
    }
    .metric-card {
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 1rem;
      text-align: center;
    }
    .metric-value { font-size: 1.5rem; font-weight: 700; }
    .metric-label { font-size: 0.75rem; color: var(--text-muted); margin-top: 0.25rem; }
    .metric-trend { font-size: 0.7rem; margin-top: 0.25rem; }
    .metric-trend.up { color: var(--error); }
    .metric-trend.down { color: var(--success); }
    .metric-trend.stable { color: var(--text-muted); }

    /* Responsive adjustments for new sections */
    @media (max-width: 768px) {
      .chart-svg { height: 150px; }
      .widget-tmpl-grid { grid-template-columns: 1fr; }
      .metric-grid { grid-template-columns: repeat(2, 1fr); }
      .upload-zone { padding: 1rem; }
      .tab-bar { gap: 0; }
      .tab-item { padding: 0.625rem 0.75rem; font-size: 0.8rem; }
    }
    @media (max-width: 480px) {
      .metric-grid { grid-template-columns: 1fr 1fr; }
      .chart-header { flex-direction: column; align-items: flex-start; }
    }
  </style>
</head>
<body>
  <div id="app"></div>
  <script>
    // State
    const API = window.location.origin;
    let state = {
      token: null,
      user: null,
      devices: [],
      firmware: null,
      branding: ${JSON.stringify(branding)},
      widgetTemplates: [],
      metricsCache: {},
      metricsDevice: null,
      metricsRange: '24h',
      metricsMetric: 'cpu_temp',
      currentPage: 'devices',
      settingsTab: 'branding',
      modal: null,
      sidebarOpen: false,
      pendingUploads: {}
    };

    // Init
    async function init() {
      const urlParams = new URLSearchParams(window.location.search);
      const urlToken = urlParams.get('token');

      if (urlToken) {
        state.token = urlToken;
        localStorage.setItem('mf_token', urlToken);
        window.history.replaceState({}, '', '/dashboard');
      } else {
        state.token = localStorage.getItem('mf_token');
      }

      if (state.token) {
        const verified = await verifyToken();
        if (verified) {
          await Promise.all([loadDevices(), loadFirmware(), loadWidgetTemplates()]);
          setInterval(loadDevices, 30000);
        }
      }

      render();
    }

    // API
    async function api(path, options = {}) {
      const headers = { 'Content-Type': 'application/json', ...options.headers };
      if (state.token) headers['Authorization'] = 'Bearer ' + state.token;
      const response = await fetch(API + path, { ...options, headers });
      return response.json();
    }

    async function verifyToken() {
      try {
        const result = await api('/auth/verify');
        if (result.valid) {
          state.user = result.user;
          return true;
        }
      } catch (e) {}
      state.token = null;
      localStorage.removeItem('mf_token');
      return false;
    }

    async function loadDevices() {
      const result = await api('/api/devices');
      state.devices = result.devices || [];
      render();
    }

    async function loadBranding() {
      const result = await api('/api/branding');
      state.branding = result.branding;
      render();
    }

    async function loadFirmware() {
      try {
        const result = await api('/api/firmware');
        state.firmware = result.firmware;
      } catch (e) {
        state.firmware = null;
      }
    }

    async function loadWidgetTemplates() {
      try {
        const result = await api('/api/widget-templates');
        state.widgetTemplates = result.templates || [];
      } catch (e) {
        state.widgetTemplates = [];
      }
    }

    async function loadMetrics(deviceId, range, metric) {
      const cacheKey = deviceId + ':' + range + ':' + metric;
      try {
        const result = await api('/api/metrics/' + deviceId + '?range=' + range + '&metric=' + metric);
        state.metricsCache[cacheKey] = result.data || [];
      } catch (e) {
        state.metricsCache[cacheKey] = [];
      }
      render();
    }

    // File upload helpers
    function handleFileUpload(inputId, field, maxSize, previewId) {
      const input = document.getElementById(inputId);
      if (!input || !input.files.length) return;

      const file = input.files[0];
      if (file.size > maxSize) {
        showToast('File too large (max ' + Math.round(maxSize/1024) + 'KB)', 'error');
        return;
      }

      const reader = new FileReader();
      reader.onload = function(e) {
        const base64 = e.target.result.split(',')[1];
        const mime = file.type || 'image/png';
        state.pendingUploads[field + 'Data'] = base64;
        state.pendingUploads[field + 'Mime'] = mime;

        // Show preview
        const preview = document.getElementById(previewId);
        if (preview) {
          preview.innerHTML = '<div class="upload-preview"><img src="' + e.target.result + '" alt="Preview"><div class="upload-preview-info"><div class="upload-preview-name">' + file.name + '</div><div class="upload-preview-size">' + (file.size / 1024).toFixed(1) + ' KB</div></div><button class="btn btn-ghost btn-sm" onclick="clearUpload(\\'' + field + '\\',\\'' + previewId + '\\',\\'' + inputId + '\\')">Remove</button></div>';
        }
      };
      reader.readAsDataURL(file);
    }

    function clearUpload(field, previewId, inputId) {
      delete state.pendingUploads[field + 'Data'];
      delete state.pendingUploads[field + 'Mime'];
      const preview = document.getElementById(previewId);
      if (preview) preview.innerHTML = '';
      const input = document.getElementById(inputId);
      if (input) input.value = '';
    }

    // Actions
    async function login() {
      const result = await api('/auth/google/url');
      window.location.href = result.url;
    }

    function logout() {
      state.token = null;
      state.user = null;
      localStorage.removeItem('mf_token');
      render();
    }

    function showModal(type, data = null) {
      state.modal = { type, data };
      render();
    }

    function hideModal() {
      state.modal = null;
      render();
    }

    function toggleSidebar() {
      state.sidebarOpen = !state.sidebarOpen;
      render();
    }

    function setPage(page) {
      state.currentPage = page;
      state.sidebarOpen = false;
      render();
    }

    function showToast(message, type = 'success') {
      const toast = document.createElement('div');
      toast.className = 'toast toast-' + type;
      toast.innerHTML = (type === 'success' ? '✓' : '✕') + ' ' + message;
      document.body.appendChild(toast);
      setTimeout(() => toast.remove(), 3000);
    }

    // Device Actions
    async function registerDevice(e) {
      e.preventDefault();
      const form = e.target;
      const result = await api('/api/devices/register', {
        method: 'POST',
        body: JSON.stringify({ name: form.name.value })
      });

      if (result.success) {
        showModal('deviceKey', result);
        await loadDevices();
      } else {
        showToast(result.error, 'error');
      }
    }

    async function deleteDevice(deviceId) {
      if (!confirm('Remove this device?')) return;
      await api('/api/devices/' + deviceId, { method: 'DELETE' });
      showToast('Device removed');
      await loadDevices();
    }

    async function viewConfig(deviceId) {
      const result = await api('/api/config/' + deviceId);
      showModal('viewConfig', { deviceId, config: result.config, version: result.version });
    }

    async function pushConfig(deviceId, config) {
      try {
        const parsed = JSON.parse(config);
        const result = await api('/api/config/' + deviceId, {
          method: 'PUT',
          body: JSON.stringify({ config: parsed })
        });
        if (result.success) {
          showToast('Config pushed (v' + result.version + ')');
          hideModal();
        }
      } catch (e) {
        showToast('Invalid JSON', 'error');
      }
    }

    async function saveBranding(e) {
      e.preventDefault();
      const form = e.target;
      const payload = {
        companyName: form.companyName.value,
        logoUrl: form.logoUrl ? form.logoUrl.value : '',
        primaryColor: form.primaryColor.value,
        accentColor: form.accentColor.value,
        darkMode: form.darkMode.checked,
        ...state.pendingUploads
      };

      const result = await api('/api/branding', {
        method: 'PUT',
        body: JSON.stringify(payload)
      });

      if (result.success) {
        state.branding = result.branding;
        state.pendingUploads = {};
        showToast('Branding saved! Refresh to see full changes.');
      } else {
        showToast(result.error || 'Save failed', 'error');
      }
    }

    function clearBrandingAsset(field) {
      state.pendingUploads[field + 'Data'] = '';
      state.pendingUploads[field + 'Mime'] = '';
      showToast('Asset will be removed on save');
      render();
    }

    // Widget Template Actions
    async function createWidgetTemplate(e) {
      e.preventDefault();
      const form = e.target;
      const configStr = form.widgetConfig ? form.widgetConfig.value : '{}';
      let config;
      try { config = JSON.parse(configStr); } catch(ex) { showToast('Invalid JSON config', 'error'); return; }

      const result = await api('/api/widget-templates', {
        method: 'POST',
        body: JSON.stringify({
          name: form.widgetName.value,
          type: form.widgetType.value,
          size: form.widgetSize.value,
          config,
          bg_color: form.widgetBg.value,
          text_color: form.widgetText.value,
          border_radius: parseInt(form.widgetRadius.value) || 8
        })
      });

      if (result.success) {
        showToast('Widget template created');
        hideModal();
        await loadWidgetTemplates();
        render();
      } else {
        showToast(result.error || 'Create failed', 'error');
      }
    }

    async function deleteWidgetTemplate(id) {
      if (!confirm('Delete this widget template?')) return;
      await api('/api/widget-templates/' + id, { method: 'DELETE' });
      showToast('Template deleted');
      await loadWidgetTemplates();
      render();
    }

    async function pushWidgetToDevices(templateId) {
      showModal('pushWidget', { template_id: templateId });
    }

    async function doPushWidget(e) {
      e.preventDefault();
      const checkboxes = document.querySelectorAll('.push-widget-cb:checked');
      const deviceIds = Array.from(checkboxes).map(cb => cb.value);
      if (deviceIds.length === 0) { showToast('Select at least one device', 'error'); return; }

      const result = await api('/api/widget-templates/push', {
        method: 'POST',
        body: JSON.stringify({ template_id: state.modal.data.template_id, device_ids: deviceIds })
      });

      if (result.success) {
        const pushed = result.results.filter(r => r.status === 'pushed').length;
        showToast('Widget pushed to ' + pushed + ' device(s)');
        hideModal();
      } else {
        showToast(result.error || 'Push failed', 'error');
      }
    }

    // Metrics helpers
    async function selectMetricsDevice(deviceId) {
      state.metricsDevice = deviceId;
      await loadMetrics(deviceId, state.metricsRange, state.metricsMetric);
    }

    async function setMetricsRange(range) {
      state.metricsRange = range;
      if (state.metricsDevice) await loadMetrics(state.metricsDevice, range, state.metricsMetric);
    }

    async function setMetricsMetric(metric) {
      state.metricsMetric = metric;
      if (state.metricsDevice) await loadMetrics(state.metricsDevice, state.metricsRange, metric);
    }

    async function uploadFirmware(e) {
      e.preventDefault();
      const fileInput = document.getElementById('firmwareFile');
      const notesInput = document.getElementById('firmwareNotes');

      if (!fileInput.files.length) {
        showToast('Please select a firmware file', 'error');
        return;
      }

      const file = fileInput.files[0];
      if (!file.name.endsWith('.py')) {
        showToast('Firmware must be a .py file', 'error');
        return;
      }

      const content = await file.text();

      // Extract version from file content
      const versionMatch = content.match(/VERSION\\s*=\\s*[\"']([^\"']+)[\"']/);
      const version = versionMatch ? versionMatch[1] : 'unknown';

      const result = await api('/api/firmware/upload', {
        method: 'POST',
        body: JSON.stringify({
          version,
          content,
          notes: notesInput ? notesInput.value : ''
        })
      });

      if (result.success) {
        showToast('Firmware v' + version + ' uploaded');
        await loadFirmware();
        hideModal();
        render();
      } else {
        showToast(result.error || 'Upload failed', 'error');
      }
    }

    async function deployFirmware(e) {
      e.preventDefault();
      const checkboxes = document.querySelectorAll('.deploy-device-cb:checked');
      const deviceIds = Array.from(checkboxes).map(cb => cb.value);

      if (deviceIds.length === 0) {
        showToast('Select at least one device', 'error');
        return;
      }

      const result = await api('/api/firmware/deploy', {
        method: 'POST',
        body: JSON.stringify({ device_ids: deviceIds })
      });

      if (result.success) {
        const queued = result.results.filter(r => r.status === 'queued').length;
        showToast('Firmware queued for ' + queued + ' device(s)');
        hideModal();
        await loadDevices();
      } else {
        showToast(result.error || 'Deploy failed', 'error');
      }
    }

    async function requestConfig(deviceId) {
      const result = await api('/api/config/' + deviceId + '/request', { method: 'POST' });
      if (result.success) {
        showToast('Config refresh requested');
      } else {
        showToast(result.error || 'Request failed', 'error');
      }
    }

    // Render
    function render() {
      const app = document.getElementById('app');
      if (!state.token || !state.user) {
        app.innerHTML = renderLogin();
      } else {
        app.innerHTML = renderApp();
      }
    }

    function renderLogin() {
      const b = state.branding;
      const loginLogoSrc = b.logoData ? 'data:' + (b.logoMime || 'image/png') + ';base64,' + b.logoData : b.logoUrl;
      return \`
        <div class="login-container">
          <div class="login-card">
            \${loginLogoSrc
              ? '<img src="' + loginLogoSrc + '" class="login-logo" alt="Logo">'
              : '<div class="login-logo-placeholder">📺</div>'
            }
            <h1 class="login-title">\${b.companyName}</h1>
            <p class="login-subtitle">Cloud Device Management</p>
            <button class="google-btn" onclick="login()">
              <svg width="20" height="20" viewBox="0 0 24 24"><path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"/><path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/><path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"/><path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"/></svg>
              Sign in with Google
            </button>
          </div>
        </div>
      \`;
    }

    function renderApp() {
      const b = state.branding;
      return \`
        <div class="app">
          <div class="sidebar-overlay \${state.sidebarOpen ? 'open' : ''}" onclick="toggleSidebar()"></div>

          <aside class="sidebar \${state.sidebarOpen ? 'open' : ''}">
            <div class="sidebar-header">
              \${b.logoData
                ? '<img src="data:' + (b.logoMime || 'image/png') + ';base64,' + b.logoData + '" class="sidebar-logo" alt="Logo">'
                : (b.logoUrl ? '<img src="' + b.logoUrl + '" class="sidebar-logo" alt="Logo">' : '<div class="sidebar-logo-placeholder">📺</div>')
              }
              <span class="sidebar-title">\${b.companyName}</span>
            </div>
            <nav class="sidebar-nav">
              <div class="nav-item \${state.currentPage === 'devices' ? 'active' : ''}" onclick="setPage('devices')">
                <span class="nav-item-icon">📱</span> Devices
              </div>
              <div class="nav-item \${state.currentPage === 'widgets' ? 'active' : ''}" onclick="setPage('widgets')">
                <span class="nav-item-icon">🧩</span> Widgets
              </div>
              <div class="nav-item \${state.currentPage === 'metrics' ? 'active' : ''}" onclick="setPage('metrics')">
                <span class="nav-item-icon">📊</span> Metrics
              </div>
              <div class="nav-item \${state.currentPage === 'firmware' ? 'active' : ''}" onclick="setPage('firmware')">
                <span class="nav-item-icon">📦</span> Firmware
              </div>
              <div class="nav-item \${state.currentPage === 'settings' ? 'active' : ''}" onclick="setPage('settings')">
                <span class="nav-item-icon">⚙️</span> Settings
              </div>
            </nav>
            <div class="sidebar-footer">
              <div class="user-card">
                <img src="\${state.user.picture}" class="user-avatar" alt="Avatar">
                <div class="user-info">
                  <div class="user-name">\${state.user.name}</div>
                  <div class="user-email">\${state.user.email}</div>
                </div>
                <button class="btn btn-ghost btn-icon" onclick="logout()" title="Logout">🚪</button>
              </div>
            </div>
          </aside>

          <header class="mobile-header">
            <button class="menu-btn" onclick="toggleSidebar()">☰</button>
            <span style="font-weight:600;">\${b.companyName}</span>
          </header>

          <main class="main-content">
            \${state.currentPage === 'devices' ? renderDevicesPage() : ''}
            \${state.currentPage === 'widgets' ? renderWidgetsPage() : ''}
            \${state.currentPage === 'metrics' ? renderMetricsPage() : ''}
            \${state.currentPage === 'firmware' ? renderFirmwarePage() : ''}
            \${state.currentPage === 'settings' ? renderSettingsPage() : ''}
          </main>

          \${state.modal ? renderModal() : ''}
        </div>
      \`;
    }

    function renderDevicesPage() {
      const online = state.devices.filter(d => d.status === 'online').length;
      const offline = state.devices.length - online;

      return \`
        <div class="page-header">
          <div>
            <h1 class="page-title">Devices</h1>
            <p class="page-subtitle">Manage your Multi-Frames installations</p>
          </div>
          <button class="btn btn-primary" onclick="showModal('addDevice')">
            <span>+</span> Add Device
          </button>
        </div>

        <div class="stats-grid">
          <div class="stat-card">
            <div class="stat-icon" style="background:var(--primary)20;color:var(--primary);">📱</div>
            <div class="stat-value">\${state.devices.length}</div>
            <div class="stat-label">Total Devices</div>
          </div>
          <div class="stat-card">
            <div class="stat-icon" style="background:var(--success)20;color:var(--success);">✓</div>
            <div class="stat-value">\${online}</div>
            <div class="stat-label">Online</div>
          </div>
          <div class="stat-card">
            <div class="stat-icon" style="background:var(--error)20;color:var(--error);">○</div>
            <div class="stat-value">\${offline}</div>
            <div class="stat-label">Offline</div>
          </div>
        </div>

        \${state.devices.length === 0 ? \`
          <div class="empty-state">
            <div class="empty-state-icon">📱</div>
            <h3>No devices yet</h3>
            <p>Register your first Multi-Frames device to get started</p>
            <button class="btn btn-primary" onclick="showModal('addDevice')">+ Add Device</button>
          </div>
        \` : \`
          <div class="devices-grid">
            \${state.devices.map(renderDeviceCard).join('')}
          </div>
        \`}
      \`;
    }

    function renderDeviceCard(device) {
      const isOnline = device.status === 'online';
      const lastSeen = new Date(device.last_seen).toLocaleString();

      return \`
        <div class="device-card">
          <div class="device-header">
            <div class="device-name">
              <span>\${device.name}</span>
            </div>
            <div class="device-status \${isOnline ? 'status-online' : 'status-offline'}">
              <span class="status-dot"></span>
              \${isOnline ? 'Online' : 'Offline'}
            </div>
          </div>

          <div class="device-info">
            <div class="device-info-row">🖥️ <span>\${device.hostname}</span></div>
            <div class="device-info-row">🌐 <span>\${device.ip_address}</span></div>
            <div class="device-info-row">📦 <span>v\${device.version}\${device.firmware_pending ? ' ⬆️ Update pending' : ''}</span></div>
            <div class="device-info-row">🕐 <span>\${lastSeen}</span></div>
          </div>

          \${isOnline ? \`
            <div class="device-stats">
              <div class="device-stat">
                <div class="device-stat-value">\${device.uptime || '-'}</div>
                <div class="device-stat-label">Uptime</div>
              </div>
              <div class="device-stat">
                <div class="device-stat-value">\${device.memory_used || '-'}</div>
                <div class="device-stat-label">Memory</div>
              </div>
              <div class="device-stat">
                <div class="device-stat-value">\${device.cpu_temp ? device.cpu_temp + '°' : '-'}</div>
                <div class="device-stat-label">Temp</div>
              </div>
            </div>
          \` : ''}

          <div class="device-actions">
            <button class="btn btn-secondary btn-sm" onclick="viewConfig('\${device.id}')">⚙️ Config</button>
            <button class="btn btn-secondary btn-sm" onclick="requestConfig('\${device.id}')" title="Request device to sync its current config">🔄 Refresh</button>
            <button class="btn btn-danger btn-sm" onclick="deleteDevice('\${device.id}')">🗑️ Remove</button>
          </div>
        </div>
      \`;
    }

    function renderFirmwarePage() {
      const fw = state.firmware;
      const onlineDevices = state.devices.filter(d => d.status === 'online');

      return \`
        <div class="page-header">
          <div>
            <h1 class="page-title">Firmware</h1>
            <p class="page-subtitle">Upload and deploy firmware updates to your devices</p>
          </div>
          <button class="btn btn-primary" onclick="showModal('uploadFirmware')">
            <span>⬆️</span> Upload Firmware
          </button>
        </div>

        <div class="stats-grid">
          <div class="stat-card">
            <div class="stat-icon" style="background:var(--primary)20;color:var(--primary);">📦</div>
            <div class="stat-value">\${fw ? 'v' + fw.version : 'None'}</div>
            <div class="stat-label">Latest Firmware</div>
          </div>
          <div class="stat-card">
            <div class="stat-icon" style="background:var(--accent)20;color:var(--accent);">📏</div>
            <div class="stat-value">\${fw ? (fw.size / 1024).toFixed(0) + ' KB' : '-'}</div>
            <div class="stat-label">File Size</div>
          </div>
          <div class="stat-card">
            <div class="stat-icon" style="background:var(--success)20;color:var(--success);">📱</div>
            <div class="stat-value">\${state.devices.filter(d => fw && d.version === fw.version).length}/\${state.devices.length}</div>
            <div class="stat-label">Up to Date</div>
          </div>
        </div>

        \${fw ? \`
          <div class="settings-section">
            <h3 class="settings-section-title">📋 Current Firmware</h3>
            <div class="device-info">
              <div class="device-info-row">📦 Version: <span>v\${fw.version}</span></div>
              <div class="device-info-row">👤 Uploaded by: <span>\${fw.uploaded_by}</span></div>
              <div class="device-info-row">🕐 Uploaded: <span>\${new Date(fw.uploaded_at).toLocaleString()}</span></div>
              \${fw.notes ? '<div class="device-info-row">📝 Notes: <span>' + fw.notes + '</span></div>' : ''}
            </div>
            <button class="btn btn-primary" onclick="showModal('deployFirmware')">🚀 Deploy to Devices</button>
          </div>
        \` : \`
          <div class="empty-state">
            <div class="empty-state-icon">📦</div>
            <h3>No firmware uploaded</h3>
            <p>Upload a firmware file to deploy it to your devices</p>
            <button class="btn btn-primary" onclick="showModal('uploadFirmware')">⬆️ Upload Firmware</button>
          </div>
        \`}

        \${fw && state.devices.length > 0 ? \`
          <div class="settings-section" style="margin-top:1.5rem;">
            <h3 class="settings-section-title">📱 Device Firmware Status</h3>
            <table style="width:100%;border-collapse:collapse;">
              <thead>
                <tr style="border-bottom:1px solid var(--border);">
                  <th style="text-align:left;padding:0.75rem 0.5rem;color:var(--text-secondary);font-size:0.85rem;">Device</th>
                  <th style="text-align:left;padding:0.75rem 0.5rem;color:var(--text-secondary);font-size:0.85rem;">Current Version</th>
                  <th style="text-align:left;padding:0.75rem 0.5rem;color:var(--text-secondary);font-size:0.85rem;">Status</th>
                  <th style="text-align:center;padding:0.75rem 0.5rem;color:var(--text-secondary);font-size:0.85rem;">Update</th>
                </tr>
              </thead>
              <tbody>
                \${state.devices.map(d => {
                  const isCurrent = d.version === fw.version;
                  const isPending = d.firmware_pending;
                  let statusBadge;
                  if (isCurrent) {
                    statusBadge = '<span style="color:var(--success);font-size:0.85rem;">✓ Up to date</span>';
                  } else if (isPending) {
                    statusBadge = '<span style="color:var(--warning);font-size:0.85rem;">⏳ Pending</span>';
                  } else {
                    statusBadge = '<span style="color:var(--text-muted);font-size:0.85rem;">⬆ Update available</span>';
                  }
                  return '<tr style="border-bottom:1px solid var(--border);">' +
                    '<td style="padding:0.75rem 0.5rem;font-weight:500;">' + d.name + '</td>' +
                    '<td style="padding:0.75rem 0.5rem;">v' + d.version + '</td>' +
                    '<td style="padding:0.75rem 0.5rem;">' + statusBadge + '</td>' +
                    '<td style="padding:0.75rem 0.5rem;text-align:center;">' +
                      (isCurrent ? '-' : '<button class=\\"btn btn-secondary btn-sm\\" onclick=\\"deploySingleDevice(\\'' + d.id + '\\')\\">Deploy</button>') +
                    '</td></tr>';
                }).join('')}
              </tbody>
            </table>
          </div>
        \` : ''}
      \`;
    }

    async function deploySingleDevice(deviceId) {
      const result = await api('/api/firmware/deploy', {
        method: 'POST',
        body: JSON.stringify({ device_ids: [deviceId] })
      });
      if (result.success) {
        showToast('Firmware queued for deployment');
        await loadDevices();
      } else {
        showToast(result.error || 'Deploy failed', 'error');
      }
    }

    function renderSettingsPage() {
      const b = state.branding;
      const tab = state.settingsTab || 'branding';
      const hasLogoUploaded = !!(b.logoData || state.pendingUploads.logoData);
      const hasFaviconUploaded = !!(b.faviconData || state.pendingUploads.faviconData);
      const hasAppleIconUploaded = !!(b.appleTouchIconData || state.pendingUploads.appleTouchIconData);
      const hasAndroidIconUploaded = !!(b.androidIconData || state.pendingUploads.androidIconData);

      return \`
        <div class="page-header">
          <div>
            <h1 class="page-title">Settings</h1>
            <p class="page-subtitle">Customize your cloud portal appearance and branding</p>
          </div>
        </div>

        <div class="tab-bar">
          <div class="tab-item \${tab === 'branding' ? 'active' : ''}" onclick="state.settingsTab='branding';render()">Branding</div>
          <div class="tab-item \${tab === 'icons' ? 'active' : ''}" onclick="state.settingsTab='icons';render()">App Icons</div>
          <div class="tab-item \${tab === 'colors' ? 'active' : ''}" onclick="state.settingsTab='colors';render()">Colors & Theme</div>
        </div>

        <form onsubmit="saveBranding(event)">
          \${tab === 'branding' ? \`
            <div class="settings-section">
              <h3 class="settings-section-title">Company Identity</h3>

              <div class="form-group">
                <label class="form-label">Company Name</label>
                <input type="text" name="companyName" class="form-input" value="\${b.companyName}" placeholder="Your Company">
              </div>

              <div class="form-group">
                <label class="form-label">Logo Upload</label>
                <p class="form-hint" style="margin-bottom:0.5rem;">Recommended: 200x200px or larger, PNG or SVG. Displayed in sidebar and login page.</p>
                \${hasLogoUploaded ? \`
                  <div class="upload-preview">
                    <img src="\${state.pendingUploads.logoData ? 'data:' + (state.pendingUploads.logoMime||'image/png') + ';base64,' + state.pendingUploads.logoData : 'data:' + (b.logoMime||'image/png') + ';base64,' + b.logoData}" alt="Logo">
                    <div class="upload-preview-info">
                      <div class="upload-preview-name">Current Logo</div>
                      <div class="upload-preview-size">Uploaded</div>
                    </div>
                    <button type="button" class="btn btn-ghost btn-sm" onclick="clearBrandingAsset('logo')">Remove</button>
                  </div>
                \` : ''}
                <div class="upload-zone" onclick="document.getElementById('logoUpload').click()" id="logoZone">
                  <div class="upload-zone-icon">🖼️</div>
                  <div class="upload-zone-text">\${hasLogoUploaded ? 'Replace logo' : 'Click to upload logo'}</div>
                  <div class="upload-zone-hint">PNG, JPG, SVG - Max 2MB</div>
                </div>
                <input type="file" id="logoUpload" accept="image/*" style="display:none" onchange="handleFileUpload('logoUpload','logo',2097152,'logoPreview')">
                <div id="logoPreview"></div>
              </div>

              <div class="form-group">
                <label class="form-label">Logo URL (alternative)</label>
                <input type="url" name="logoUrl" class="form-input" value="\${b.logoUrl || ''}" placeholder="https://example.com/logo.png">
                <p class="form-hint">If no file is uploaded, this URL will be used as fallback</p>
              </div>
            </div>
          \` : ''}

          \${tab === 'icons' ? \`
            <div class="settings-section">
              <h3 class="settings-section-title">Favicon</h3>
              <p class="form-hint" style="margin-bottom:0.75rem;">Browser tab icon. Recommended: 32x32px or 64x64px ICO/PNG.</p>
              \${hasFaviconUploaded ? \`
                <div class="upload-preview">
                  <img src="\${state.pendingUploads.faviconData ? 'data:' + (state.pendingUploads.faviconMime||'image/png') + ';base64,' + state.pendingUploads.faviconData : 'data:' + (b.faviconMime||'image/x-icon') + ';base64,' + b.faviconData}" alt="Favicon">
                  <div class="upload-preview-info">
                    <div class="upload-preview-name">Current Favicon</div>
                  </div>
                  <button type="button" class="btn btn-ghost btn-sm" onclick="clearBrandingAsset('favicon')">Remove</button>
                </div>
              \` : ''}
              <div class="upload-zone" onclick="document.getElementById('faviconUpload').click()">
                <div class="upload-zone-icon">🔖</div>
                <div class="upload-zone-text">\${hasFaviconUploaded ? 'Replace favicon' : 'Click to upload favicon'}</div>
                <div class="upload-zone-hint">ICO, PNG - Max 512KB</div>
              </div>
              <input type="file" id="faviconUpload" accept="image/*,.ico" style="display:none" onchange="handleFileUpload('faviconUpload','favicon',524288,'faviconPreview')">
              <div id="faviconPreview"></div>
            </div>

            <div class="settings-section">
              <h3 class="settings-section-title">iOS Home Screen Icon</h3>
              <p class="form-hint" style="margin-bottom:0.75rem;">Apple Touch Icon for "Add to Home Screen" on iOS. Recommended: 180x180px PNG.</p>
              \${hasAppleIconUploaded ? \`
                <div class="upload-preview">
                  <img src="\${state.pendingUploads.appleTouchIconData ? 'data:' + (state.pendingUploads.appleTouchIconMime||'image/png') + ';base64,' + state.pendingUploads.appleTouchIconData : 'data:' + (b.appleTouchIconMime||'image/png') + ';base64,' + b.appleTouchIconData}" alt="Apple Icon">
                  <div class="upload-preview-info">
                    <div class="upload-preview-name">iOS Icon (180x180)</div>
                  </div>
                  <button type="button" class="btn btn-ghost btn-sm" onclick="clearBrandingAsset('appleTouchIcon')">Remove</button>
                </div>
              \` : ''}
              <div class="upload-zone" onclick="document.getElementById('appleIconUpload').click()">
                <div class="upload-zone-icon">🍎</div>
                <div class="upload-zone-text">\${hasAppleIconUploaded ? 'Replace iOS icon' : 'Click to upload iOS icon'}</div>
                <div class="upload-zone-hint">PNG 180x180px - Max 512KB</div>
              </div>
              <input type="file" id="appleIconUpload" accept="image/png" style="display:none" onchange="handleFileUpload('appleIconUpload','appleTouchIcon',524288,'appleIconPreview')">
              <div id="appleIconPreview"></div>
            </div>

            <div class="settings-section">
              <h3 class="settings-section-title">Android Home Screen Icon</h3>
              <p class="form-hint" style="margin-bottom:0.75rem;">Icon for "Add to Home Screen" on Android. Recommended: 192x192px PNG. Also generates a Web App Manifest.</p>
              \${hasAndroidIconUploaded ? \`
                <div class="upload-preview">
                  <img src="\${state.pendingUploads.androidIconData ? 'data:' + (state.pendingUploads.androidIconMime||'image/png') + ';base64,' + state.pendingUploads.androidIconData : 'data:' + (b.androidIconMime||'image/png') + ';base64,' + b.androidIconData}" alt="Android Icon">
                  <div class="upload-preview-info">
                    <div class="upload-preview-name">Android Icon (192x192)</div>
                  </div>
                  <button type="button" class="btn btn-ghost btn-sm" onclick="clearBrandingAsset('androidIcon')">Remove</button>
                </div>
              \` : ''}
              <div class="upload-zone" onclick="document.getElementById('androidIconUpload').click()">
                <div class="upload-zone-icon">🤖</div>
                <div class="upload-zone-text">\${hasAndroidIconUploaded ? 'Replace Android icon' : 'Click to upload Android icon'}</div>
                <div class="upload-zone-hint">PNG 192x192px - Max 512KB</div>
              </div>
              <input type="file" id="androidIconUpload" accept="image/png" style="display:none" onchange="handleFileUpload('androidIconUpload','androidIcon',524288,'androidIconPreview')">
              <div id="androidIconPreview"></div>
            </div>
          \` : ''}

          \${tab === 'colors' ? \`
            <div class="settings-section">
              <h3 class="settings-section-title">Theme Colors</h3>

              <div class="form-row">
                <div class="form-group">
                  <label class="form-label">Primary Color</label>
                  <div class="color-input-wrapper">
                    <label class="color-preview" style="background:\${b.primaryColor}" onclick="this.querySelector('input').click()">
                      <input type="color" name="primaryColor" class="color-input" value="\${b.primaryColor}" onchange="this.parentElement.style.background=this.value">
                    </label>
                    <span>\${b.primaryColor}</span>
                  </div>
                  <p class="form-hint">Buttons, links, active states</p>
                </div>
                <div class="form-group">
                  <label class="form-label">Accent Color</label>
                  <div class="color-input-wrapper">
                    <label class="color-preview" style="background:\${b.accentColor}" onclick="this.querySelector('input').click()">
                      <input type="color" name="accentColor" class="color-input" value="\${b.accentColor}" onchange="this.parentElement.style.background=this.value">
                    </label>
                    <span>\${b.accentColor}</span>
                  </div>
                  <p class="form-hint">Gradients, secondary highlights</p>
                </div>
              </div>

              <div class="form-group">
                <label style="display:flex;align-items:center;gap:0.75rem;cursor:pointer;">
                  <input type="checkbox" name="darkMode" \${b.darkMode ? 'checked' : ''} style="width:18px;height:18px;">
                  <div>
                    <div style="font-weight:500;">Dark Mode</div>
                    <div style="font-size:0.8rem;color:var(--text-muted);">Use dark backgrounds with light text</div>
                  </div>
                </label>
              </div>
            </div>
          \` : ''}

          <button type="submit" class="btn btn-primary" style="margin-top:0.5rem;">Save Changes</button>
        </form>
      \`;
    }

    function renderWidgetsPage() {
      const widgetTypes = {clock:'🕐',date:'📅',weather:'🌤️',countdown:'⏱️',text:'📝',image:'🖼️',notes:'📋',buttons:'🎮'};

      return \`
        <div class="page-header">
          <div>
            <h1 class="page-title">Widget Templates</h1>
            <p class="page-subtitle">Create widget templates and push them to devices</p>
          </div>
          <button class="btn btn-primary" onclick="showModal('createWidget')">+ Create Template</button>
        </div>

        <div class="stats-grid">
          <div class="stat-card">
            <div class="stat-icon" style="background:var(--primary)20;color:var(--primary);">🧩</div>
            <div class="stat-value">\${state.widgetTemplates.length}</div>
            <div class="stat-label">Templates</div>
          </div>
          <div class="stat-card">
            <div class="stat-icon" style="background:var(--accent)20;color:var(--accent);">📱</div>
            <div class="stat-value">\${state.devices.length}</div>
            <div class="stat-label">Devices</div>
          </div>
        </div>

        \${state.widgetTemplates.length === 0 ? \`
          <div class="empty-state">
            <div class="empty-state-icon">🧩</div>
            <h3>No widget templates</h3>
            <p>Create widget templates to quickly push standardized widgets to your devices</p>
            <button class="btn btn-primary" onclick="showModal('createWidget')">+ Create Template</button>
          </div>
        \` : \`
          <div class="widget-tmpl-grid">
            \${state.widgetTemplates.map(t => \`
              <div class="widget-tmpl-card">
                <div class="widget-tmpl-type">\${widgetTypes[t.type] || '📦'} \${t.type}</div>
                <div class="widget-tmpl-name">\${t.name}</div>
                <div class="widget-tmpl-preview" style="background:\${t.bg_color};color:\${t.text_color};border-radius:\${t.border_radius}px;">
                  \${widgetTypes[t.type] || '📦'}
                </div>
                <div style="font-size:0.75rem;color:var(--text-muted);margin-bottom:0.75rem;">
                  Size: \${t.size} · Created by \${t.created_by || 'unknown'}
                </div>
                <div class="widget-tmpl-actions">
                  <button class="btn btn-primary btn-sm" onclick="pushWidgetToDevices('\${t.id}')">Push to Devices</button>
                  <button class="btn btn-danger btn-sm" onclick="deleteWidgetTemplate('\${t.id}')">Delete</button>
                </div>
              </div>
            \`).join('')}
          </div>
        \`}
      \`;
    }

    function renderMetricsPage() {
      const cacheKey = state.metricsDevice + ':' + state.metricsRange + ':' + state.metricsMetric;
      const data = state.metricsCache[cacheKey] || [];
      const metricLabels = {cpu_temp:'CPU Temp',memory_pct:'Memory %',cpu_usage:'CPU Usage',hours_online:'Hours Online'};
      const metricUnits = {cpu_temp:'°C',memory_pct:'%',cpu_usage:'%',hours_online:'hrs'};

      return \`
        <div class="page-header">
          <div>
            <h1 class="page-title">Device Metrics</h1>
            <p class="page-subtitle">Historical data logging and device performance history</p>
          </div>
        </div>

        <div class="settings-section" style="margin-bottom:1.5rem;">
          <h3 class="settings-section-title">Select Device</h3>
          <div style="display:flex;flex-wrap:wrap;gap:0.5rem;">
            \${state.devices.length === 0 ? '<p style="color:var(--text-muted);">No devices registered</p>' :
              state.devices.map(d => \`
                <button class="btn \${state.metricsDevice === d.id ? 'btn-primary' : 'btn-secondary'} btn-sm" onclick="selectMetricsDevice('\${d.id}')">
                  \${d.name} \${d.status === 'online' ? '🟢' : '🔴'}
                </button>
              \`).join('')}
          </div>
        </div>

        \${state.metricsDevice ? \`
          <div class="metric-grid">
            \${['cpu_temp','memory_pct','cpu_usage','hours_online'].map(m => {
              const latest = data.length > 0 ? data[data.length - 1] : null;
              const val = latest ? latest.value : '-';
              return '<div class="metric-card' + (state.metricsMetric === m ? ' style=\\"border-color:var(--primary);\\"' : '') + '" onclick="setMetricsMetric(\\'' + m + '\\')" style="cursor:pointer;' + (state.metricsMetric === m ? 'border-color:var(--primary);' : '') + '">' +
                '<div class="metric-value">' + (m === state.metricsMetric && val !== '-' ? val + (metricUnits[m] || '') : '-') + '</div>' +
                '<div class="metric-label">' + metricLabels[m] + '</div></div>';
            }).join('')}
          </div>

          <div class="chart-container">
            <div class="chart-header">
              <div class="chart-title">\${metricLabels[state.metricsMetric] || state.metricsMetric} History</div>
              <div class="chart-controls">
                <button class="\${state.metricsRange === '24h' ? 'active' : ''}" onclick="setMetricsRange('24h')">24h</button>
                <button class="\${state.metricsRange === '7d' ? 'active' : ''}" onclick="setMetricsRange('7d')">7d</button>
                <button class="\${state.metricsRange === '30d' ? 'active' : ''}" onclick="setMetricsRange('30d')">30d</button>
              </div>
            </div>
            \${data.length === 0 ? '<div class="chart-empty">No metrics data yet. Devices report metrics automatically during heartbeats.</div>' : renderChart(data, state.metricsMetric)}
          </div>
        \` : \`
          <div class="empty-state">
            <div class="empty-state-icon">📊</div>
            <h3>Select a device</h3>
            <p>Choose a device above to view its historical metrics and performance data</p>
          </div>
        \`}
      \`;
    }

    function renderChart(data, metric) {
      if (!data || data.length === 0) return '<div class="chart-empty">No data</div>';

      const values = data.map(d => d.value);
      const max = Math.max(...values) * 1.15 || 1;
      const min = Math.min(0, ...values);
      const range = max - min || 1;
      const w = 800, h = 180, pad = 40;
      const stepX = (w - pad * 2) / Math.max(data.length - 1, 1);

      const points = data.map((d, i) => {
        const x = pad + i * stepX;
        const y = h - pad - ((d.value - min) / range) * (h - pad * 2);
        return x + ',' + y;
      }).join(' ');

      const area = pad + ',' + (h - pad) + ' ' + points + ' ' + (pad + (data.length - 1) * stepX) + ',' + (h - pad);

      // Axis labels
      const yLabels = [0, 1, 2, 3].map(i => {
        const val = min + (range * (3 - i) / 3);
        const y = pad + i * ((h - pad * 2) / 3);
        return '<text x="' + (pad - 8) + '" y="' + (y + 4) + '" text-anchor="end" fill="var(--text-muted)" font-size="10">' + Math.round(val) + '</text>' +
               '<line x1="' + pad + '" y1="' + y + '" x2="' + (w - pad) + '" y2="' + y + '" stroke="var(--border)" stroke-dasharray="4" />';
      }).join('');

      const xLabels = data.filter((_, i) => data.length <= 10 || i % Math.ceil(data.length / 8) === 0).map((d, i, arr) => {
        const idx = data.indexOf(d);
        const x = pad + idx * stepX;
        const label = d.timestamp.length > 10 ? d.timestamp.substring(11, 16) : d.timestamp.substring(5, 10);
        return '<text x="' + x + '" y="' + (h - 8) + '" text-anchor="middle" fill="var(--text-muted)" font-size="10">' + label + '</text>';
      }).join('');

      return '<svg class="chart-svg" viewBox="0 0 ' + w + ' ' + h + '" preserveAspectRatio="none">' +
        yLabels + xLabels +
        '<polygon points="' + area + '" fill="var(--primary)" opacity="0.1" />' +
        '<polyline points="' + points + '" fill="none" stroke="var(--primary)" stroke-width="2" stroke-linejoin="round" />' +
        data.map((d, i) => {
          const x = pad + i * stepX;
          const y = h - pad - ((d.value - min) / range) * (h - pad * 2);
          return '<circle cx="' + x + '" cy="' + y + '" r="3" fill="var(--primary)" />';
        }).join('') +
        '</svg>';
    }

    function renderModal() {
      const m = state.modal;
      let content = '';

      if (m.type === 'addDevice') {
        content = \`
          <div class="modal-header">
            <h2 class="modal-title">Add Device</h2>
            <button class="modal-close" onclick="hideModal()">&times;</button>
          </div>
          <form onsubmit="registerDevice(event)">
            <div class="modal-body">
              <div class="form-group">
                <label class="form-label">Device Name</label>
                <input type="text" name="name" class="form-input" placeholder="e.g., Kitchen Display" required autofocus>
                <p class="form-hint">A friendly name to identify this device</p>
              </div>
            </div>
            <div class="modal-footer">
              <button type="button" class="btn btn-secondary" onclick="hideModal()">Cancel</button>
              <button type="submit" class="btn btn-primary">Register Device</button>
            </div>
          </form>
        \`;
      } else if (m.type === 'deviceKey') {
        content = \`
          <div class="modal-header">
            <h2 class="modal-title">Device Registered!</h2>
            <button class="modal-close" onclick="hideModal()">&times;</button>
          </div>
          <div class="modal-body">
            <div class="success-badge">✓ Device registered successfully</div>
            <p style="margin-bottom:1rem;color:var(--text-secondary);">Add this key to your Multi-Frames config:</p>
            <div class="copy-box">
              \${m.data.device_key}
              <button class="btn btn-secondary btn-sm copy-btn" onclick="navigator.clipboard.writeText('\${m.data.device_key}');showToast('Copied!')">📋 Copy</button>
            </div>
            <p style="color:var(--warning);font-size:0.85rem;margin-top:1rem;">⚠️ Save this key now - it won't be shown again!</p>
          </div>
          <div class="modal-footer">
            <button class="btn btn-primary" onclick="hideModal()">Done</button>
          </div>
        \`;
      } else if (m.type === 'viewConfig') {
        const configStr = m.data.config ? JSON.stringify(m.data.config, null, 2) : '// No config synced yet';
        content = \`
          <div class="modal-header">
            <h2 class="modal-title">Device Configuration</h2>
            <button class="modal-close" onclick="hideModal()">&times;</button>
          </div>
          <div class="modal-body">
            <p style="color:var(--text-secondary);margin-bottom:1rem;">Version: \${m.data.version}</p>
            <div class="form-group">
              <textarea id="configEditor" class="form-textarea">\${configStr}</textarea>
            </div>
          </div>
          <div class="modal-footer">
            <button class="btn btn-secondary" onclick="hideModal()">Cancel</button>
            <button class="btn btn-secondary" onclick="requestConfig('\${m.data.deviceId}')" title="Ask device to push its current config">🔄 Refresh from Device</button>
            <button class="btn btn-primary" onclick="pushConfig('\${m.data.deviceId}', document.getElementById('configEditor').value)">Push to Device</button>
          </div>
        \`;
      } else if (m.type === 'uploadFirmware') {
        content = \`
          <div class="modal-header">
            <h2 class="modal-title">Upload Firmware</h2>
            <button class="modal-close" onclick="hideModal()">&times;</button>
          </div>
          <form onsubmit="uploadFirmware(event)">
            <div class="modal-body">
              <div class="form-group">
                <label class="form-label">Firmware File (.py)</label>
                <input type="file" id="firmwareFile" accept=".py" required class="form-input" style="padding:0.5rem;">
                <p class="form-hint">Select the multi_frames.py firmware file to upload</p>
              </div>
              <div class="form-group">
                <label class="form-label">Release Notes (optional)</label>
                <textarea id="firmwareNotes" class="form-input" rows="3" placeholder="What changed in this version..."></textarea>
              </div>
            </div>
            <div class="modal-footer">
              <button type="button" class="btn btn-secondary" onclick="hideModal()">Cancel</button>
              <button type="submit" class="btn btn-primary">⬆️ Upload</button>
            </div>
          </form>
        \`;
      } else if (m.type === 'createWidget') {
        content = \`
          <div class="modal-header">
            <h2 class="modal-title">Create Widget Template</h2>
            <button class="modal-close" onclick="hideModal()">&times;</button>
          </div>
          <form onsubmit="createWidgetTemplate(event)">
            <div class="modal-body">
              <div class="form-group">
                <label class="form-label">Widget Name</label>
                <input type="text" name="widgetName" class="form-input" placeholder="e.g., Office Clock" required autofocus>
              </div>
              <div class="form-group">
                <label class="form-label">Widget Type</label>
                <select name="widgetType" class="form-select">
                  <option value="clock">🕐 Clock</option>
                  <option value="date">📅 Date</option>
                  <option value="weather">🌤️ Weather</option>
                  <option value="countdown">⏱️ Countdown</option>
                  <option value="text">📝 Text/HTML</option>
                  <option value="image">🖼️ Image</option>
                  <option value="notes">📋 Notes</option>
                  <option value="buttons">🎮 Command Buttons</option>
                </select>
              </div>
              <div class="form-group">
                <label class="form-label">Size</label>
                <select name="widgetSize" class="form-select">
                  <option value="small">Small</option>
                  <option value="medium" selected>Medium</option>
                  <option value="large">Large</option>
                </select>
              </div>
              <div class="form-row">
                <div class="form-group">
                  <label class="form-label">Background Color</label>
                  <input type="color" name="widgetBg" value="#141416" class="form-input" style="height:44px;padding:4px;">
                </div>
                <div class="form-group">
                  <label class="form-label">Text Color</label>
                  <input type="color" name="widgetText" value="#e8e8e8" class="form-input" style="height:44px;padding:4px;">
                </div>
              </div>
              <div class="form-group">
                <label class="form-label">Border Radius (px)</label>
                <input type="number" name="widgetRadius" value="8" min="0" max="24" class="form-input">
              </div>
              <div class="form-group">
                <label class="form-label">Configuration (JSON)</label>
                <textarea name="widgetConfig" class="form-textarea" style="min-height:100px;" placeholder='{"format":"24h"}'>{}</textarea>
                <p class="form-hint">Type-specific config. E.g., clock: {"format":"24h"}, weather: {"latitude":30.2,"longitude":-97.7}</p>
              </div>
            </div>
            <div class="modal-footer">
              <button type="button" class="btn btn-secondary" onclick="hideModal()">Cancel</button>
              <button type="submit" class="btn btn-primary">Create Template</button>
            </div>
          </form>
        \`;
      } else if (m.type === 'pushWidget') {
        content = \`
          <div class="modal-header">
            <h2 class="modal-title">Push Widget to Devices</h2>
            <button class="modal-close" onclick="hideModal()">&times;</button>
          </div>
          <form onsubmit="doPushWidget(event)">
            <div class="modal-body">
              \${state.devices.length === 0 ? \`
                <p style="color:var(--text-secondary);">No devices registered.</p>
              \` : \`
                <p style="color:var(--text-secondary);margin-bottom:1rem;">Select devices to receive this widget:</p>
                <div style="display:flex;flex-direction:column;gap:0.5rem;">
                  \${state.devices.map(d => \`
                    <label style="display:flex;align-items:center;gap:0.75rem;padding:0.75rem;background:var(--bg-tertiary);border-radius:10px;cursor:pointer;">
                      <input type="checkbox" class="push-widget-cb" value="\${d.id}" checked style="width:18px;height:18px;">
                      <div>
                        <div style="font-weight:500;">\${d.name}</div>
                        <div style="font-size:0.8rem;color:var(--text-muted);">\${d.status === 'online' ? 'Online' : 'Offline'} · v\${d.version}</div>
                      </div>
                    </label>
                  \`).join('')}
                </div>
              \`}
            </div>
            <div class="modal-footer">
              <button type="button" class="btn btn-secondary" onclick="hideModal()">Cancel</button>
              \${state.devices.length > 0 ? '<button type="submit" class="btn btn-primary">Push Widget</button>' : ''}
            </div>
          </form>
        \`;
      } else if (m.type === 'deployFirmware') {
        const fw = state.firmware;
        const eligibleDevices = state.devices.filter(d => d.version !== fw.version);
        content = \`
          <div class="modal-header">
            <h2 class="modal-title">Deploy Firmware v\${fw.version}</h2>
            <button class="modal-close" onclick="hideModal()">&times;</button>
          </div>
          <form onsubmit="deployFirmware(event)">
            <div class="modal-body">
              \${eligibleDevices.length === 0 ? \`
                <p style="color:var(--text-secondary);">All devices are already running v\${fw.version}.</p>
              \` : \`
                <p style="color:var(--text-secondary);margin-bottom:1rem;">Select devices to update to v\${fw.version}:</p>
                <div style="display:flex;flex-direction:column;gap:0.5rem;">
                  \${eligibleDevices.map(d => \`
                    <label style="display:flex;align-items:center;gap:0.75rem;padding:0.75rem;background:var(--bg-tertiary);border-radius:10px;cursor:pointer;">
                      <input type="checkbox" class="deploy-device-cb" value="\${d.id}" checked style="width:18px;height:18px;">
                      <div>
                        <div style="font-weight:500;">\${d.name}</div>
                        <div style="font-size:0.8rem;color:var(--text-muted);">Currently: v\${d.version} \${d.status === 'online' ? '(online)' : '(offline)'}</div>
                      </div>
                    </label>
                  \`).join('')}
                </div>
              \`}
            </div>
            <div class="modal-footer">
              <button type="button" class="btn btn-secondary" onclick="hideModal()">Cancel</button>
              \${eligibleDevices.length > 0 ? '<button type="submit" class="btn btn-primary">🚀 Deploy</button>' : ''}
            </div>
          </form>
        \`;
      }

      return \`
        <div class="modal-overlay" onclick="if(event.target===this)hideModal()">
          <div class="modal">\${content}</div>
        </div>
      \`;
    }

    // Start
    init();
  </script>
</body>
</html>`;
}

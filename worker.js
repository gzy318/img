// Zero Star Host Ultra Backend (修复文件名处理版)
export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const method = request.method;
    const path = url.pathname;

    const corsHeaders = {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    };

    if (method === 'OPTIONS') return new Response(null, { headers: corsHeaders });

    const checkAuth = () => {
      const auth = request.headers.get('Authorization');
      const secret = env.ADMIN_TOKEN || '123456'; 
      return auth === `Bearer ${secret}`;
    };
    
    // 修正时区问题
    const getTodayDate = () => {
        const date = new Date(new Date().getTime() + 8 * 60 * 60 * 1000);
        return date.toISOString().split('T')[0];
    };

    const err = (msg, status = 400) => new Response(JSON.stringify({ error: msg }), { status, headers: { 'Content-Type': 'application/json', ...corsHeaders } });

    async function calculateHash(file) {
      const buffer = await file.arrayBuffer();
      const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
      return Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, '0')).join('');
    }

    // --- API ---

    if (method === 'GET' && path === '/api/stats') {
      try {
        const total = await env.DB.prepare('SELECT count(*) as count, sum(size) as totalSize FROM images').first() || { count: 0, totalSize: 0 };
        const todayStr = getTodayDate();
        const today = await env.DB.prepare('SELECT * FROM daily_stats WHERE date = ?').bind(todayStr).first() || { count: 0, size: 0 };
        const settingsRaw = await env.DB.prepare("SELECT * FROM settings").all();
        const settings = {};
        if(settingsRaw.results) settingsRaw.results.forEach(r => settings[r.key] = r.value);

        return new Response(JSON.stringify({
          total: { count: total.count, size: total.totalSize || 0 },
          today: { count: today.count, size: today.size || 0 },
          limits: { 
              count: parseInt(settings.limit_count || '50'), 
              size: parseInt(settings.limit_size || '50'),
              compress: parseInt(settings.compress_limit || '2')
          },
          announcement: settings.announcement || '',
          maintenance: settings.maintenance_mode === 'true'
        }), { headers: { 'Content-Type': 'application/json', ...corsHeaders } });
      } catch (e) { return err('DB Error: ' + e.message, 500); }
    }

    if (method === 'POST' && path === '/api/upload') {
      const clientIP = request.headers.get('CF-Connecting-IP') || '0.0.0.0';
      const isAdmin = checkAuth();

      const isBlocked = await env.DB.prepare('SELECT 1 FROM blocked_ips WHERE ip = ?').bind(clientIP).first();
      if (isBlocked) return err('Access Denied: IP Blocked', 403);

      const maintMode = await env.DB.prepare("SELECT value FROM settings WHERE key='maintenance_mode'").first('value');
      if (maintMode === 'true' && !isAdmin) return err('Maintenance Mode Active', 503);

      const formData = await request.formData();
      const file = formData.get('file');
      const expireVal = formData.get('expire');
      
      if (!file) return err('No file');
      if (file.size > 20 * 1024 * 1024) return err('Max 20MB', 413);

      if (!isAdmin) {
        const limitCount = parseInt((await env.DB.prepare("SELECT value FROM settings WHERE key='limit_count'").first('value')) || '50');
        const todayStr = getTodayDate();
        const stats = await env.DB.prepare("SELECT * FROM daily_stats WHERE date = ?").bind(todayStr).first() || { count: 0, size: 0 };
        if (limitCount > 0 && stats.count >= limitCount) return err(`Daily limit reached (${limitCount})`, 429);
        
        const limitSize = parseInt((await env.DB.prepare("SELECT value FROM settings WHERE key='limit_size'").first('value')) || '50');
        if (limitSize > 0 && (stats.size + file.size) / 1048576 > limitSize) return err(`Daily size limit reached (${limitSize}MB)`, 429);
      }

      const fileHash = await calculateHash(file);
      const existing = await env.DB.prepare('SELECT url, filename, size FROM images WHERE hash = ? AND (expire_at IS NULL OR expire_at > ?) LIMIT 1')
        .bind(fileHash, Date.now()).first();

      if (existing) {
          return new Response(JSON.stringify({
              success: true, url: existing.url, filename: existing.filename, size: existing.size, deduplicated: true
          }), { headers: { 'Content-Type': 'application/json', ...corsHeaders } });
      }

      let expireAt = null;
      if (expireVal && parseInt(expireVal) > 0) expireAt = Date.now() + parseInt(expireVal) * 3600000;

      const timestamp = Date.now();
      const random = Math.random().toString(36).substring(2, 9);
      
      // 增强的文件名处理：如果前端传来的名字里没有后缀，尝试从类型推断，或者给个默认值
      let originalName = file.name || 'image.jpg';
      if (originalName === 'blob') originalName = 'image.jpg'; // 防止 blob 文件名
      let ext = originalName.split('.').pop();
      if(ext === originalName) ext = 'jpg'; // 如果没有后缀
      
      const newKey = `${timestamp}_${random}.${ext}`;

      await env.MY_BUCKET.put(newKey, file);
      const imageUrl = `${url.origin}/image/${newKey}`;

      try {
        await env.DB.prepare('INSERT INTO images (key, filename, url, size, created_at, ip, expire_at, hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?)')
          .bind(newKey, originalName, imageUrl, file.size, timestamp, clientIP, expireAt, fileHash).run();
        
        const todayStr = getTodayDate();
        await env.DB.prepare(`INSERT INTO daily_stats (date, count, size) VALUES (?, 1, ?) ON CONFLICT(date) DO UPDATE SET count=count+1, size=size+?`)
          .bind(todayStr, file.size, file.size).run();
      } catch (e) { console.error(e); }

      return new Response(JSON.stringify({ success: true, url: imageUrl, filename: originalName, size: file.size, expire_at: expireAt }), { headers: { 'Content-Type': 'application/json', ...corsHeaders } });
    }

    // 图片代理
    if (method === 'GET' && path.startsWith('/image/')) {
        const key = path.replace('/image/', '');
        const imgMeta = await env.DB.prepare('SELECT id, expire_at FROM images WHERE key = ?').bind(key).first();
        if (imgMeta && imgMeta.expire_at && Date.now() > imgMeta.expire_at) {
            ctx.waitUntil(env.MY_BUCKET.delete(key));
            ctx.waitUntil(env.DB.prepare('DELETE FROM images WHERE id = ?').bind(imgMeta.id).run());
            return new Response('Expired', { status: 410, headers: corsHeaders });
        }
        const allowedRaw = await env.DB.prepare("SELECT value FROM settings WHERE key='allowed_referers'").first('value');
        if (allowedRaw && allowedRaw.trim() !== '') {
            const referer = request.headers.get('Referer');
            if (referer && !allowedRaw.split(',').some(d => referer.includes(d.trim()))) {
                return new Response('Hotlink Denied', { status: 403, headers: corsHeaders });
            }
        }
        const object = await env.MY_BUCKET.get(key);
        if (!object) return new Response('Not Found', { status: 404, headers: corsHeaders });
        const headers = new Headers(corsHeaders);
        object.writeHttpMetadata(headers);
        headers.set('etag', object.httpEtag);
        return new Response(object.body, { headers });
    }

    // 管理接口
    if (path.startsWith('/api/admin')) {
        if (!checkAuth()) return err('Unauthorized', 401);

        if (path === '/api/admin/list') {
            const { results } = await env.DB.prepare('SELECT * FROM images ORDER BY created_at DESC LIMIT 200').all();
            return new Response(JSON.stringify(results || []), { headers: { 'Content-Type': 'application/json', ...corsHeaders } });
        }
        if (path === '/api/admin/delete/' && method === 'DELETE') {
            const id = path.split('/').pop();
            const img = await env.DB.prepare('SELECT key FROM images WHERE id = ?').bind(id).first();
            if (img) { await env.MY_BUCKET.delete(img.key); await env.DB.prepare('DELETE FROM images WHERE id = ?').bind(id).run(); }
            return new Response(JSON.stringify({ success: true }), { headers: corsHeaders });
        }
        if (path === '/api/admin/batch_delete' && method === 'POST') {
            const { ids } = await request.json();
            if (ids) { for (const id of ids) { const img = await env.DB.prepare('SELECT key FROM images WHERE id = ?').bind(id).first(); if (img) { await env.MY_BUCKET.delete(img.key); await env.DB.prepare('DELETE FROM images WHERE id = ?').bind(id).run(); } } }
            return new Response(JSON.stringify({ success: true }), { headers: { 'Content-Type': 'application/json', ...corsHeaders } });
        }
        if (path === '/api/admin/settings') {
            if (method === 'POST') {
                const body = await request.json();
                const stmt = env.DB.prepare("INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=?");
                const batch = [];
                for (const [k, v] of Object.entries(body)) batch.push(stmt.bind(k, String(v), String(v)));
                await env.DB.batch(batch);
                return new Response(JSON.stringify({ success: true }), { headers: corsHeaders });
            }
            const data = await env.DB.prepare("SELECT * FROM settings").all();
            const map = {}; if(data.results) data.results.forEach(r => map[r.key] = r.value);
            return new Response(JSON.stringify(map), { headers: { 'Content-Type': 'application/json', ...corsHeaders } });
        }
        if (path === '/api/admin/blocked_ips') {
            const { results } = await env.DB.prepare('SELECT * FROM blocked_ips ORDER BY created_at DESC').all();
            return new Response(JSON.stringify(results || []), { headers: { 'Content-Type': 'application/json', ...corsHeaders } });
        }
        if (path === '/api/admin/block_ip' && method === 'POST') {
            const { ip } = await request.json();
            await env.DB.prepare('INSERT OR IGNORE INTO blocked_ips (ip, created_at) VALUES (?, ?)').bind(ip, Date.now()).run();
            return new Response(JSON.stringify({ success: true }), { headers: corsHeaders });
        }
        if (path === '/api/admin/unblock_ip' && method === 'POST') {
            const { ip } = await request.json();
            await env.DB.prepare('DELETE FROM blocked_ips WHERE ip = ?').bind(ip).run();
            return new Response(JSON.stringify({ success: true }), { headers: corsHeaders });
        }
        if (path === '/api/admin/purge_expired' && method === 'POST') {
            const now = Date.now();
            const expired = await env.DB.prepare('SELECT id, key FROM images WHERE expire_at IS NOT NULL AND expire_at < ? LIMIT 50').bind(now).all();
            let count = 0;
            if(expired.results) { for (const img of expired.results) { await env.MY_BUCKET.delete(img.key); await env.DB.prepare('DELETE FROM images WHERE id = ?').bind(img.id).run(); count++; } }
            return new Response(JSON.stringify({ success: true, count }), { headers: corsHeaders });
        }
    }

    return new Response('API OK', { headers: corsHeaders });
  }
};

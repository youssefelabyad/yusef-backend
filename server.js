// Instagram Intelligence - Secure Backend
// Youssef Elabyad @yusef_elabyad | Instagram ID 17841405344844788
const 【entity-express¦canonical_name=express】 = require('【entity-express¦canonical_name=express】');
const cors = require('cors');
const app = 【entity-express¦canonical_name=express】();
app.use(cors());
app.use(【entity-express¦canonical_name=express】.json());

const IG_ID = process.env.INSTAGRAM_ID || '17841405344844788';
const TOKEN = process.env.INSTAGRAM_ACCESS_TOKEN;
const FB_API = 'https://graph.facebook.com/v21.0';

async function fbFetch(path) {
  if (!TOKEN) throw new Error('Missing INSTAGRAM_ACCESS_TOKEN env var');
  const url = `${FB_API}${path}${path.includes('?') ? '&' : '?'}access_token=${TOKEN}`;
  const r = await fetch(url);
  const data = await r.json();
  if (data.error && data.error.code && data.error.code !== 'ok') throw new Error(data.error.message || data.error.code);
  return data;
}

app.get('/api/health', (req, res) => res.json({ ok: true, instagram_id: IG_ID, has_token: !!TOKEN }));

app.get('/api/me', async (req, res) => {
  try {
    const data = await fbFetch(`/me/accounts?fields=id,name,instagram_business_account{id,username}`);
    res.json(data);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/profile', async (req, res) => {
  try {
    const data = await fbFetch(`/${IG_ID}?fields=id,username,name,biography,media_count,followers_count,follows_count,profile_picture_url,website`);
    res.json({ ...data, source: 'Live API' });
  } catch (e) { res.status(500).json({ error: e.message, source: 'Live API' }); }
});

app.get('/api/media', async (req, res) => {
  try {
    const limit = req.query.limit || 25;
    const data = await fbFetch(`/${IG_ID}/media?fields=id,caption,media_type,media_url,permalink,timestamp,like_count,comments_count&limit=${limit}`);
    res.json({ ...data, source: 'Live API' });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/insights', async (req, res) => {
  try {
    const metrics = 'reach,views,accounts_engaged,total_interactions,profile_views';
    const data = await fbFetch(`/${IG_ID}/insights?metric=${metrics}&period=day&metric_type=total_value`);
    res.json({ ...data, source: 'Live API' });
  } catch (e) { res.status(500).json({ error: e.message, note: 'Insights may be Unavailable if permission missing' }); }
});

// ===== TikTok - Sandbox =====
const TIKTOK_KEY = process.env.TIKTOK_CLIENT_KEY;
const TIKTOK_SECRET = process.env.TIKTOK_CLIENT_SECRET;
const TIKTOK_REDIRECT = process.env.TIKTOK_REDIRECT_URI || 'https://yusef-backend-production.up.railway.app/api/tiktok/callback';
let TIKTOK_TOKEN = process.env.TIKTOK_ACCESS_TOKEN || null;

app.get('/api/tiktok/status', (req, res) => res.json({ ok: true, has_key: !!TIKTOK_KEY, has_secret: !!TIKTOK_SECRET, has_token: !!TIKTOK_TOKEN, redirect_uri: TIKTOK_REDIRECT }));

app.get('/api/tiktok/login', (req, res) => {
  if (!TIKTOK_KEY) return res.status(500).json({ error: 'Missing TIKTOK_CLIENT_KEY env var' });
  const scope = 'user.info.profile,user.info.stats,video.list';
  const url = `https://www.tiktok.com/v2/auth/authorize?client_key=${TIKTOK_KEY}&scope=${scope}&response_type=code&redirect_uri=${encodeURIComponent(TIKTOK_REDIRECT)}&state=tiktok_login`;
  res.redirect(url);
});

app.get('/api/tiktok/callback', async (req, res) => {
  const { code, error } = req.query;
  if (error) return res.status(400).send(`TikTok auth error: ${error}`);
  if (!code) return res.status(400).send('Missing code');
  try {
    const r = await fetch('https://open.tiktokapis.com/v2/oauth/token/', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ client_key: TIKTOK_KEY, client_secret: TIKTOK_SECRET, grant_type: 'authorization_code', code, redirect_uri: TIKTOK_REDIRECT })
    });
    const data = await r.json();
    if (data.error) throw new Error(data.error_description || data.error);
    TIKTOK_TOKEN = data.access_token;
    res.send(`<h1>TikTok connected ✅</h1><p>Token saved in backend. You can close this and open your dashboard.</p><p><a href="https://yusef-delta.vercel.app">Open Dashboard</a></p>`);
  } catch (e) { res.status(500).send(`Token exchange failed: ${e.message}`); }
});

app.get('/api/tiktok/profile', async (req, res) => {
  try {
    if (!TIKTOK_TOKEN) throw new Error('Not connected - open /api/tiktok/login first');
    const r = await fetch('https://open.tiktokapis.com/v2/user/info/?fields=open_id,union_id,avatar_url,display_name,bio_description,profile_deep_link,is_verified,follower_count,following_count,likes_count,video_count', { headers: { Authorization: `Bearer ${TIKTOK_TOKEN}` } });
    const data = await r.json();
    if (data.error && data.error.code && data.error.code !== 'ok') throw new Error(data.error.message || data.error.code);
    res.json({ ...data.data.user, source: 'Live TikTok API' });
  } catch (e) { res.status(500).json({ error: e.message, source: 'Live TikTok API' }); }
});

app.post('/api/tiktok/videos', async (req, res) => {
  try {
    if (!TIKTOK_TOKEN) throw new Error('Not connected - open /api/tiktok/login first');
    const r = await fetch('https://open.tiktokapis.com/v2/video/list/?fields=id,title,cover_image_url,share_url,view_count,like_count,comment_count,share_count,create_time', {
      method: 'POST',
      headers: { Authorization: `Bearer ${TIKTOK_TOKEN}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ max_count: 20 })
    });
    const data = await r.json();
    if (data.error && data.error.code && data.error.code !== 'ok') throw new Error(data.error.message || data.error.code);
    res.json({ ...data.data, source: 'Live TikTok API' });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Backend running on ${PORT}`));

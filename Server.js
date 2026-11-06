// Instagram Intelligence - Secure Backend
// Youssef Elabyad @yusef_elabyad | Instagram ID 17841405344844788
// Uses System User Token from Environment Variable - NEVER in frontend code
const express = require('express');
const cors = require('cors');
const app = express();
app.use(cors());
app.use(express.json());

const IG_ID = process.env.INSTAGRAM_ID || '17841405344844788';
const TOKEN = process.env.INSTAGRAM_ACCESS_TOKEN; // Set in Railway/Vercel Env Vars
const FB_API = 'https://graph.facebook.com/v21.0';

async function fbFetch(path) {
  if (!TOKEN) throw new Error('Missing INSTAGRAM_ACCESS_TOKEN env var');
  const url = `${FB_API}${path}${path.includes('?') ? '&' : '?'}access_token=${TOKEN}`;
  const r = await fetch(url);
  const data = await r.json();
  if (data.error) throw new Error(data.error.message);
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
    const data = await fbFetch(`/${IG_ID}?fields=id,username,account_type,media_count,followers_count,follows_count,biography,profile_picture_url,website`);
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

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Backend running on ${PORT}`));

const BOT_TOKEN            = '';
const USER_TOKEN           = '';

const CLIENT_ID            = '';
const CLIENT_SECRET        = '';
const REDIRECT_URI         = '';

const SLACK_SIGNING_SECRET = '';
const TARGET_CHANNEL       = '';
const JSON_HEADERS         = { 'Content-Type': 'application/json' };

const tokenStore = { bot: null, user: null };

export default {
  async fetch(request) {
    const url = new URL(request.url);

    if (url.pathname === '/oauth_redirect') {
      const code = url.searchParams.get('code');
      if (!code) {
        return new Response('Missing code parameter', { status: 400 });
      }
      const resp = await fetch('https://slack.com/api/oauth.v2.access', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          client_id: CLIENT_ID,
          client_secret: CLIENT_SECRET,
          code,
          redirect_uri: REDIRECT_URI
        })
      });
      const data = await resp.json();
      if (!data.ok) {
        return new Response(`OAuth error: ${data.error}`, { status: 400 });
      }
      tokenStore.bot  = data.access_token;
      tokenStore.user = data.authed_user?.access_token || null;
      return new Response(JSON.stringify({ bot: tokenStore.bot, user: tokenStore.user }), { headers: JSON_HEADERS });
    }

    if (url.pathname === '/' && request.method === 'POST') {
      return handleSlash(request);
    }

    return new Response('Not found', { status: 404 });
  }
};

async function handleSlash(request) {
  const body      = await request.text();
  const timestamp = request.headers.get('X-Slack-Request-Timestamp') || '';
  const signature = request.headers.get('X-Slack-Signature')        || '';
  if (!await verifySlackSignature(timestamp, body, signature)) {
    return new Response('Invalid signature', { status: 400 });
  }

  const text      = new URLSearchParams(body).get('text')?.trim() || '';
  if (!text) {
    return json({ text: 'Usage: /identity-add @username' });
  }

  const mentionRx = /^<@([UW][A-Z0-9]+)(?:\|[^>]+)?>$/;
  const m         = text.match(mentionRx);
  let userId      = m ? m[1] : null;
  if (!userId && /^[UW][A-Z0-9]+$/.test(text)) userId = text;
  if (!userId) {
    return json({ text: '⚠️ Please mention exactly one user.' });
  }
  
  await slackApi('conversations.join', { channel: TARGET_CHANNEL }, 'bot');
  const inv = await slackApi('conversations.invite', { channel: TARGET_CHANNEL, users: userId }, 'user');
  if (!inv.ok) {
    return json({ text: `Invite failed: ${inv.error}` });
  }
  return json({ text: `✅ <@${userId}> invited to <#${TARGET_CHANNEL}>.` });
}

async function slackApi(method, payload = {}, type = 'bot') {
  const url   = `https://slack.com/api/${method}`;
  const manual = (type === 'bot' ? BOT_TOKEN : USER_TOKEN).trim();
  const store  = type === 'bot' ? tokenStore.bot : tokenStore.user;
  const token  = manual || store;
  if (!token) throw new Error(`Missing ${type} token: set manual or complete OAuth flow.`);

  const opts = { headers: { Authorization: `Bearer ${token}` } };
  if (Object.keys(payload).length) {
    opts.method                  = 'POST';
    opts.headers['Content-Type'] = 'application/json';
    opts.body                    = JSON.stringify(payload);
  }
  const res = await fetch(url, opts);
  return res.json();
}

function json(body) {
  return new Response(JSON.stringify(body), { headers: JSON_HEADERS });
}

async function verifySlackSignature(timestamp, body, signature) {
  const encoder = new TextEncoder();
  const key     = await crypto.subtle.importKey('raw', encoder.encode(SLACK_SIGNING_SECRET), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const base    = `v0:${timestamp}:${body}`;
  const sigBuf  = await crypto.subtle.sign('HMAC', key, encoder.encode(base));
  const hash    = Array.from(new Uint8Array(sigBuf)).map(b => b.toString(16).padStart(2, '0')).join('');
  return signature === `v0=${hash}`;
}

// api/webhook.js – Babypass SOMRIG Webhook
// Vercel Serverless Function (Node.js runtime)

import crypto from 'node:crypto';

const SECRET_TOKEN = process.env.WEBHOOK_SECRET || 'babypass-somrig-2026';

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const token = req.query.token || req.headers['x-webhook-token'];
  if (token !== SECRET_TOKEN) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const userId = req.query.userId || 'MyfMCfH70yYM2CVwmhVBAt8Azt43';
  const babyId = req.query.babyId || 'nnF5Ti5HkFr5ixisjnmn';

  try {
    const accessToken = await getFirebaseToken();
    if (!accessToken) {
      return res.status(500).json({ error: 'Could not get Firebase token - check FIREBASE_CLIENT_EMAIL / FIREBASE_PRIVATE_KEY env vars' });
    }

    const now = new Date();
    const date = now.toISOString().split('T')[0];
    const time = String(now.getHours()).padStart(2, '0') + ':' + String(now.getMinutes()).padStart(2, '0');

    const firestorePath = `users/${userId}/babies/${babyId}/rapporte`;
    const projectId = 'gesundheits-rapport';
    const url = `https://firestore.googleapis.com/v1/projects/${projectId}/databases/(default)/documents/${firestorePath}`;

    const entry = {
      fields: {
        date:      { stringValue: date },
        time:      { stringValue: time },
        tempMode:  { stringValue: 'none' },
        temp:      { nullValue: null },
        mealType:  { stringValue: 'pending' },
        meal:      { stringValue: '⏳ Ausstehend' },
        vitD3:     { booleanValue: false },
        panda:     { booleanValue: false },
        urin:      { booleanValue: false },
        stuhl:     { booleanValue: false },
        note:      { stringValue: 'Via SOMRIG Button erfasst' },
        lang:      { stringValue: 'de' },
        pending:   { booleanValue: true },
        createdAt: { stringValue: now.toISOString() }
      }
    };

    const firestoreRes = await fetch(url, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${accessToken}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(entry)
    });

    if (!firestoreRes.ok) {
      const err = await firestoreRes.text();
      console.error('Firestore error:', err);
      return res.status(500).json({ error: 'Firestore write failed', details: err });
    }

    const result = await firestoreRes.json();
    console.log('Entry created:', result.name);

    return res.status(200).json({
      success: true,
      message: `Eintrag gespeichert: ${date} ${time}`,
      date,
      time
    });

  } catch (error) {
    console.error('Webhook error:', error);
    return res.status(500).json({ error: error.message });
  }
}

// Get Firebase access token using a service account JWT.
// Uses Node's built-in crypto module (not Web Crypto) so it works reliably
// on Vercel's standard Node.js serverless runtime.
async function getFirebaseToken() {
  const clientEmail = process.env.FIREBASE_CLIENT_EMAIL;
  const privateKey = process.env.FIREBASE_PRIVATE_KEY?.replace(/\\n/g, '\n');

  if (!clientEmail || !privateKey) {
    console.error('Missing FIREBASE_CLIENT_EMAIL or FIREBASE_PRIVATE_KEY env vars');
    return null;
  }

  const now = Math.floor(Date.now() / 1000);
  const payload = {
    iss: clientEmail,
    sub: clientEmail,
    aud: 'https://oauth2.googleapis.com/token',
    iat: now,
    exp: now + 3600,
    scope: 'https://www.googleapis.com/auth/datastore'
  };

  try {
    const jwt = createJWT(payload, privateKey);

    const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=${jwt}`
    });

    const tokenData = await tokenRes.json();
    if (!tokenData.access_token) {
      console.error('Token response error:', tokenData);
      return null;
    }
    return tokenData.access_token;
  } catch (e) {
    console.error('Token error:', e);
    return null;
  }
}

function base64url(input) {
  return Buffer.from(input)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

// Sign a service-account JWT with Node's native crypto (RS256), avoiding
// browser-only globals (btoa/atob/crypto.subtle) that aren't reliably
// available in a standard Node.js serverless function.
function createJWT(payload, privateKeyPem) {
  const header = { alg: 'RS256', typ: 'JWT' };
  const headerB64  = base64url(JSON.stringify(header));
  const payloadB64 = base64url(JSON.stringify(payload));
  const signingInput = `${headerB64}.${payloadB64}`;

  const signer = crypto.createSign('RSA-SHA256');
  signer.update(signingInput);
  signer.end();
  const signature = signer.sign(privateKeyPem);
  const sigB64 = signature.toString('base64')
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');

  return `${signingInput}.${sigB64}`;
}

// api/webhook.js – Babypass SOMRIG Webhook
// Vercel Serverless Function

const SECRET_TOKEN = process.env.WEBHOOK_SECRET || 'babypass-somrig-2026';

export default async function handler(req, res) {
  // Only allow POST
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  // Validate secret token
  const token = req.query.token || req.headers['x-webhook-token'];
  if (token !== SECRET_TOKEN) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const userId = req.query.userId || 'MyfMCfH70yYM2CVwmhVBAt8Azt43';
  const babyId = req.query.babyId || 'nnF5Ti5HkFr5ixisjnmn';

  try {
    // Get Firebase Admin token using service account
    const tokenResponse = await getFirebaseToken();
    if (!tokenResponse) {
      return res.status(500).json({ error: 'Could not get Firebase token' });
    }

    // Create timestamp
    const now = new Date();
    const date = now.toISOString().split('T')[0];
    const time = String(now.getHours()).padStart(2, '0') + ':' + String(now.getMinutes()).padStart(2, '0');

    // Write to Firestore via REST API
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
        'Authorization': `Bearer ${tokenResponse}`,
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

// Get Firebase access token using service account JWT
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
    // Create JWT manually (no external dependencies)
    const jwt = await createJWT(payload, privateKey);

    const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=${jwt}`
    });

    const tokenData = await tokenRes.json();
    return tokenData.access_token;
  } catch (e) {
    console.error('Token error:', e);
    return null;
  }
}

// Create signed JWT using Web Crypto API (built into Vercel/Node)
async function createJWT(payload, privateKeyPem) {
  const header = { alg: 'RS256', typ: 'JWT' };
  const enc = new TextEncoder();

  const b64 = str => btoa(unescape(encodeURIComponent(str)))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');

  const headerB64  = b64(JSON.stringify(header));
  const payloadB64 = b64(JSON.stringify(payload));
  const signingInput = `${headerB64}.${payloadB64}`;

  // Import private key
  const keyData = pemToBuffer(privateKeyPem);
  const key = await crypto.subtle.importKey(
    'pkcs8', keyData,
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    false, ['sign']
  );

  // Sign
  const signature = await crypto.subtle.sign(
    'RSASSA-PKCS1-v1_5', key, enc.encode(signingInput)
  );

  const sigB64 = btoa(String.fromCharCode(...new Uint8Array(signature)))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');

  return `${signingInput}.${sigB64}`;
}

function pemToBuffer(pem) {
  const base64 = pem
    .replace(/-----BEGIN PRIVATE KEY-----/, '')
    .replace(/-----END PRIVATE KEY-----/, '')
    .replace(/\s/g, '');
  const binary = atob(base64);
  const buffer = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) buffer[i] = binary.charCodeAt(i);
  return buffer.buffer;
}

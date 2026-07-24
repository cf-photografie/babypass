// api/accept-invite.js – Grants a partner access to a shared baby.
//
// Runs with Firebase Admin privileges (service account) so it can update
// documents the partner cannot write themselves yet under Firestore
// Security Rules: they need to be a listed partner to get access, but they
// need access to become a listed partner. This endpoint breaks that loop
// by performing the grant server-side, after verifying the caller's
// Firebase ID token ourselves (via Google's public signing certs) - this
// avoids relying on the restricted browser API key, which rejects
// server-to-server requests that have no HTTP referrer header.

import crypto from 'node:crypto';

const PROJECT_ID = 'gesundheits-rapport';

export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  const { idToken, ownerUid, babyId } = req.body || {};
  if (!idToken || !ownerUid || !babyId) {
    return res.status(400).json({ error: 'idToken, ownerUid, babyId required' });
  }

  try {
    // 1) Verify the caller's Firebase ID token ourselves (no API key needed).
    let email, uid;
    try {
      const verified = await verifyFirebaseIdToken(idToken);
      email = verified.email;
      uid = verified.uid;
    } catch (e) {
      console.error('Token verification failed:', e.message);
      return res.status(401).json({ error: 'Invalid ID token: ' + e.message });
    }

    const adminToken = await getFirebaseToken();
    if (!adminToken) return res.status(500).json({ error: 'Admin auth failed - check FIREBASE_CLIENT_EMAIL / FIREBASE_PRIVATE_KEY' });

    // 2) Confirm a real invite exists matching this email + baby.
    const inviteId = `${email.replace(/\./g, '_')}_${babyId}`;
    const inviteUrl = `https://firestore.googleapis.com/v1/projects/${PROJECT_ID}/databases/(default)/documents/partnerInvites/${inviteId}`;
    const inviteRes = await fetch(inviteUrl, { headers: { Authorization: `Bearer ${adminToken}` } });
    if (!inviteRes.ok) {
      const errText = await inviteRes.text();
      console.error('Invite lookup failed:', inviteRes.status, errText);
      return res.status(404).json({ error: 'No matching invite found for this email/baby' });
    }
    const invite = await inviteRes.json();
    const inviteEmail = invite.fields?.email?.stringValue;
    const inviteOwner = invite.fields?.ownerUid?.stringValue;
    if (inviteEmail !== email || inviteOwner !== ownerUid) {
      return res.status(403).json({ error: 'Invite does not match this caller/baby' });
    }

    // 3) Grant access: add this UID to the baby's + owner's partnerUids array.
    await arrayUnionField(adminToken, `users/${ownerUid}/babies/${babyId}`, 'partnerUids', uid);
    await arrayUnionField(adminToken, `users/${ownerUid}`, 'partnerUids', uid);

    // 4) Mark the invite and the matching "partners" subcollection entry active.
    await patchFields(adminToken, `partnerInvites/${inviteId}`, { status: { stringValue: 'active' } });

    const partnersUrl = `https://firestore.googleapis.com/v1/projects/${PROJECT_ID}/databases/(default)/documents/users/${ownerUid}/babies/${babyId}/partners`;
    const partnersRes = await fetch(partnersUrl, { headers: { Authorization: `Bearer ${adminToken}` } });
    const partnersData = await partnersRes.json();
    const match = (partnersData.documents || []).find(d => d.fields?.email?.stringValue === email);
    if (match) {
      const partnerDocPath = match.name.split('/documents/')[1];
      await patchFields(adminToken, partnerDocPath, {
        status: { stringValue: 'active' },
        uid: { stringValue: uid }
      });
    }

    // 5) Return the baby's basic info so the client can show it right away.
    const babyUrl = `https://firestore.googleapis.com/v1/projects/${PROJECT_ID}/databases/(default)/documents/users/${ownerUid}/babies/${babyId}`;
    const babyRes = await fetch(babyUrl, { headers: { Authorization: `Bearer ${adminToken}` } });
    const babyData = await babyRes.json();

    return res.status(200).json({
      success: true,
      baby: {
        id: babyId,
        ownerUid,
        name: babyData.fields?.name?.stringValue || 'Baby',
        icon: babyData.fields?.icon?.stringValue || '👶'
      }
    });
  } catch (e) {
    console.error('accept-invite error:', e);
    return res.status(500).json({ error: e.message });
  }
}

// ── Verify a Firebase Auth ID token without the Admin SDK and without the
//    (referrer-restricted) browser API key: check its RS256 signature
//    against Google's published public certs for Firebase Auth. ──────────
let _certsCache = null, _certsCacheAt = 0;
async function getGoogleCerts() {
  if (_certsCache && Date.now() - _certsCacheAt < 5 * 60 * 1000) return _certsCache;
  const r = await fetch('https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com');
  _certsCache = await r.json();
  _certsCacheAt = Date.now();
  return _certsCache;
}

async function verifyFirebaseIdToken(idToken) {
  const parts = idToken.split('.');
  if (parts.length !== 3) throw new Error('Malformed token');
  const [headerB64, payloadB64, sigB64] = parts;
  const header = JSON.parse(Buffer.from(headerB64, 'base64').toString('utf8'));
  const payload = JSON.parse(Buffer.from(payloadB64, 'base64').toString('utf8'));

  const certs = await getGoogleCerts();
  const cert = certs[header.kid];
  if (!cert) throw new Error('Unknown signing key (kid)');

  const signingInput = `${headerB64}.${payloadB64}`;
  const signature = Buffer.from(sigB64.replace(/-/g, '+').replace(/_/g, '/'), 'base64');

  const verifier = crypto.createVerify('RSA-SHA256');
  verifier.update(signingInput);
  verifier.end();
  if (!verifier.verify(cert, signature)) throw new Error('Bad signature');

  const now = Math.floor(Date.now() / 1000);
  if (payload.exp < now) throw new Error('Token expired');
  if (payload.aud !== PROJECT_ID) throw new Error('Wrong audience');
  if (payload.iss !== `https://securetoken.google.com/${PROJECT_ID}`) throw new Error('Wrong issuer');
  if (!payload.email) throw new Error('Token has no email');

  return { uid: payload.user_id || payload.sub, email: payload.email.toLowerCase() };
}

async function arrayUnionField(token, path, field, value) {
  const url = `https://firestore.googleapis.com/v1/projects/${PROJECT_ID}/databases/(default)/documents:commit`;
  const body = {
    writes: [{
      transform: {
        document: `projects/${PROJECT_ID}/databases/(default)/documents/${path}`,
        fieldTransforms: [{
          fieldPath: field,
          appendMissingElements: { values: [{ stringValue: value }] }
        }]
      }
    }]
  };
  const r = await fetch(url, {
    method: 'POST',
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    body: JSON.stringify(body)
  });
  if (!r.ok) console.error('arrayUnion failed:', await r.text());
}

async function patchFields(token, path, fields) {
  const mask = Object.keys(fields).map(k => `updateMask.fieldPaths=${k}`).join('&');
  const url = `https://firestore.googleapis.com/v1/projects/${PROJECT_ID}/databases/(default)/documents/${path}?${mask}`;
  const r = await fetch(url, {
    method: 'PATCH',
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ fields })
  });
  if (!r.ok) console.error('patch failed:', await r.text());
}

async function getFirebaseToken() {
  const clientEmail = process.env.FIREBASE_CLIENT_EMAIL;
  const privateKey = process.env.FIREBASE_PRIVATE_KEY?.replace(/\\n/g, '\n');
  if (!clientEmail || !privateKey) return null;
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    iss: clientEmail, sub: clientEmail,
    aud: 'https://oauth2.googleapis.com/token',
    iat: now, exp: now + 3600,
    scope: 'https://www.googleapis.com/auth/datastore'
  };
  const jwt = createJWT(payload, privateKey);
  const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=${jwt}`
  });
  const tokenData = await tokenRes.json();
  if (!tokenData.access_token) console.error('Admin token error:', tokenData);
  return tokenData.access_token || null;
}

function base64url(input) {
  return Buffer.from(input).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

function createJWT(payload, privateKeyPem) {
  const header = { alg: 'RS256', typ: 'JWT' };
  const signingInput = `${base64url(JSON.stringify(header))}.${base64url(JSON.stringify(payload))}`;
  const signer = crypto.createSign('RSA-SHA256');
  signer.update(signingInput);
  signer.end();
  const sig = signer.sign(privateKeyPem).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  return `${signingInput}.${sig}`;
}

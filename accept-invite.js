// api/accept-invite.js – Grants a partner access to a shared baby.
//
// Runs with Firebase Admin privileges (service account) so it can update
// documents the partner cannot write themselves yet under Firestore
// Security Rules: they need to be a listed partner to get access, but they
// need access to become a listed partner. This endpoint breaks that loop
// by performing the grant server-side, after verifying the caller's
// Firebase ID token directly with Google (so nobody can grant themselves
// access to someone else's baby by simply guessing IDs).

import crypto from 'node:crypto';

const PROJECT_ID = 'gesundheits-rapport';
const API_KEY = 'AIzaSyAHwARmCNsKcQZj276ogN0DEONJN1DoQoQ';

export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  const { idToken, ownerUid, babyId } = req.body || {};
  if (!idToken || !ownerUid || !babyId) {
    return res.status(400).json({ error: 'idToken, ownerUid, babyId required' });
  }

  try {
    // 1) Verify the caller's Firebase ID token directly with Google.
    const lookupRes = await fetch(`https://identitytoolkit.googleapis.com/v1/accounts:lookup?key=${API_KEY}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ idToken })
    });
    const lookupData = await lookupRes.json();
    const user = lookupData.users && lookupData.users[0];
    if (!user) return res.status(401).json({ error: 'Invalid ID token' });
    const email = (user.email || '').toLowerCase();
    const uid = user.localId;

    const adminToken = await getFirebaseToken();
    if (!adminToken) return res.status(500).json({ error: 'Admin auth failed - check FIREBASE_CLIENT_EMAIL / FIREBASE_PRIVATE_KEY' });

    // 2) Confirm a real invite exists matching this email + baby (prevents
    // granting access to babies the caller was never invited to).
    const inviteId = `${email.replace(/\./g, '_')}_${babyId}`;
    const inviteUrl = `https://firestore.googleapis.com/v1/projects/${PROJECT_ID}/databases/(default)/documents/partnerInvites/${inviteId}`;
    const inviteRes = await fetch(inviteUrl, { headers: { Authorization: `Bearer ${adminToken}` } });
    if (!inviteRes.ok) return res.status(404).json({ error: 'No matching invite found for this email/baby' });
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

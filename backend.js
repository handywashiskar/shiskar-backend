require('dotenv').config();
const express = require('express');
const multer = require('multer');
const crypto = require('crypto');
const axios = require('axios');
const cors = require('cors');

const app = express();
app.use(cors());
const upload = multer();

const KEY_ID = process.env.KEY_ID;
const APP_KEY = process.env.APP_KEY;
const BUCKET_ID = process.env.BUCKET_ID;
const BUCKET_NAME = process.env.BUCKET_NAME;

let authData = null;
let authFetchedAt = 0;
const AUTH_TTL_MS = 1000 * 60 * 45;

async function authorizeB2() {
  try {
    const encoded = Buffer.from(`${KEY_ID}:${APP_KEY}`).toString('base64');
    const res = await axios.get('https://api.backblazeb2.com/b2api/v2/b2_authorize_account', {
      headers: { Authorization: `Basic ${encoded}` }
    });
    authData = res.data;
    authFetchedAt = Date.now();
    return authData;
  } catch (err) {
    console.error('b2 authorize failed', err.response?.data || err.message);
    throw err;
  }
}

async function ensureAuth() {
  if (!authData || (Date.now() - authFetchedAt) > AUTH_TTL_MS) {
    await authorizeB2();
  }
}

async function getUploadUrl() {
  await ensureAuth();
  const url = `${authData.apiUrl}/b2api/v2/b2_get_upload_url`;
  try {
    const res = await axios.post(url, { bucketId: BUCKET_ID }, {
      headers: { Authorization: authData.authorizationToken }
    });
    return res.data;
  } catch (err) {
    console.error('b2 get_upload_url failed', err.response?.data || err.message);
    throw err;
  }
}

app.post('/upload', upload.single('file'), async (req, res) => {
  try {
    if (!req.file || !req.file.buffer) {
      return res.status(400).json({ error: 'No file uploaded' });
    }

    const uploadData = await getUploadUrl();
    const sha1 = crypto.createHash('sha1').update(req.file.buffer).digest('hex');
    const timestamp = Date.now();
    const random = crypto.randomBytes(6).toString('hex');
    const originalName = (req.file.originalname || 'file').replace(/[^a-zA-Z0-9_\-\.]/g, '_');
    const fileName = `${timestamp}-${random}-${originalName}`;

    const uploadRes = await axios.post(uploadData.uploadUrl, req.file.buffer, {
      headers: {
        Authorization: uploadData.authorizationToken,
        'X-Bz-File-Name': fileName,
        'Content-Type': req.file.mimetype || 'application/octet-stream',
        'X-Bz-Content-Sha1': sha1
      },
      maxContentLength: Infinity,
      maxBodyLength: Infinity
    });

    const publicUrl = `https://f000.backblazeb2.com/file/${BUCKET_NAME}/${encodeURIComponent(fileName)}`;
    return res.json({ url: publicUrl });
  } catch (err) {
    console.error('upload error', err.response?.data || err.message);
    const status = err.response?.status || 500;
    const message = err.response?.data || err.message;
    return res.status(status).json({ error: String(message) });
  }
});

app.get('/health', (req, res) => res.json({ ok: true }));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`B2 upload backend running on port ${PORT}`));

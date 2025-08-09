'use strict';

const crypto = require('crypto');

function getRawBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

function verifySignature(appSecret, rawBody, signatureHeader) {
  if (!signatureHeader || !appSecret) return false;
  const [scheme, signature] = signatureHeader.split('=');
  if (scheme !== 'sha256' || !signature) return false;
  const hmac = crypto.createHmac('sha256', appSecret);
  hmac.update(rawBody);
  const expected = hmac.digest('hex');
  try {
    return crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected));
  } catch {
    return false;
  }
}

async function callSendAPI(recipientId, message) {
  const url = `https://graph.facebook.com/v20.0/me/messages?access_token=${encodeURIComponent(process.env.PAGE_ACCESS_TOKEN)}`;
  const payload = {
    recipient: { id: recipientId },
    message,
  };
  const r = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  if (!r.ok) {
    const txt = await r.text();
    console.error('Send API error', r.status, txt);
  }
}

module.exports = async (req, res) => {
  if (req.method === 'GET') {
    // Xác minh webhook
    const mode = req.query['hub.mode'];
    const token = req.query['hub.verify_token'];
    const challenge = req.query['hub.challenge'];
    if (mode === 'subscribe' && token === process.env.VERIFY_TOKEN) {
      return res.status(200).send(challenge);
    }
    return res.status(403).send('Forbidden');
  }

  if (req.method === 'POST') {
    try {
      const rawBody = await getRawBody(req);
      const sig = req.headers['x-hub-signature-256'];
      const ok = verifySignature(process.env.APP_SECRET, rawBody, sig);
      if (!ok) {
        return res.status(401).send('Invalid signature');
      }

      const body = JSON.parse(rawBody.toString('utf8'));

      if (body.object === 'page') {
        for (const entry of body.entry || []) {
          for (const event of entry.messaging || []) {
            const senderId = event.sender && event.sender.id;

            if (event.message && senderId) {
              const text = event.message.text || '';
              await callSendAPI(senderId, {
                text: `Bạn vừa nói: "${text}". Tôi có thể giúp gì thêm?`,
              });
              await callSendAPI(senderId, {
                text: 'Bạn quan tâm điều gì?',
                quick_replies: [
                  { content_type: 'text', title: 'Báo giá', payload: 'PRICING' },
                  { content_type: 'text', title: 'Tư vấn', payload: 'CONSULT' },
                  { content_type: 'text', title: 'CSKH', payload: 'SUPPORT' },
                ],
              });
            } else if (event.postback && senderId) {
              const payload = event.postback.payload;
              await callSendAPI(senderId, { text: `Bạn đã chọn: ${payload}` });
            }
          }
        }
        return res.sendStatus(200);
      }
      return res.sendStatus(404);
    } catch (e) {
      console.error('Webhook error:', e);
      return res.sendStatus(500);
    }
  }

  return res.status(405).send('Method Not Allowed');
};
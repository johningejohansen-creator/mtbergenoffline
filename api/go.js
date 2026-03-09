// /api/go.js
const crypto = require("crypto");

function base64url(buf) {
  return Buffer.from(buf).toString("base64").replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}

function timingSafeEq(a, b) {
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  if (ab.length !== bb.length) return false;
  return crypto.timingSafeEqual(ab, bb);
}

function verifyToken(token, secret) {
  if (!token) return { ok: false };
  const parts = token.split(".");
  if (parts.length !== 3) return { ok: false };
  const [expStr, nonce, sig] = parts;

  const exp = Number(expStr);
  if (!Number.isFinite(exp) || exp < Date.now()) return { ok: false };

  const payload = `${expStr}.${nonce}`;
  const expected = base64url(crypto.createHmac("sha256", secret).update(payload).digest());
  if (!timingSafeEq(sig, expected)) return { ok: false };

  return { ok: true, exp };
}

module.exports = (req, res) => {
  const secret = process.env.NY_SECRET;
  if (!secret) return res.status(500).send("Missing NY_SECRET");

  const url = new URL(req.url, `https://${req.headers.host}`);
  const token = url.searchParams.get("t");

  const v = verifyToken(token, secret);
  if (!v.ok) return res.status(403).send("Ugyldig eller utløpt token");

  // HttpOnly cookie (ikke lesbar i JS)
  const cookie = [
    `ny=${token}`,
    "Path=/",
    "HttpOnly",
    "Secure",
    "SameSite=Lax",
    `Max-Age=${60}` // 60 sek
  ].join("; ");

  res.setHeader("Set-Cookie", cookie);
  res.setHeader("Cache-Control", "no-store");
  res.statusCode = 302;
  res.setHeader("Location", "/nysgjerrig");
  res.end();
};
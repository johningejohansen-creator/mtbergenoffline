// /api/nysgjerrig.js
const fs = require("fs");
const path = require("path");
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

function parseCookies(cookieHeader = "") {
  const out = {};
  cookieHeader.split(";").forEach(part => {
    const [k, ...v] = part.trim().split("=");
    if (!k) return;
    out[k] = decodeURIComponent(v.join("=") || "");
  });
  return out;
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

  return { ok: true };
}

module.exports = (req, res) => {
  const secret = process.env.NY_SECRET;
  if (!secret) return res.status(500).send("Missing NY_SECRET");

  const cookies = parseCookies(req.headers.cookie || "");
  const token = cookies.ny;

  const v = verifyToken(token, secret);
  if (!v.ok) {
    res.statusCode = 302;
    res.setHeader("Location", "/"); // eller en “ikke tilgang”-side
    return res.end();
  }

  const filePath = path.join(process.cwd(), "protected", "nysgjerrig.html");
  const html = fs.readFileSync(filePath, "utf8");

  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.setHeader("Cache-Control", "no-store");
  res.status(200).send(html);
};
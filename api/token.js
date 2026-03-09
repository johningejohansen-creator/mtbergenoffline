// /api/token.js
const crypto = require("crypto");

function base64url(buf) {
  return Buffer.from(buf).toString("base64").replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}

module.exports = (req, res) => {
  const secret = process.env.NY_SECRET;
  if (!secret) return res.status(500).json({ error: "Missing NY_SECRET" });

  const exp = Date.now() + 60_000; // 60 sek gyldighet
  const nonce = crypto.randomBytes(12).toString("hex");
  const payload = `${exp}.${nonce}`;

  const sig = base64url(crypto.createHmac("sha256", secret).update(payload).digest());
  const token = `${payload}.${sig}`;

  res.setHeader("Cache-Control", "no-store");
  res.status(200).json({ token });
};
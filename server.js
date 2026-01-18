require("dotenv").config();

const express = require("express");
const rateLimit = require("express-rate-limit");
const helmet = require("helmet");
const crypto = require("crypto");

const app = express();
app.use(express.json());
app.use(helmet());

/* ================= RATE LIMIT ================= */
const limiter = rateLimit({
  windowMs: 60 * 1000,
  max: 10, // 10 req/min per IP
  standardHeaders: true,
  legacyHeaders: false
});
app.use(limiter);

/* ================= IN-MEMORY DB =================
   Replace with Mongo/SQLite later
*/
const database = {
  keys: {}
};

/* ================= UTILS ================= */
function generateKey() {
  return crypto.randomBytes(16).toString("hex").toUpperCase();
}

function hash(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

/* ================= ADMIN KEY GENERATION =================
   PROTECTED BY SECRET
*/
app.post("/genkey", (req, res) => {
  const adminSecret = req.headers["x-admin-secret"];

  if (adminSecret !== process.env.ADMIN_SECRET) {
    return res.status(403).json({ error: "Forbidden" });
  }

  const key = generateKey();

  database.keys[key] = {
    used: false,
    userId: null,
    hwid: null,
    ip: null,
    createdAt: Date.now()
  };

  res.json({ key });
});

/* ================= KEY VALIDATION (ROBLOX CALLS THIS) ================= */
app.post("/validate", (req, res) => {
  const { key, userId, hwid } = req.body;
  const ip =
    req.headers["x-forwarded-for"] ||
    req.socket.remoteAddress;

  if (!key || !userId || !hwid) {
    return res.json({ valid: false });
  }

  const record = database.keys[key];
  if (!record) {
    return res.json({ valid: false });
  }

  const hwidHash = hash(hwid);

  // FIRST USE → BIND
  if (!record.used) {
    record.used = true;
    record.userId = String(userId);
    record.hwid = hwidHash;
    record.ip = ip;

    return res.json({ valid: true, first: true });
  }

  // ALREADY USED → VERIFY
  if (
    record.userId !== String(userId) ||
    record.hwid !== hwidHash
  ) {
    return res.json({
      valid: false,
      reason: "Key bound to another device"
    });
  }

  res.json({ valid: true });
});

/* ================= ERROR HANDLER ================= */
app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: "Internal Server Error" });
});

/* ================= START ================= */
const PORT = process.env.PORT || 3000;
app.listen(PORT, () =>
  console.log(`Antares API running on port ${PORT}`)
);

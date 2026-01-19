const TIERS = {
  trial: {
    duration: 14 * 24 * 60 * 60 * 1000, // 14 days
    bind: false
  },
  monthly: {
    duration: 30 * 24 * 60 * 60 * 1000, // 30 days
    bind: true
  },
  permanent: {
    duration: null, // no expiration
    bind: true
  }
}


const express = require("express");
const bodyParser = require("body-parser");

const app = express();
app.use(bodyParser.json());

// ===============================
// CONFIG
// ===============================
const ADMIN_SECRET = process.env.ADMIN_SECRET;

// In-memory storage (resets on restart)
const sessions = {};
const keys = {};

// ===============================
// UTILS
// ===============================
function randomString(len = 24) {
	return Math.random().toString(36).substring(2, 2 + len);
}

// ===============================
// ADMIN: GENERATE KEY (POSTMAN)
// ===============================
app.get("/genkey", (req, res) => {
	const adminSecret = req.headers["x-admin-secret"];

	if (!adminSecret || adminSecret !== ADMIN_SECRET) {
		return res.status(403).json({ error: "Forbidden" });
	}

	const key = "ANTARES-" + randomString(10).toUpperCase();

	keys[key] = {
		redeemed: false,
		playerId: null
	};

	res.json({ key });
});

// ===============================
// ROBLOX: CREATE SESSION
// ===============================
app.post("/session", (req, res) => {
	const session = randomString(32);

	sessions[session] = {
		created: Date.now()
	};

	res.json({ session });
});

// ===============================
// ROBLOX: REDEEM KEY
// ===============================
app.post("/redeem", (req, res) => {
	const { session, key, playerId } = req.body;

	if (!session || !sessions[session]) {
		return res.json({ success: false, error: "Invalid session" });
	}

	if (!key || !keys[key]) {
		return res.json({ success: false, error: "Invalid key" });
	}

	const entry = keys[key];

	// First redemption
	if (!entry.redeemed) {
		entry.redeemed = true;
		entry.playerId = playerId;
		return res.json({ success: true });
	}

	// Already redeemed: only allow same player
	if (entry.playerId === playerId) {
		return res.json({ success: true });
	}

	// Redeemed by someone else
	return res.json({ success: false, error: "Key already used" });
});

// ===============================
// HEALTH CHECK
// ===============================
app.get("/", (req, res) => {
	res.send("Antares key server online");
});

// ===============================
// START SERVER
// ===============================
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
	console.log("Antares server running on port", PORT);
});

// server.js
const express = require("express");
const cors = require("cors");
const bodyParser = require("body-parser");
const crypto = require("crypto");
const app = express();

// Load ADMIN_SECRET
const ADMIN_SECRET = process.env.ADMIN_SECRET;
if (!ADMIN_SECRET) {
    console.error("Error: ADMIN_SECRET environment variable not set!");
    process.exit(1);
}

// Middleware
app.use(cors());
app.use(bodyParser.json());

// In-memory database
const database = {
    keys: {} // { key: { createdAt, expires, fingerprint } }
};

// Utility: generate unique key
function generateKey() {
    return "ANTARES-" + crypto.randomBytes(4).toString("hex").toUpperCase() + "-" +
        crypto.randomBytes(4).toString("hex").toUpperCase();
}

// Genkey endpoint
app.post("/genkey", (req, res) => {
    const adminSecret = req.headers["x-admin-secret"];

    if (!adminSecret) {
        return res.status(403).json({ error: "Forbidden - missing x-admin-secret header" });
    }

    if (adminSecret !== ADMIN_SECRET) {
        return res.status(403).json({ error: "Forbidden - invalid admin secret" });
    }

    const key = generateKey();
    const expiresInHours = req.body.expires_in || 24;
    const now = Date.now();
    const expires = now + expiresInHours * 60 * 60 * 1000;

    database.keys[key] = {
        createdAt: now,
        expires: expires,
        fingerprint: null // will be bound on first verify
    };

    return res.json({ key: key, expires: expires });
});

// Verify endpoint
app.post("/verify", (req, res) => {
    const { key, fingerprint } = req.body;

    if (!key || !database.keys[key]) {
        return res.json({ valid: false, reason: "Invalid key" });
    }

    const keyData = database.keys[key];

    if (Date.now() > keyData.expires) {
        return res.json({ valid: false, reason: "Key expired" });
    }

    // Bind fingerprint on first use
    if (!keyData.fingerprint) {
        keyData.fingerprint = fingerprint;
    } else {
        const bound = keyData.fingerprint;
        const match =
            bound.userid === fingerprint.userid &&
            bound.placeid === fingerprint.placeid &&
            bound.executor === fingerprint.executor;

        if (!match) {
            return res.json({ valid: false, reason: "Key already used by another user" });
        }
    }

    return res.json({
        valid: true,
        expires: keyData.expires,
        script_url: "https://raw.githubusercontent.com/ssantares/antares/refs/heads/main/antares.lua"
    });
});

// Health check
app.get("/", (req, res) => {
    res.send("Antares Key Server running!");
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});

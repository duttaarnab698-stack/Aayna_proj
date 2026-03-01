require("dotenv").config();
const express = require("express");
const nodemailer = require("nodemailer");
const twilio = require("twilio");

const app = express();
const PORT = Number(process.env.PORT || 5500);
const APP_ORIGIN = process.env.APP_ORIGIN || "*";

app.use(express.json({ limit: "100kb" }));
app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", APP_ORIGIN === "*" ? "*" : APP_ORIGIN);
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  if (req.method === "OPTIONS") return res.sendStatus(204);
  next();
});

const OTP_EXPIRY_MS = 5 * 60 * 1000;
const OTP_RESEND_MS = 30 * 1000;
const OTP_MAX_ATTEMPTS = 5;

// In-memory OTP store: restart করলে reset হবে।
const otpStore = new Map();

const isValidEmail = (value) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test((value || "").trim());
const isIndianPhone = (value) => /^\+91\d{10}$/.test((value || "").trim());

function parseIdentifier(identifier) {
  const raw = (identifier || "").trim();
  if (!raw) return { ok: false, reason: "missing" };
  if (raw.includes("@")) {
    if (!isValidEmail(raw)) return { ok: false, reason: "invalid_email" };
    return { ok: true, channel: "email", value: raw.toLowerCase() };
  }
  if (!isIndianPhone(raw)) return { ok: false, reason: "invalid_phone" };
  return { ok: true, channel: "phone", value: raw };
}

function generateOtp() {
  return String(Math.floor(100000 + Math.random() * 900000));
}

function maskIdentifier(identifier) {
  if (identifier.includes("@")) {
    const [name, domain] = identifier.split("@");
    return `${name.slice(0, 2)}***@${domain}`;
  }
  return `${identifier.slice(0, 3)}******${identifier.slice(-4)}`;
}

const hasTwilio = Boolean(process.env.TWILIO_ACCOUNT_SID && process.env.TWILIO_AUTH_TOKEN && process.env.TWILIO_FROM_NUMBER);
const twilioClient = hasTwilio ? twilio(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN) : null;

const hasSMTP = Boolean(process.env.SMTP_HOST && process.env.SMTP_PORT && process.env.SMTP_USER && process.env.SMTP_PASS);
const mailTransporter = hasSMTP
  ? nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: Number(process.env.SMTP_PORT),
      secure: String(process.env.SMTP_SECURE || "false") === "true",
      auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS
      }
    })
  : null;

app.get("/api/otp/health", (req, res) => {
  res.json({
    ok: true,
    smsConfigured: hasTwilio,
    emailConfigured: hasSMTP
  });
});

app.post("/api/otp/send", async (req, res) => {
  try {
    const parsed = parseIdentifier(req.body?.identifier);
    if (!parsed.ok) {
      return res.status(400).json({ ok: false, message: "Invalid identifier. Use email or +91 phone." });
    }

    const existing = otpStore.get(parsed.value);
    if (existing && Date.now() - existing.sentAt < OTP_RESEND_MS) {
      return res.status(429).json({ ok: false, message: "Please wait 30 seconds before requesting OTP again." });
    }

    const otp = generateOtp();
    otpStore.set(parsed.value, {
      otp,
      channel: parsed.channel,
      sentAt: Date.now(),
      expiresAt: Date.now() + OTP_EXPIRY_MS,
      attempts: 0
    });

    if (parsed.channel === "phone") {
      if (!twilioClient) {
        return res.status(500).json({ ok: false, message: "SMS provider is not configured." });
      }

      await twilioClient.messages.create({
        body: `Your AAYNA OTP is ${otp}. Valid for 5 minutes.`,
        from: process.env.TWILIO_FROM_NUMBER,
        to: parsed.value
      });
    } else {
      if (!mailTransporter) {
        return res.status(500).json({ ok: false, message: "Email provider is not configured." });
      }

      await mailTransporter.sendMail({
        from: process.env.SMTP_FROM || process.env.SMTP_USER,
        to: parsed.value,
        subject: "Your AAYNA OTP",
        text: `Your AAYNA OTP is ${otp}. It is valid for 5 minutes.`,
        html: `<p>Your AAYNA OTP is <strong>${otp}</strong>.</p><p>It is valid for 5 minutes.</p>`
      });
    }

    return res.json({
      ok: true,
      message: `OTP sent to ${maskIdentifier(parsed.value)}`
    });
  } catch (error) {
    return res.status(500).json({
      ok: false,
      message: "Failed to send OTP. Please try again.",
      error: error?.message || "Unknown error"
    });
  }
});

app.post("/api/otp/verify", (req, res) => {
  const parsed = parseIdentifier(req.body?.identifier);
  const otpInput = String(req.body?.otp || "").trim();
  if (!parsed.ok) {
    return res.status(400).json({ ok: false, message: "Invalid identifier." });
  }
  if (!/^\d{6}$/.test(otpInput)) {
    return res.status(400).json({ ok: false, message: "OTP must be 6 digits." });
  }

  const record = otpStore.get(parsed.value);
  if (!record) return res.status(400).json({ ok: false, message: "Please send OTP first." });
  if (Date.now() > record.expiresAt) {
    otpStore.delete(parsed.value);
    return res.status(400).json({ ok: false, message: "OTP expired. Request a new OTP." });
  }
  if (record.attempts >= OTP_MAX_ATTEMPTS) {
    otpStore.delete(parsed.value);
    return res.status(429).json({ ok: false, message: "Too many attempts. Request OTP again." });
  }
  if (record.otp !== otpInput) {
    record.attempts += 1;
    otpStore.set(parsed.value, record);
    return res.status(400).json({ ok: false, message: "Invalid OTP." });
  }

  otpStore.delete(parsed.value);
  return res.json({ ok: true, message: "OTP verified." });
});

setInterval(() => {
  const now = Date.now();
  for (const [key, record] of otpStore.entries()) {
    if (record.expiresAt <= now) otpStore.delete(key);
  }
}, 60 * 1000);

app.use(express.static("."));

app.listen(PORT, () => {
  console.log(`AAYNA server running on http://localhost:${PORT}`);
});

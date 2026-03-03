import express from "express";
import path from "path";
import { fileURLToPath } from "url";
import dotenv from "dotenv";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import nodemailer from "nodemailer";
import cookieParser from "cookie-parser";
import helmet from "helmet";
import rateLimit from "express-rate-limit";

dotenv.config();

const app = express();
app.set("trust proxy", 1);

app.use(helmet());
app.use(express.json({ limit: "200kb" }));
app.use(express.urlencoded({ extended: true, limit: "200kb" }));
app.use(cookieParser());

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PUBLIC_DIR = path.join(__dirname, "public");

function mustEnv(name) {
  const v = process.env[name];
  if (!v) throw new Error(`Missing env: ${name}`);
  return v;
}

const JWT_SECRET = mustEnv("JWT_SECRET");
const ADMIN_USER = mustEnv("ADMIN_USER");
const ADMIN_PASS_HASH = mustEnv("ADMIN_PASS_HASH");

const BRAND_NAME = process.env.BRAND_NAME || "Clan TRIPxESPORTS";
const BRAND_URL = process.env.BRAND_URL || "https://clan-tripxesports.up.railway.app";
const LOGO_URL = process.env.LOGO_URL || ""; // رابط صورة اللوجو (png/jpg)
const FROM_NAME = process.env.FROM_NAME || BRAND_NAME;
const FROM_EMAIL = mustEnv("FROM_EMAIL");

// ====== Rate limits (تقليل سوء الاستخدام/سبام) ======
const loginLimiter = rateLimit({
  windowMs: 5 * 60 * 1000,
  max: 15,
  standardHeaders: true,
  legacyHeaders: false,
});

const sendLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 8,
  standardHeaders: true,
  legacyHeaders: false,
});

// ====== SMTP transporter ======
const transporter = nodemailer.createTransport({
  host: mustEnv("SMTP_HOST"),
  port: Number(process.env.SMTP_PORT || 587),
  secure: String(process.env.SMTP_SECURE || "false").toLowerCase() === "true",
  auth: {
    user: mustEnv("SMTP_USER"),
    pass: mustEnv("SMTP_PASS"),
  },
});

// ====== Helpers ======
function escapeHtml(str = "") {
  return String(str)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function buildEmailHtml({ toEmail, message, subject }) {
  const safeMsg = escapeHtml(message).replaceAll("\n", "<br/>");
  const safeSubject = escapeHtml(subject || `رسالة من ${BRAND_NAME}`);

  // تصميم HTML بإسلوب الجداول + inline CSS عشان يشتغل كويس في معظم برامج البريد
  // (ده أسلوب شائع ومُوصى به في HTML email) 
  return `
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="margin:0;padding:0;background:#f5f6f8;">
    <tr>
      <td align="center" style="padding:24px 12px;">
        <table role="presentation" width="600" cellpadding="0" cellspacing="0" style="width:600px;max-width:600px;background:#ffffff;border-radius:16px;overflow:hidden;border:1px solid #ececec;">
          ${LOGO_URL ? `
          <tr>
            <td style="padding:0;">
              <img src="${LOGO_URL}" alt="${BRAND_NAME}" width="600" style="display:block;width:100%;max-width:600px;height:auto;border:0;"/>
            </td>
          </tr>` : ""}

          <tr>
            <td style="padding:18px 18px 8px 18px;font-family:Arial,Helvetica,sans-serif;">
              <div style="font-size:18px;line-height:26px;font-weight:800;color:#111;">${BRAND_NAME}</div>
              <div style="font-size:13px;line-height:20px;color:#666;margin-top:6px;">${safeSubject}</div>
            </td>
          </tr>

          <tr>
            <td style="padding:0 18px 16px 18px;font-family:Arial,Helvetica,sans-serif;">
              <div style="font-size:15px;line-height:24px;color:#222;background:#f3f4f6;border-radius:14px;padding:14px;">
                ${safeMsg}
              </div>
              <div style="font-size:12px;line-height:18px;color:#777;margin-top:10px;">
                To: ${escapeHtml(toEmail)}
              </div>
            </td>
          </tr>

          <tr>
            <td align="center" style="padding:0 18px 18px 18px;">
              <a href="${BRAND_URL}" style="display:inline-block;text-decoration:none;font-family:Arial,Helvetica,sans-serif;font-size:14px;font-weight:800;padding:12px 16px;border-radius:12px;background:#111;color:#fff;">
                زيارة الموقع
              </a>
            </td>
          </tr>

          <tr>
            <td style="padding:14px 18px;background:#0b0b0b;font-family:Arial,Helvetica,sans-serif;">
              <div style="font-size:12px;line-height:18px;color:#cfcfcf;">
                © ${new Date().getFullYear()} ${BRAND_NAME}
              </div>
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
  `;
}

function signToken(payload) {
  // JWT معيار RFC 7519 
  return jwt.sign(payload, JWT_SECRET, { expiresIn: "2h" });
}

function verifyToken(token) {
  return jwt.verify(token, JWT_SECRET);
}

function authMiddleware(req, res, next) {
  const token = req.cookies?.auth_token;
  if (!token) return res.redirect("/login");

  try {
    const decoded = verifyToken(token);
    req.user = decoded;
    next();
  } catch {
    return res.redirect("/login");
  }
}

// ====== Static ======
app.use("/assets", express.static(path.join(PUBLIC_DIR, "assets")));

// ====== Pages ======
app.get("/", (req, res) => res.redirect("/dashboard"));

app.get("/login", (req, res) => {
  res.sendFile(path.join(PUBLIC_DIR, "login.html"));
});

app.get("/dashboard", authMiddleware, (req, res) => {
  res.sendFile(path.join(PUBLIC_DIR, "dashboard.html"));
});

// ====== Auth API ======
app.post("/api/auth/login", loginLimiter, async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) {
    return res.status(400).json({ ok: false, error: "Missing username/password" });
  }

  if (username !== ADMIN_USER) {
    return res.status(401).json({ ok: false, error: "Invalid credentials" });
  }

  const ok = await bcrypt.compare(String(password), ADMIN_PASS_HASH);
  if (!ok) {
    return res.status(401).json({ ok: false, error: "Invalid credentials" });
  }

  const token = signToken({ sub: ADMIN_USER, role: "admin" });

  // cookie httpOnly: المتصفح مش هيقدر يقرأ التوكن من JS (أفضل أمانًا) 
  res.cookie("auth_token", token, {
    httpOnly: true,
    sameSite: "lax",
    secure: true, // على Vercel HTTPS
    maxAge: 2 * 60 * 60 * 1000,
    path: "/",
  });

  return res.json({ ok: true });
});

app.post("/api/auth/logout", (req, res) => {
  res.clearCookie("auth_token", { path: "/" });
  res.json({ ok: true });
});

// ====== Send API ======
app.post("/api/send", authMiddleware, sendLimiter, async (req, res) => {
  try {
    const { toEmail, subject, message } = req.body || {};
    if (!toEmail || !message) {
      return res.status(400).json({ ok: false, error: "toEmail and message are required" });
    }

    if (String(message).length > 5000) {
      return res.status(400).json({ ok: false, error: "Message too long" });
    }

    const html = buildEmailHtml({ toEmail, message, subject });

    const info = await transporter.sendMail({
      from: `"${FROM_NAME}" <${FROM_EMAIL}>`,
      to: toEmail,
      subject: subject || `رسالة من ${BRAND_NAME}`,
      html,
      text: message,
    });

    // SMTP هو بروتوكول الإرسال القياسي 
    return res.json({ ok: true, messageId: info.messageId });
  } catch (err) {
    return res.status(500).json({ ok: false, error: err?.message || "Send failed" });
  }
});

// ====== Start ======
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Running on :${PORT}`));

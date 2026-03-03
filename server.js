import express from "express";
import dotenv from "dotenv";
import jwt from "jsonwebtoken";
import nodemailer from "nodemailer";
import cookieParser from "cookie-parser";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import fs from "fs/promises";
import path from "path";

dotenv.config();

const app = express();
app.set("trust proxy", 1);

app.use(
  helmet({
    contentSecurityPolicy: false,
  })
);
app.use(express.json({ limit: "200kb" }));
app.use(express.urlencoded({ extended: true, limit: "200kb" }));
app.use(cookieParser());

function mustEnv(name) {
  const v = process.env[name];
  if (!v) throw new Error(`Missing env: ${name}`);
  return v;
}

// ===== ENV =====
const JWT_SECRET = mustEnv("JWT_SECRET");
const ADMIN_USER = mustEnv("ADMIN_USER");
const ADMIN_PASS = mustEnv("ADMIN_PASS");

const SMTP_HOST = mustEnv("SMTP_HOST");
const SMTP_USER = mustEnv("SMTP_USER");
const SMTP_PASS = mustEnv("SMTP_PASS");
const SMTP_PORT = Number(process.env.SMTP_PORT || 587);
const SMTP_SECURE = String(process.env.SMTP_SECURE || "false").toLowerCase() === "true";

const BRAND_NAME = process.env.BRAND_NAME || "Clan TRIPxESPORTS";
const BRAND_URL = process.env.BRAND_URL || "https://clan-tripxesports.up.railway.app";
const LOGO_URL = process.env.LOGO_URL || "";
const FROM_NAME = process.env.FROM_NAME || BRAND_NAME;
const FROM_EMAIL = mustEnv("FROM_EMAIL");

// ===== Rate limits =====
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

// ===== SMTP =====
const transporter = nodemailer.createTransport({
  host: SMTP_HOST,
  port: SMTP_PORT,
  secure: SMTP_SECURE,
  auth: { user: SMTP_USER, pass: SMTP_PASS },
});

// ===== Helpers =====
function signToken(payload) {
  // JWT per RFC 7519 
  return jwt.sign(payload, JWT_SECRET, { expiresIn: "2h" });
}

function verifyToken(token) {
  return jwt.verify(token, JWT_SECRET);
}

function authMiddleware(req, res, next) {
  const token = req.cookies?.auth_token;
  if (!token) return res.redirect("/login");
  try {
    req.user = verifyToken(token);
    next();
  } catch {
    return res.redirect("/login");
  }
}

function escapeHtml(str = "") {
  return String(str)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

// Email HTML (tables + inline CSS) لعرض أفضل عبر عملاء البريد
function buildEmailHtml({ toEmail, subject, message }) {
  const safeMsg = escapeHtml(message).replaceAll("\n", "<br/>");
  const title = escapeHtml(subject || `رسالة من ${BRAND_NAME}`);

  // 🔥 اللوجو ثابت هنا
  const logo = "https://i.postimg.cc/0yvHTB0r/IMG-20260301-WA0034.jpg";

  return `
<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
</head>
<body style="margin:0;padding:0;background:#0f172a;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#0f172a;padding:30px 10px;">
    <tr>
      <td align="center">

        <table width="600" cellpadding="0" cellspacing="0" style="max-width:600px;background:#ffffff;border-radius:18px;overflow:hidden;">

          <!-- Header -->
          <tr>
            <td style="background:#111827;padding:20px;" align="left">
              <table width="100%">
                <tr>
                  <td style="vertical-align:middle;">
                    <img src="${logo}" width="50" style="border-radius:12px;display:block;" />
                  </td>
                  <td style="vertical-align:middle;padding-left:12px;font-family:Arial;color:#ffffff;">
                    <div style="font-size:18px;font-weight:bold;">
                      ${BRAND_NAME}
                    </div>
                    <div style="font-size:13px;color:#cbd5e1;margin-top:4px;">
                      ${title}
                    </div>
                  </td>
                </tr>
              </table>
            </td>
          </tr>

          <!-- Message -->
          <tr>
            <td style="padding:25px;font-family:Arial;color:#111827;">
              <div style="font-size:14px;color:#6b7280;margin-bottom:10px;">
                إلى: ${escapeHtml(toEmail)}
              </div>

              <div style="background:#f3f4f6;padding:18px;border-radius:14px;font-size:15px;line-height:24px;">
                ${safeMsg}
              </div>
            </td>
          </tr>

          <!-- Button -->
          <tr>
            <td align="center" style="padding-bottom:25px;">
              <a href="${BRAND_URL}"
                 style="background:#2563eb;color:#ffffff;padding:12px 20px;border-radius:12px;text-decoration:none;font-weight:bold;font-family:Arial;">
                زيارة الموقع
              </a>
            </td>
          </tr>

        </table>

        <!-- Footer -->
        <div style="color:#94a3b8;font-size:12px;margin-top:15px;font-family:Arial;">
          © ${new Date().getFullYear()} ${BRAND_NAME}
        </div>

      </td>
    </tr>
  </table>
</body>
</html>
`;
}

async function sendHtmlPage(res, filename) {
  // مهم على Vercel: اقرأ من process.cwd() + includeFiles في vercel.json
  const filePath = path.join(process.cwd(), filename);
  const html = await fs.readFile(filePath, "utf8");
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.send(html);
}

// ===== Pages =====
app.get("/", (req, res) => res.redirect("/dashboard"));

app.get("/login", async (req, res) => {
  try {
    await sendHtmlPage(res, "login.html");
  } catch (e) {
    res.status(500).send("Missing login.html (must be next to server.js + included in Vercel function)");
  }
});

app.get("/dashboard", authMiddleware, async (req, res) => {
  try {
    await sendHtmlPage(res, "dashboard.html");
  } catch (e) {
    res.status(500).send("Missing dashboard.html (must be next to server.js + included in Vercel function)");
  }
});

// ===== API: Auth =====
app.post("/api/auth/login", loginLimiter, async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) {
    return res.status(400).json({ ok: false, error: "Missing username/password" });
  }

  if (String(username) !== ADMIN_USER || String(password) !== ADMIN_PASS) {
    return res.status(401).json({ ok: false, error: "Invalid credentials" });
  }

  const token = signToken({ sub: ADMIN_USER, role: "admin" });

  res.cookie("auth_token", token, {
    httpOnly: true,
    sameSite: "lax",
    secure: true, // Vercel HTTPS
    maxAge: 2 * 60 * 60 * 1000,
    path: "/",
  });

  return res.json({ ok: true });
});

app.post("/api/auth/logout", (req, res) => {
  res.clearCookie("auth_token", { path: "/" });
  res.json({ ok: true });
});

// ===== API: Send =====
app.post("/api/send", authMiddleware, sendLimiter, async (req, res) => {
  try {
    const { toEmail, subject, message } = req.body || {};
    if (!toEmail || !message) {
      return res.status(400).json({ ok: false, error: "toEmail and message are required" });
    }
    if (String(message).length > 5000) {
      return res.status(400).json({ ok: false, error: "Message too long" });
    }

    const html = buildEmailHtml({ toEmail, subject, message });

    const info = await transporter.sendMail({
      from: `"${FROM_NAME}" <${FROM_EMAIL}>`,
      to: toEmail,
      subject: subject || `رسالة من ${BRAND_NAME}`,
      html,
      text: message,
    });

    // SMTP RFC 5321 
    return res.json({ ok: true, messageId: info.messageId });
  } catch (err) {
    return res.status(500).json({ ok: false, error: err?.message || "Send failed" });
  }
});

// ===== Start (Local only) =====
// على Vercel مش هيحتاج listen فعليًا، بس وجوده مش بيكسر محليًا.
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Running on :${PORT}`));

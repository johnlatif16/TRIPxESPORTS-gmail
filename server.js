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

  // لو مش حاطط LOGO_URL في env، هنستخدم اللينك اللي إنت بعته
  const logo = (LOGO_URL && String(LOGO_URL).trim())
    ? String(LOGO_URL).trim()
    : "https://postimg.cc/kBjc8wZd";

  // Preheader (بيظهر جنب عنوان الإيميل في inbox)
  const preheader = escapeHtml(
    (String(message || "").trim().slice(0, 90) || `رسالة جديدة من ${BRAND_NAME}`)
  );

  return `
<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>${title}</title>
</head>
<body style="margin:0;padding:0;background:#0b0f1a;">
  <!-- Preheader (hidden) -->
  <div style="display:none;max-height:0;overflow:hidden;opacity:0;color:transparent;">
    ${preheader}
  </div>

  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="margin:0;padding:0;background:#0b0f1a;">
    <tr>
      <td align="center" style="padding:28px 12px;">
        <table role="presentation" width="600" cellpadding="0" cellspacing="0" style="width:600px;max-width:600px;">
          <!-- Header -->
          <tr>
            <td style="padding:0 0 12px 0;">
              <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#111827;border-radius:18px;overflow:hidden;">
                <tr>
                  <td style="padding:16px 18px;" align="left">
                    <table role="presentation" cellpadding="0" cellspacing="0">
                      <tr>
                        <td style="vertical-align:middle;">
                          <img src="${logo}" width="44" height="44" alt="${escapeHtml(BRAND_NAME)}"
                               style="display:block;border:0;border-radius:12px;object-fit:cover;" />
                        </td>
                        <td style="vertical-align:middle;padding-left:12px;font-family:Arial,Helvetica,sans-serif;">
                          <div style="font-size:16px;line-height:22px;font-weight:800;color:#ffffff;">
                            ${escapeHtml(BRAND_NAME)}
                          </div>
                          <div style="font-size:12px;line-height:18px;color:#a7b0c0;margin-top:2px;">
                            ${title}
                          </div>
                        </td>
                      </tr>
                    </table>
                  </td>
                  <td style="padding:16px 18px;" align="right">
                    <a href="${BRAND_URL}"
                       style="font-family:Arial,Helvetica,sans-serif;font-size:12px;font-weight:800;color:#ffffff;text-decoration:none;background:#2563eb;padding:10px 12px;border-radius:12px;display:inline-block;">
                      زيارة الموقع
                    </a>
                  </td>
                </tr>
              </table>
            </td>
          </tr>

          <!-- Card -->
          <tr>
            <td>
              <table role="presentation" width="100%" cellpadding="0" cellspacing="0"
                     style="background:#ffffff;border-radius:18px;overflow:hidden;">
                <tr>
                  <td style="padding:20px 20px 10px 20px;font-family:Arial,Helvetica,sans-serif;">
                    <div style="font-size:14px;line-height:22px;color:#111827;font-weight:800;">
                      رسالة
                    </div>
                    <div style="font-size:12px;line-height:18px;color:#6b7280;margin-top:6px;">
                      إلى: ${escapeHtml(toEmail)}
                    </div>
                  </td>
                </tr>

                <tr>
                  <td style="padding:0 20px 20px 20px;font-family:Arial,Helvetica,sans-serif;">
                    <div style="background:#f3f4f6;border-radius:16px;padding:16px;font-size:14px;line-height:24px;color:#111827;">
                      ${safeMsg}
                    </div>
                  </td>
                </tr>

                <tr>
                  <td style="padding:0 20px 20px 20px;">
                    <table role="presentation" cellpadding="0" cellspacing="0">
                      <tr>
                        <td style="background:#111827;border-radius:14px;">
                          <a href="${BRAND_URL}"
                             style="display:inline-block;padding:12px 16px;font-family:Arial,Helvetica,sans-serif;font-size:13px;font-weight:800;color:#ffffff;text-decoration:none;">
                            فتح الموقع
                          </a>
                        </td>
                        <td style="padding-left:10px;font-family:Arial,Helvetica,sans-serif;font-size:12px;color:#6b7280;">
                          تم الإرسال من لوحة تحكم ${escapeHtml(BRAND_NAME)}
                        </td>
                      </tr>
                    </table>
                  </td>
                </tr>
              </table>
            </td>
          </tr>

          <!-- Footer -->
          <tr>
            <td style="padding:14px 6px 0 6px;font-family:Arial,Helvetica,sans-serif;color:#9ca3af;font-size:11px;line-height:16px;" align="center">
              © ${new Date().getFullYear()} ${escapeHtml(BRAND_NAME)} — جميع الحقوق محفوظة
            </td>
          </tr>

        </table>
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

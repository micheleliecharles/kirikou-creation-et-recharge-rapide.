const crypto = require("crypto");

const COOKIE_NAME = "admin_session";
const SESSION_DURATION = 8 * 60 * 60 * 1000; // 8 heures

function createSignature(timestamp, token) {
  return crypto
    .createHmac("sha256", token)
    .update(timestamp)
    .digest("hex");
}

function parseCookies(cookieHeader = "") {
  const cookies = {};

  cookieHeader.split(";").forEach((cookie) => {
    const [name, ...rest] = cookie.trim().split("=");
    if (name) {
      cookies[name] = rest.join("=");
    }
  });

  return cookies;
}

function validSession(req, token) {
  const cookies = parseCookies(req.headers.cookie);
  const session = cookies[COOKIE_NAME];

  if (!session) return false;

  const parts = session.split(".");
  if (parts.length !== 2) return false;

  const [timestamp, signature] = parts;
  const time = Number(timestamp);

  if (!Number.isFinite(time)) return false;

  if (Date.now() - time > SESSION_DURATION) return false;

  const expectedSignature = createSignature(timestamp, token);

  try {
    return crypto.timingSafeEqual(
      Buffer.from(signature),
      Buffer.from(expectedSignature)
    );
  } catch {
    return false;
  }
}

module.exports = async (req, res) => {
  const token = process.env.ADMIN_TOKEN;

  if (!token) {
    return res.status(500).json({
      success: false,
      message: "ADMIN_TOKEN n'est pas configuré sur Vercel."
    });
  }

  // Vérifier la session
  if (req.method === "GET") {
    const authenticated = validSession(req, token);

    return res.status(200).json({
      authenticated
    });
  }

  // Connexion
  if (req.method === "POST") {
    try {
      const { username, password } =
        typeof req.body === "string"
          ? JSON.parse(req.body)
          : req.body || {};

      if (username !== "admin" || password !== token) {
        return res.status(401).json({
          success: false,
          message: "Identifiant ou mot de passe incorrect."
        });
      }

      const timestamp = Date.now().toString();
      const signature = createSignature(timestamp, token);

      const isHttps =
        req.headers["x-forwarded-proto"] === "https" ||
        process.env.NODE_ENV === "production";

      const cookie = [
        `${COOKIE_NAME}=${timestamp}.${signature}`,
        "HttpOnly",
        "Path=/",
        "SameSite=Strict",
        `Max-Age=${SESSION_DURATION / 1000}`,
        isHttps ? "Secure" : ""
      ]
        .filter(Boolean)
        .join("; ");

      res.setHeader("Set-Cookie", cookie);
      res.setHeader("Cache-Control", "no-store");

      return res.status(200).json({
        success: true,
        message: "Connexion réussie."
      });
    } catch {
      return res.status(400).json({
        success: false,
        message: "Requête invalide."
      });
    }
  }

  // Déconnexion
  if (req.method === "DELETE") {
    res.setHeader(
      "Set-Cookie",
      `${COOKIE_NAME}=; HttpOnly; Path=/; SameSite=Strict; Max-Age=0`
    );

    return res.status(200).json({
      success: true
    });
  }

  res.setHeader("Allow", ["GET", "POST", "DELETE"]);

  return res.status(405).json({
    success: false,
    message: "Méthode non autorisée."
  });
};

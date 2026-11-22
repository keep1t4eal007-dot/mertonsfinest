import crypto from "node:crypto";
import { promisify } from "node:util";
import express from "express";
import session from "express-session";
import connectPgSimple from "connect-pg-simple";
import helmet from "helmet";
import pg from "pg";
import { rateLimit } from "express-rate-limit";
import { createServer } from "node:http";
import { Server as SocketServer } from "socket.io";
import path from "node:path";
import { execFile as execFileCallback } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";

const { Pool } = pg;
const scrypt = promisify(crypto.scrypt);
const execFile = promisify(execFileCallback);
const app = express();
const httpServer = createServer(app);
const port = Number(process.env.PORT || 3000);
const production = process.env.NODE_ENV === "production";
const sessionSecret = process.env.SESSION_SECRET || "";
const databaseUrl = process.env.DATABASE_URL || "";
const ownerSetupToken = process.env.OWNER_SETUP_TOKEN || "";
const ownerNotificationEmail = process.env.OWNER_NOTIFICATION_EMAIL || "";
const resendApiKey = process.env.RESEND_API_KEY || "";
const resendFromEmail = process.env.RESEND_FROM_EMAIL || "";
const frontendOrigins = new Set(
  (process.env.FRONTEND_ORIGINS || "https://project43331.websitepublisher.ai")
    .split(",").map(value => value.trim()).filter(Boolean)
);
if (!production) {
  frontendOrigins.add("http://localhost:3000");
  frontendOrigins.add("http://127.0.0.1:3000");
}
const MAX_TRACK_BYTES = 20 * 1024 * 1024;
const MAX_TRACK_STORAGE_BYTES = 600 * 1024 * 1024;
const MAX_MONTHLY_AUDIO_BYTES = 3500 * 1000 * 1000;
const MAX_TRACKS_PER_ARTIST = 20;
const AUDIO_MIME_BY_EXTENSION = {
  ".mp3": "audio/mpeg", ".wav": "audio/wav", ".m4a": "audio/mp4", ".aac": "audio/aac",
  ".ogg": "audio/ogg", ".flac": "audio/flac", ".opus": "audio/opus", ".webm": "audio/webm"
};

if (!databaseUrl) throw new Error("DATABASE_URL is required.");
if (sessionSecret.length < 32) throw new Error("SESSION_SECRET must be at least 32 characters.");

const pool = new Pool({
  connectionString: databaseUrl,
  max: 12,
  ssl: process.env.PGSSL === "true" ? true : undefined
});

app.disable("x-powered-by");
app.set("trust proxy", 1);
app.use(helmet({ contentSecurityPolicy: false, crossOriginResourcePolicy: false }));
app.use((req, res, next) => {
  const origin = req.get("origin");
  if (origin && frontendOrigins.has(origin)) {
    res.set("Access-Control-Allow-Origin", origin);
    res.set("Access-Control-Allow-Methods", "GET,POST,PATCH,DELETE,OPTIONS");
    res.set("Access-Control-Allow-Headers", "Content-Type,Authorization,X-File-Name");
    res.set("Access-Control-Max-Age", "600");
    res.vary("Origin");
  }
  if (req.method === "OPTIONS") {
    return origin && frontendOrigins.has(origin) ? res.sendStatus(204) : res.sendStatus(403);
  }
  next();
});
app.use(express.json({ limit: "512kb" }));
app.use("/api", (_req, res, next) => {
  res.set("Cache-Control", "no-store");
  next();
});

const PgStore = connectPgSimple(session);
const sessionMiddleware = session({
  store: new PgStore({
    pool,
    tableName: "sessions",
    createTableIfMissing: true
  }),
  name: "scene_session",
  secret: sessionSecret,
  resave: false,
  saveUninitialized: false,
  proxy: production,
  cookie: {
    httpOnly: true,
    secure: production,
    sameSite: "lax",
    maxAge: 1000 * 60 * 60 * 24 * 7
  }
});
app.use(sessionMiddleware);

const io = new SocketServer(httpServer, {
  serveClient: true,
  transports: ["websocket", "polling"],
  maxHttpBufferSize: 16 * 1024,
  cors: { origin: [...frontendOrigins], methods: ["GET", "POST"] },
  allowRequest: (req, callback) => {
    try {
      const origin = req.headers.origin;
      const host = req.headers.host;
      const localOrigin = Boolean(origin && host && new URL(origin).host === host);
      callback(null, Boolean(origin && (frontendOrigins.has(origin) || localOrigin)));
    } catch {
      callback(null, false);
    }
  }
});
io.engine.use(sessionMiddleware);

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 12,
  standardHeaders: "draft-8",
  legacyHeaders: false,
  message: { error: "Too many attempts. Please wait a little and try again." }
});
const publicContentLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 120,
  standardHeaders: "draft-8",
  legacyHeaders: false,
  message: { error: "Too many requests. Please wait a little and try again." }
});

function sameOrigin(req, res, next) {
  const origin = req.get("origin");
  const host = req.get("host");
  if (!origin || !host) return res.status(403).json({ error: "This request was blocked." });
  try {
    const parsed = new URL(origin);
    const localOrigin = parsed.host === host && (!production || parsed.protocol === "https:");
    if (!localOrigin && !frontendOrigins.has(origin)) {
      return res.status(403).json({ error: "This request was blocked." });
    }
  } catch {
    return res.status(403).json({ error: "This request was blocked." });
  }
  next();
}

function requireUser(req, res, next) {
  if (req.session?.userId) {
    req.userId = Number(req.session.userId);
    return next();
  }
  const match = /^Bearer\s+([A-Za-z0-9_-]{40,100})$/i.exec(req.get("authorization") || "");
  if (!match) return res.status(401).json({ error: "Sign in to continue." });
  const tokenHash = crypto.createHash("sha256").update(match[1]).digest("hex");
  pool.query("SELECT user_id FROM api_tokens WHERE token_hash=$1 AND expires_at>now()", [tokenHash])
    .then(result => {
      if (!result.rows[0]) return res.status(401).json({ error: "Your sign-in expired. Please sign in again." });
      req.userId = Number(result.rows[0].user_id);
      next();
    })
    .catch(next);
}

function currentUserId(req) {
  return Number(req.userId || req.session?.userId || 0);
}

async function requireOwner(req, res, next) {
  try {
    const result = await pool.query("SELECT role FROM artists WHERE id=$1", [currentUserId(req)]);
    if (result.rows[0]?.role !== "owner") return res.status(403).json({ error: "Owner access required." });
    next();
  } catch (error) { next(error); }
}

function bearerToken(req) {
  const match = /^Bearer\s+([A-Za-z0-9_-]{40,100})$/i.exec(req.get("authorization") || "");
  return match?.[1] || "";
}

async function issueApiToken(userId) {
  const token = crypto.randomBytes(32).toString("base64url");
  const tokenHash = crypto.createHash("sha256").update(token).digest("hex");
  await pool.query("DELETE FROM api_tokens WHERE expires_at<=now()");
  await pool.query(
    "INSERT INTO api_tokens (token_hash,user_id,expires_at) VALUES ($1,$2,now()+interval '14 days')",
    [tokenHash, userId]
  );
  return token;
}

function asyncRoute(handler) {
  return (req, res, next) => Promise.resolve(handler(req, res, next)).catch(next);
}

async function notifyOwner(subject, lines) {
  if (!ownerNotificationEmail || !resendApiKey || !resendFromEmail) {
    console.warn("Owner email notifications are disabled until their sender settings are configured.");
    return;
  }
  const response = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: { Authorization: "Bearer " + resendApiKey, "Content-Type": "application/json" },
    body: JSON.stringify({
      from: resendFromEmail,
      to: [ownerNotificationEmail],
      subject: subject.slice(0, 180),
      text: lines.join("\n").slice(0, 6000)
    }),
    signal: AbortSignal.timeout(8000)
  });
  if (!response.ok) throw new Error("Email provider returned HTTP " + response.status);
}

async function notifyOwnerSafely(subject, lines) {
  try { await notifyOwner(subject, lines); }
  catch (error) { console.error("Owner email notification failed:", error.message); }
}

function safeUser(row) {
  return {
    id: Number(row.id),
    displayName: row.display_name,
    handle: row.handle,
    genre: row.genre,
    city: row.city,
    looking: row.looking || "",
    bio: row.bio || "",
    color: row.profile_color || "#d8e4d2",
    photo: row.profile_photo || "",
    role: row.role || "artist"
  };
}

function validEmail(value) {
  return typeof value === "string" && value.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
}

function cleanString(value, max) {
  return typeof value === "string" ? value.trim().slice(0, max) : "";
}

function positiveId(value) {
  const id = Number(value);
  return Number.isSafeInteger(id) && id > 0 ? id : null;
}

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function regenerateSession(req) {
  return new Promise((resolve, reject) => {
    req.session.regenerate(error => error ? reject(error) : resolve());
  });
}

function saveSession(req) {
  return new Promise((resolve, reject) => {
    req.session.save(error => error ? reject(error) : resolve());
  });
}

async function hashPassword(password, salt) {
  const derived = await scrypt(password, salt, 64, { N: 16384, r: 8, p: 1, maxmem: 64 * 1024 * 1024 });
  return Buffer.from(derived).toString("hex");
}

async function passwordsMatch(password, salt, storedHash) {
  const derived = Buffer.from(await hashPassword(password, salt), "hex");
  const expected = Buffer.from(storedHash, "hex");
  return derived.length === expected.length && crypto.timingSafeEqual(derived, expected);
}

async function prepareDatabase() {
  await pool.query(
    "CREATE TABLE IF NOT EXISTS artists (" +
    "id BIGSERIAL PRIMARY KEY, email TEXT NOT NULL UNIQUE, display_name TEXT NOT NULL, " +
    "handle TEXT NOT NULL UNIQUE, genre TEXT NOT NULL, city TEXT NOT NULL, " +
    "password_salt TEXT NOT NULL, password_hash TEXT NOT NULL, looking TEXT NOT NULL DEFAULT '', bio TEXT NOT NULL DEFAULT '', " +
    "profile_color TEXT NOT NULL DEFAULT '#d8e4d2', profile_photo TEXT NOT NULL DEFAULT '', role TEXT NOT NULL DEFAULT 'artist', " +
    "created_at TIMESTAMPTZ NOT NULL DEFAULT now())"
  );
  await pool.query("ALTER TABLE artists ADD COLUMN IF NOT EXISTS looking TEXT NOT NULL DEFAULT ''");
  await pool.query("ALTER TABLE artists ADD COLUMN IF NOT EXISTS bio TEXT NOT NULL DEFAULT ''");
  await pool.query("ALTER TABLE artists ADD COLUMN IF NOT EXISTS profile_color TEXT NOT NULL DEFAULT '#d8e4d2'");
  await pool.query("ALTER TABLE artists ADD COLUMN IF NOT EXISTS profile_photo TEXT NOT NULL DEFAULT ''");
  await pool.query("ALTER TABLE artists ADD COLUMN IF NOT EXISTS role TEXT NOT NULL DEFAULT 'artist'");
  await pool.query("CREATE UNIQUE INDEX IF NOT EXISTS artists_single_owner_idx ON artists(role) WHERE role='owner'");
  await pool.query(
    "CREATE TABLE IF NOT EXISTS api_tokens (" +
    "token_hash TEXT PRIMARY KEY, user_id BIGINT NOT NULL REFERENCES artists(id) ON DELETE CASCADE, " +
    "expires_at TIMESTAMPTZ NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT now())"
  );
  await pool.query("CREATE INDEX IF NOT EXISTS api_tokens_expiry_idx ON api_tokens(expires_at)");
  await pool.query(
    "CREATE TABLE IF NOT EXISTS tracks (" +
    "id UUID PRIMARY KEY, artist_id BIGINT NOT NULL REFERENCES artists(id) ON DELETE CASCADE, " +
    "title TEXT NOT NULL CHECK (char_length(title) BETWEEN 1 AND 60), file_name TEXT NOT NULL, " +
    "mime_type TEXT NOT NULL, duration_seconds DOUBLE PRECISION NOT NULL CHECK (duration_seconds > 0 AND duration_seconds <= 600), " +
    "audio BYTEA NOT NULL, moderation_status TEXT NOT NULL DEFAULT 'pending', created_at TIMESTAMPTZ NOT NULL DEFAULT now())"
  );
  await pool.query("ALTER TABLE tracks ADD COLUMN IF NOT EXISTS moderation_status TEXT");
  await pool.query("UPDATE tracks SET moderation_status='approved' WHERE moderation_status IS NULL");
  await pool.query("ALTER TABLE tracks ALTER COLUMN moderation_status SET DEFAULT 'pending'");
  await pool.query("ALTER TABLE tracks ALTER COLUMN moderation_status SET NOT NULL");
  await pool.query("CREATE INDEX IF NOT EXISTS tracks_moderation_idx ON tracks(moderation_status,created_at DESC)");
  await pool.query("CREATE INDEX IF NOT EXISTS tracks_created_idx ON tracks(created_at DESC)");
  await pool.query("CREATE INDEX IF NOT EXISTS tracks_artist_idx ON tracks(artist_id,created_at DESC)");
  await pool.query(
    "CREATE TABLE IF NOT EXISTS audio_usage (" +
    "month_start DATE PRIMARY KEY, bytes BIGINT NOT NULL DEFAULT 0 CHECK (bytes >= 0))"
  );
  await pool.query(
    "CREATE TABLE IF NOT EXISTS conversations (" +
    "id UUID PRIMARY KEY, type TEXT NOT NULL CHECK (type IN ('direct','group')), " +
    "name TEXT NOT NULL DEFAULT '', direct_key TEXT UNIQUE, " +
    "created_at TIMESTAMPTZ NOT NULL DEFAULT now(), updated_at TIMESTAMPTZ NOT NULL DEFAULT now())"
  );
  await pool.query(
    "CREATE TABLE IF NOT EXISTS conversation_members (" +
    "conversation_id UUID NOT NULL REFERENCES conversations(id) ON DELETE CASCADE, " +
    "user_id BIGINT NOT NULL REFERENCES artists(id) ON DELETE CASCADE, " +
    "joined_at TIMESTAMPTZ NOT NULL DEFAULT now(), PRIMARY KEY (conversation_id,user_id))"
  );
  await pool.query(
    "CREATE TABLE IF NOT EXISTS messages (" +
    "id BIGSERIAL PRIMARY KEY, conversation_id UUID NOT NULL REFERENCES conversations(id) ON DELETE CASCADE, " +
    "sender_id BIGINT NOT NULL REFERENCES artists(id) ON DELETE CASCADE, " +
    "body TEXT NOT NULL CHECK (char_length(body) BETWEEN 1 AND 2000), client_id UUID, " +
    "created_at TIMESTAMPTZ NOT NULL DEFAULT now())"
  );
  await pool.query("ALTER TABLE messages ADD COLUMN IF NOT EXISTS client_id UUID");
  await pool.query("CREATE INDEX IF NOT EXISTS conversation_members_user_idx ON conversation_members(user_id, conversation_id)");
  await pool.query("CREATE INDEX IF NOT EXISTS messages_conversation_idx ON messages(conversation_id, id DESC)");
  await pool.query("CREATE UNIQUE INDEX IF NOT EXISTS messages_sender_client_id_idx ON messages(sender_id, client_id) WHERE client_id IS NOT NULL");
  await pool.query("CREATE INDEX IF NOT EXISTS artists_directory_idx ON artists(display_name)");
}

app.get("/api/health", (_req, res) => res.json({ ok: true }));

app.get("/api/auth/me", asyncRoute(async (req, res) => {
  const token = bearerToken(req);
  let userId = req.session?.userId ? Number(req.session.userId) : 0;
  if (token) {
    const tokenHash = crypto.createHash("sha256").update(token).digest("hex");
    const tokenResult = await pool.query(
      "SELECT user_id FROM api_tokens WHERE token_hash=$1 AND expires_at>now()",
      [tokenHash]
    );
    userId = tokenResult.rows[0] ? Number(tokenResult.rows[0].user_id) : 0;
  }
  if (!userId) return res.json({ user: null });
  const result = await pool.query(
    "SELECT id,display_name,handle,genre,city,looking,bio,profile_color,profile_photo,role FROM artists WHERE id = $1",
    [userId]
  );
  if (!result.rows[0]) {
    req.session?.destroy(() => {});
    return res.json({ user: null });
  }
  res.json({ user: safeUser(result.rows[0]) });
}));

app.post(["/api/auth/register", "/api/auth/owner-setup"], sameOrigin, authLimiter, asyncRoute(async (req, res) => {
  const ownerClaim = req.path === "/api/auth/owner-setup";
  if (ownerClaim) {
    const supplied = typeof req.body.ownerSetupToken === "string" ? req.body.ownerSetupToken : "";
    const expected = Buffer.from(ownerSetupToken);
    const received = Buffer.from(supplied);
    if (!ownerSetupToken || expected.length !== received.length || !crypto.timingSafeEqual(expected, received)) {
      return res.status(403).json({ error: "The owner setup code is invalid." });
    }
    const owners = await pool.query("SELECT 1 FROM artists WHERE role='owner' LIMIT 1");
    if (owners.rows.length) return res.status(409).json({ error: "The owner account has already been claimed." });
  }
  const displayName = cleanString(req.body.displayName, 60);
  const handle = cleanString(req.body.handle, 24).toLowerCase().replace(/^@/, "");
  const genre = cleanString(req.body.genre, 60);
  const city = cleanString(req.body.city, 80);
  const email = cleanString(req.body.email, 254).toLowerCase();
  const password = typeof req.body.password === "string" ? req.body.password : "";
  if (displayName.length < 2 || !/^[a-z0-9_]{3,24}$/.test(handle) || !genre || !city ||
      !validEmail(email) || password.length < 12 || password.length > 200) {
    return res.status(400).json({ error: "Check the fields. Passwords need at least 12 characters." });
  }
  const salt = crypto.randomBytes(16).toString("hex");
  const passwordHash = await hashPassword(password, salt);
  let created;
  try {
    created = await pool.query(
      "INSERT INTO artists (email,display_name,handle,genre,city,password_salt,password_hash,role) " +
      "VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id,display_name,handle,genre,city,looking,bio,profile_color,profile_photo,role",
      [email, displayName, handle, genre, city, salt, passwordHash, ownerClaim ? "owner" : "artist"]
    );
  } catch (error) {
    if (error.code === "23505") return res.status(409).json({ error: ownerClaim ? "The owner account has already been claimed." : "That email or handle is already in use." });
    throw error;
  }
  await regenerateSession(req);
  req.session.userId = Number(created.rows[0].id);
  await saveSession(req);
  const token = await issueApiToken(created.rows[0].id);
  await notifyOwnerSafely("New SceneSpool account", [
    "A new account was created on SceneSpool.",
    "Artist name: " + displayName,
    "Handle: @" + handle,
    "Account type: " + (ownerClaim ? "Owner" : "Artist")
  ]);
  res.status(201).json({ user: safeUser(created.rows[0]), token });
}));

app.post("/api/auth/login", sameOrigin, authLimiter, asyncRoute(async (req, res) => {
  const email = cleanString(req.body.email, 254).toLowerCase();
  const password = typeof req.body.password === "string" ? req.body.password : "";
  if (!validEmail(email) || !password || password.length > 200) {
    return res.status(400).json({ error: "Enter a valid email and password." });
  }
  const result = await pool.query(
    "SELECT id,email,display_name,handle,genre,city,looking,bio,profile_color,profile_photo,password_salt,password_hash,role FROM artists WHERE email = $1",
    [email]
  );
  const artist = result.rows[0];
  if (!artist || !(await passwordsMatch(password, artist.password_salt, artist.password_hash))) {
    return res.status(401).json({ error: "Email or password did not match." });
  }
  await regenerateSession(req);
  req.session.userId = Number(artist.id);
  await saveSession(req);
  const token = await issueApiToken(artist.id);
  res.json({ user: safeUser(artist), token });
}));

app.post("/api/auth/logout", sameOrigin, requireUser, asyncRoute(async (req, res) => {
  const token = bearerToken(req);
  if (token) {
    const tokenHash = crypto.createHash("sha256").update(token).digest("hex");
    await pool.query("DELETE FROM api_tokens WHERE token_hash=$1", [tokenHash]);
  }
  if (req.session) {
    await new Promise((resolve, reject) => req.session.destroy(error => error ? reject(error) : resolve()));
  }
  res.clearCookie("scene_session", { httpOnly: true, secure: production, sameSite: "lax" });
  res.json({ ok: true });
}));

app.delete("/api/auth/account", sameOrigin, requireUser, asyncRoute(async (req, res) => {
  const userId = currentUserId(req);
  const password = typeof req.body.password === "string" ? req.body.password : "";
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const result = await client.query(
      "SELECT password_salt,password_hash FROM artists WHERE id=$1 FOR UPDATE",
      [userId]
    );
    const artist = result.rows[0];
    if (!artist || !(await passwordsMatch(password, artist.password_salt, artist.password_hash))) {
      await client.query("ROLLBACK");
      return res.status(401).json({ error: "Enter your sign-in password to delete this account." });
    }
    await client.query("DELETE FROM artists WHERE id=$1", [userId]);
    await client.query(
      "DELETE FROM conversations c WHERE NOT EXISTS " +
      "(SELECT 1 FROM conversation_members cm WHERE cm.conversation_id=c.id) OR " +
      "(c.type='direct' AND (SELECT count(*) FROM conversation_members cm WHERE cm.conversation_id=c.id)<2)"
    );
    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
  try { await pool.query("DELETE FROM sessions WHERE sess->>'userId'=$1", [String(userId)]); }
  catch (error) { if (error.code !== "42P01") throw error; }
  if (req.session) {
    await new Promise((resolve, reject) => req.session.destroy(error => error ? reject(error) : resolve()));
  }
  res.clearCookie("scene_session", { httpOnly: true, secure: production, sameSite: "lax" });
  res.json({ deleted: true });
}));

app.get("/api/artists", publicContentLimiter, asyncRoute(async (req, res) => {
  const search = cleanString(req.query.search, 80);
  const result = await pool.query(
    "SELECT id,display_name,handle,genre,city,looking,bio,profile_color,profile_photo FROM artists " +
    "WHERE role='artist' AND ($1 = '' OR display_name ILIKE '%' || $1 || '%' OR handle ILIKE '%' || $1 || '%' " +
    "OR genre ILIKE '%' || $1 || '%' OR city ILIKE '%' || $1 || '%') " +
    "ORDER BY display_name LIMIT 100",
    [search]
  );
  res.json({ artists: result.rows.map(safeUser) });
}));

app.get("/api/artists/me", requireUser, asyncRoute(async (req, res) => {
  const result = await pool.query(
    "SELECT id,display_name,handle,genre,city,looking,bio,profile_color,profile_photo,role FROM artists WHERE id=$1",
    [currentUserId(req)]
  );
  if (!result.rows[0]) return res.status(404).json({ error: "Artist account not found." });
  res.json({ artist: safeUser(result.rows[0]) });
}));

app.patch("/api/artists/me", sameOrigin, requireUser, asyncRoute(async (req, res) => {
  const displayName = cleanString(req.body.displayName, 60);
  const handle = cleanString(req.body.handle, 24).toLowerCase().replace(/^@/, "");
  const genre = cleanString(req.body.genre, 60);
  const city = cleanString(req.body.city, 80);
  const looking = cleanString(req.body.looking, 160);
  const bio = cleanString(req.body.bio, 500);
  const profileColor = cleanString(req.body.color, 7);
  const profilePhoto = typeof req.body.photo === "string" ? req.body.photo : "";
  if (displayName.length < 2 || !/^[a-z0-9_]{3,24}$/.test(handle) || !genre || !city ||
      !/^#[0-9a-f]{6}$/i.test(profileColor) ||
      (profilePhoto && !/^data:image\/jpeg;base64,[A-Za-z0-9+/=]{1,400000}$/.test(profilePhoto))) {
    return res.status(400).json({ error: "Check your profile details and try again." });
  }
  try {
    const result = await pool.query(
      "UPDATE artists SET display_name=$1,handle=$2,genre=$3,city=$4,looking=$5,bio=$6,profile_color=$7,profile_photo=$8 " +
      "WHERE id=$9 RETURNING id,display_name,handle,genre,city,looking,bio,profile_color,profile_photo,role",
      [displayName, handle, genre, city, looking, bio, profileColor, profilePhoto, currentUserId(req)]
    );
    if (!result.rows[0]) return res.status(404).json({ error: "Artist account not found." });
    res.json({ artist: safeUser(result.rows[0]) });
  } catch (error) {
    if (error.code === "23505") return res.status(409).json({ error: "That artist name is already in use." });
    throw error;
  }
}));

function publicTrack(row) {
  return {
    id: row.id,
    artistId: Number(row.artist_id),
    artistName: row.display_name,
    artistHandle: row.handle,
    title: row.title,
    fileName: row.file_name,
    mimeType: row.mime_type,
    duration: Number(row.duration_seconds),
    addedAt: row.created_at,
    audioUrl: "/api/tracks/" + row.id + "/audio"
  };
}

async function inspectAudioDuration(buffer, fileName) {
  const extension = (path.extname(fileName).toLowerCase().replace(/[^.a-z0-9]/g, "") || ".audio");
  const directory = await mkdtemp(path.join(tmpdir(), "scenespool-audio-"));
  const audioPath = path.join(directory, "upload" + extension);
  try {
    await writeFile(audioPath, buffer);
    const result = await execFile(
      "ffprobe",
      ["-v", "error", "-show_entries", "format=duration", "-of", "default=noprint_wrappers=1:nokey=1", audioPath],
      { timeout: 15000, maxBuffer: 4096 }
    );
    const duration = Number(result.stdout.trim());
    if (!Number.isFinite(duration) || duration <= 0) throw new Error("The audio file duration could not be read.");
    return duration;
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

const trackUploadLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  limit: 8,
  keyGenerator: req => String(currentUserId(req)),
  standardHeaders: "draft-8",
  legacyHeaders: false,
  message: { error: "Upload limit reached. Please try again later." }
});
app.get("/api/tracks", publicContentLimiter, asyncRoute(async (_req, res) => {
  const result = await pool.query(
    "SELECT t.id,t.artist_id,t.title,t.file_name,t.mime_type,t.duration_seconds,t.created_at, " +
    "a.display_name,a.handle FROM tracks t JOIN artists a ON a.id=t.artist_id WHERE t.moderation_status='approved' ORDER BY t.created_at DESC LIMIT 200"
  );
  res.json({ tracks: result.rows.map(publicTrack) });
}));

app.post("/api/tracks", sameOrigin, requireUser, trackUploadLimiter,
  express.raw({ type: () => true, limit: MAX_TRACK_BYTES }), asyncRoute(async (req, res) => {
    const title = cleanString(req.query.title, 60);
    let fileName = cleanString(req.get("x-file-name"), 120);
    try { fileName = decodeURIComponent(fileName); } catch {}
    fileName = path.basename(fileName).replace(/[\r\n\0]/g, "");
    const bytes = req.body;
    if (!title || !fileName || !Buffer.isBuffer(bytes) || bytes.length < 1024) {
      return res.status(400).json({ error: "Choose an audio file and enter a track title." });
    }
    const extension = path.extname(fileName).toLowerCase();
    const allowedExtensions = new Set([".mp3", ".wav", ".m4a", ".aac", ".ogg", ".flac", ".opus", ".webm"]);
    if (!allowedExtensions.has(extension)) return res.status(415).json({ error: "Use an MP3, WAV, M4A, AAC, OGG, FLAC, OPUS or WEBM audio file." });
    let duration;
    try {
      duration = await inspectAudioDuration(bytes, fileName);
    } catch (error) {
      if (error.code === "ENOENT") return res.status(503).json({ error: "Audio checking is temporarily unavailable." });
      return res.status(400).json({ error: "This audio file could not be checked. Try another file." });
    }
    if (duration > 600) return res.status(400).json({ error: "Tracks must be 10 minutes or shorter." });
    const artistId = currentUserId(req);
    const limits = await pool.query(
      "SELECT count(*)::int AS tracks,COALESCE(sum(octet_length(audio)),0)::bigint AS bytes FROM tracks"
    );
    const ownCount = await pool.query("SELECT count(*)::int AS tracks FROM tracks WHERE artist_id=$1", [artistId]);
    if (Number(ownCount.rows[0].tracks) >= MAX_TRACKS_PER_ARTIST) {
      return res.status(409).json({ error: "Your artist profile has reached its 20-track limit." });
    }
    if (Number(limits.rows[0].bytes) + bytes.length > MAX_TRACK_STORAGE_BYTES) {
      return res.status(507).json({ error: "The shared music shelf has reached its storage limit." });
    }
    const mimeType = cleanString(req.get("content-type"), 80).split(";")[0].toLowerCase();
    const normalizedMime = mimeType.startsWith("audio/") ? mimeType : AUDIO_MIME_BY_EXTENSION[extension];
    const saved = await pool.query(
      "INSERT INTO tracks (id,artist_id,title,file_name,mime_type,duration_seconds,audio) " +
      "VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING id,artist_id,title,file_name,mime_type,duration_seconds,created_at",
      [crypto.randomUUID(), artistId, title, fileName, normalizedMime, duration, bytes]
    );
    const artist = await pool.query("SELECT display_name,handle FROM artists WHERE id=$1", [artistId]);
    await notifyOwnerSafely("Track uploaded for SceneSpool review", [
      "A new track was uploaded and is waiting for owner review.",
      "Track: " + title,
      "Artist: " + artist.rows[0].display_name + " (@" + artist.rows[0].handle + ")",
      "Duration: " + Math.floor(duration / 60) + ":" + String(Math.floor(duration % 60)).padStart(2, "0"),
      "File: " + fileName,
      "Review it in the SceneSpool music shelf."
    ]);
    res.status(201).json({ track: publicTrack({ ...saved.rows[0], ...artist.rows[0] }) });
  })
);

app.get("/api/tracks/manage", requireUser, asyncRoute(async (req, res) => {
  const result = await pool.query(
    "SELECT t.id,t.artist_id,t.title,t.file_name,t.mime_type,t.duration_seconds,t.created_at,t.moderation_status, " +
    "a.display_name,a.handle FROM tracks t JOIN artists a ON a.id=t.artist_id WHERE t.artist_id=$1 ORDER BY t.created_at DESC",
    [currentUserId(req)]
  );
  res.json({ tracks: result.rows.map(row => ({ ...publicTrack(row), status: row.moderation_status })) });
}));

app.get("/api/owner/tracks", requireUser, requireOwner, asyncRoute(async (_req, res) => {
  const result = await pool.query(
    "SELECT t.id,t.artist_id,t.title,t.file_name,t.mime_type,t.duration_seconds,t.created_at,t.moderation_status, " +
    "a.display_name,a.handle FROM tracks t JOIN artists a ON a.id=t.artist_id WHERE t.moderation_status='pending' ORDER BY t.created_at ASC LIMIT 100"
  );
  res.json({ tracks: result.rows.map(row => ({ ...publicTrack(row), status: row.moderation_status })) });
}));

app.patch("/api/owner/tracks/:trackId", sameOrigin, requireUser, requireOwner, asyncRoute(async (req, res) => {
  const status = req.body.status;
  if (!/^[0-9a-f-]{36}$/i.test(req.params.trackId) || !["approved", "rejected"].includes(status)) {
    return res.status(400).json({ error: "Choose approve or reject for this track." });
  }
  const result = await pool.query(
    "UPDATE tracks SET moderation_status=$1 WHERE id=$2 AND moderation_status='pending' RETURNING id",
    [status, req.params.trackId]
  );
  if (!result.rows[0]) return res.status(404).json({ error: "This pending track was not found." });
  res.json({ updated: true, status });
}));

app.get("/api/tracks/:trackId/audio", publicContentLimiter, asyncRoute(async (req, res) => {
  if (!/^[0-9a-f-]{36}$/i.test(req.params.trackId)) return res.status(404).end();
  const result = await pool.query(
    "SELECT audio,mime_type,file_name FROM tracks WHERE id=$1 AND moderation_status='approved'",
    [req.params.trackId]
  );
  const row = result.rows[0];
  if (!row) return res.status(404).end();
  const buffer = row.audio;
  const range = req.get("range");
  res.set("Accept-Ranges", "bytes");
  res.set("Content-Type", row.mime_type);
  res.set("Content-Disposition", "inline; filename*=UTF-8''" + encodeURIComponent(row.file_name));
  res.set("Cache-Control", "public, max-age=3600");
  if (range) {
    const match = /^bytes=(\d*)-(\d*)$/.exec(range);
    if (!match) return res.status(416).set("Content-Range", "bytes */" + buffer.length).end();
    let start = match[1] ? Number(match[1]) : Math.max(0, buffer.length - Number(match[2] || 0));
    let end = match[2] && match[1] ? Number(match[2]) : buffer.length - 1;
    if (!Number.isSafeInteger(start) || !Number.isSafeInteger(end) || start < 0 || end < start || start >= buffer.length) {
      return res.status(416).set("Content-Range", "bytes */" + buffer.length).end();
    }
    end = Math.min(end, buffer.length - 1);
    if (!(await reserveAudioBandwidth(end - start + 1))) {
      return res.status(429).json({ error: "The monthly shared-music listening allowance has been reached." });
    }
    res.status(206).set("Content-Range", `bytes ${start}-${end}/${buffer.length}`);
    res.set("Content-Length", String(end - start + 1));
    return res.end(buffer.subarray(start, end + 1));
  }
  if (!(await reserveAudioBandwidth(buffer.length))) {
    return res.status(429).json({ error: "The monthly shared-music listening allowance has been reached." });
  }
  res.set("Content-Length", String(buffer.length));
  res.end(buffer);
}));

app.delete("/api/tracks/:trackId", sameOrigin, requireUser, asyncRoute(async (req, res) => {
  if (!/^[0-9a-f-]{36}$/i.test(req.params.trackId)) return res.status(404).json({ error: "Track not found." });
  const removed = await pool.query(
    "DELETE FROM tracks WHERE id=$1 AND artist_id=$2 RETURNING id",
    [req.params.trackId, currentUserId(req)]
  );
  if (!removed.rows[0]) return res.status(404).json({ error: "Track not found." });
  res.json({ removed: true });
}));

app.get("/api/conversations", requireUser, asyncRoute(async (req, res) => {
  const result = await pool.query(
    "SELECT c.id,c.type,c.name,c.created_at,c.updated_at, " +
    "COALESCE((SELECT json_agg(json_build_object('id',a.id,'displayName',a.display_name,'handle',a.handle) " +
    "ORDER BY a.display_name) FROM conversation_members cm JOIN artists a ON a.id=cm.user_id " +
    "WHERE cm.conversation_id=c.id),'[]'::json) AS participants, " +
    "(SELECT json_build_object('id',m.id,'text',m.body,'senderId',m.sender_id,'senderName',a.display_name,'createdAt',m.created_at) " +
    "FROM messages m JOIN artists a ON a.id=m.sender_id WHERE m.conversation_id=c.id ORDER BY m.id DESC LIMIT 1) AS latest " +
    "FROM conversations c JOIN conversation_members own ON own.conversation_id=c.id " +
    "WHERE own.user_id=$1 ORDER BY c.updated_at DESC LIMIT 100",
    [currentUserId(req)]
  );
  const conversations = result.rows.map(row => {
    const participants = row.participants || [];
    const others = participants.filter(person => Number(person.id) !== currentUserId(req));
    return {
      id: row.id,
      type: row.type,
      name: row.name,
      title: row.type === "group" ? row.name : (others[0]?.displayName || "Direct message"),
      participants,
      latest: row.latest || null,
      createdAt: row.created_at,
      updatedAt: row.updated_at
    };
  });
  res.json({ conversations });
}));

app.post("/api/conversations/direct", sameOrigin, requireUser, asyncRoute(async (req, res) => {
  const otherId = positiveId(req.body.artistId);
  const userId = currentUserId(req);
  if (!otherId || otherId === userId) return res.status(400).json({ error: "Choose another artist." });
  const exists = await pool.query("SELECT id FROM artists WHERE id=$1", [otherId]);
  if (!exists.rows[0]) return res.status(404).json({ error: "That artist account was not found." });
  const directKey = [userId, otherId].sort((a, b) => a - b).join(":");
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    let result = await client.query(
      "INSERT INTO conversations (id,type,direct_key) VALUES ($1,'direct',$2) " +
      "ON CONFLICT (direct_key) DO NOTHING RETURNING id",
      [crypto.randomUUID(), directKey]
    );
    let conversationId = result.rows[0]?.id;
    if (!conversationId) {
      result = await client.query("SELECT id FROM conversations WHERE direct_key=$1", [directKey]);
      conversationId = result.rows[0].id;
    }
    await client.query(
      "INSERT INTO conversation_members (conversation_id,user_id) VALUES ($1,$2),($1,$3) ON CONFLICT DO NOTHING",
      [conversationId, userId, otherId]
    );
    await client.query("COMMIT");
    res.status(200).json({ conversationId });
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}));

app.post("/api/conversations/group", sameOrigin, requireUser, asyncRoute(async (req, res) => {
  const userId = currentUserId(req);
  const participantIds = Array.isArray(req.body.participantIds)
    ? [...new Set(req.body.participantIds.map(positiveId).filter(Boolean))]
    : [];
  const otherIds = participantIds.filter(id => id !== userId);
  if (otherIds.length < 1 || otherIds.length > 19) {
    return res.status(400).json({ error: "Choose between one and 19 other artists for a group chat." });
  }
  const ids = [...new Set([userId, ...otherIds])];
  const members = await pool.query(
    "SELECT id,display_name FROM artists WHERE id=ANY($1::bigint[])",
    [ids]
  );
  if (members.rows.length !== ids.length) {
    return res.status(400).json({ error: "One of those artist accounts could not be found." });
  }
  const requestedName = cleanString(req.body.name, 50);
  const participantNames = members.rows.filter(row => Number(row.id) !== userId).map(row => row.display_name);
  const name = requestedName || participantNames.slice(0, 3).join(" & ") +
    (participantNames.length > 3 ? " +" + (participantNames.length - 3) : "");
  const conversationId = crypto.randomUUID();
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await client.query(
      "INSERT INTO conversations (id,type,name) VALUES ($1,'group',$2)",
      [conversationId, name]
    );
    for (const memberId of ids) {
      await client.query(
        "INSERT INTO conversation_members (conversation_id,user_id) VALUES ($1,$2)",
        [conversationId, memberId]
      );
    }
    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
  res.status(201).json({ conversationId });
}));

async function isMember(conversationId, userId) {
  const result = await pool.query(
    "SELECT 1 FROM conversation_members WHERE conversation_id=$1 AND user_id=$2",
    [conversationId, userId]
  );
  return Boolean(result.rows[0]);
}

async function reserveAudioBandwidth(bytes) {
  const monthStart = new Date().toISOString().slice(0, 7) + "-01";
  const result = await pool.query(
    "INSERT INTO audio_usage (month_start,bytes) VALUES ($1,$2) " +
    "ON CONFLICT (month_start) DO UPDATE SET bytes=audio_usage.bytes+EXCLUDED.bytes " +
    "WHERE audio_usage.bytes+EXCLUDED.bytes <= $3 RETURNING bytes",
    [monthStart, bytes, MAX_MONTHLY_AUDIO_BYTES]
  );
  return Boolean(result.rows[0]);
}

app.get("/api/conversations/:conversationId/messages", requireUser, asyncRoute(async (req, res) => {
  const conversationId = req.params.conversationId;
  if (!/^[0-9a-f-]{36}$/i.test(conversationId)) return res.status(404).json({ error: "Conversation not found." });
  if (!(await isMember(conversationId, currentUserId(req)))) {
    return res.status(404).json({ error: "Conversation not found." });
  }
  const result = await pool.query(
    "SELECT m.id,m.body AS text,m.client_id AS \"clientId\",m.sender_id AS \"senderId\", " +
    "a.display_name AS \"senderName\",m.created_at AS \"createdAt\" " +
    "FROM messages m JOIN artists a ON a.id=m.sender_id WHERE m.conversation_id=$1 " +
    "ORDER BY m.id DESC LIMIT 100",
    [conversationId]
  );
  res.json({ messages: result.rows.reverse().map(row => ({
    id: row.id,
    text: row.text,
    clientId: row.clientId,
    senderId: Number(row.senderId),
    senderName: row.senderName,
    createdAt: row.createdAt
  })) });
}));

app.post("/api/conversations/:conversationId/messages", sameOrigin, requireUser, asyncRoute(async (req, res) => {
  const conversationId = req.params.conversationId;
  if (!/^[0-9a-f-]{36}$/i.test(conversationId)) return res.status(404).json({ error: "Conversation not found." });
  const input = isPlainObject(req.body) ? req.body : {};
  const text = typeof input.text === "string" ? input.text.trim() : "";
  const clientId = input.clientId == null ? null : input.clientId;
  if (!text || text.length > 2000 ||
      (clientId !== null && (typeof clientId !== "string" || !/^[0-9a-f-]{36}$/i.test(clientId)))) {
    return res.status(400).json({ error: "Enter a message of up to 2,000 characters." });
  }
  if (!(await isMember(conversationId, currentUserId(req)))) {
    return res.status(404).json({ error: "Conversation not found." });
  }
  const result = await pool.query(
    "INSERT INTO messages (conversation_id,sender_id,body,client_id) VALUES ($1,$2,$3,$4) " +
    "ON CONFLICT (sender_id,client_id) WHERE client_id IS NOT NULL DO NOTHING " +
    "RETURNING id,client_id AS \"clientId\",sender_id AS \"senderId\",created_at AS \"createdAt\"",
    [conversationId, currentUserId(req), text, clientId]
  );
  if (!result.rows[0]) return res.status(409).json({ error: "This message was already sent." });
  const author = await pool.query("SELECT display_name FROM artists WHERE id=$1", [currentUserId(req)]);
  const message = { ...result.rows[0], text, senderName: author.rows[0].display_name };
  await pool.query("UPDATE conversations SET updated_at=now() WHERE id=$1", [conversationId]);
  io.to("conversation:" + conversationId).emit("message:new", { conversationId });
  res.status(201).json({ message });
}));

io.use(async (socket, next) => {
  try {
    const rawToken = socket.handshake.auth?.token;
    if (typeof rawToken === "string" && /^[A-Za-z0-9_-]{40,100}$/.test(rawToken)) {
      const tokenHash = crypto.createHash("sha256").update(rawToken).digest("hex");
      const result = await pool.query(
        "SELECT user_id FROM api_tokens WHERE token_hash=$1 AND expires_at>now()",
        [tokenHash]
      );
      if (result.rows[0]) {
        socket.data.userId = Number(result.rows[0].user_id);
        return next();
      }
    }
    if (socket.request.session?.userId) {
      socket.data.userId = Number(socket.request.session.userId);
      return next();
    }
    next(new Error("Sign in to use messages."));
  } catch (error) {
    next(error);
  }
});

io.on("connection", async socket => {
  const userId = Number(socket.data.userId);
  try {
    const result = await pool.query(
      "SELECT conversation_id FROM conversation_members WHERE user_id=$1",
      [userId]
    );
    for (const row of result.rows) socket.join("conversation:" + row.conversation_id);
  } catch {
    socket.disconnect(true);
    return;
  }
  socket.on("conversation:join", async conversationId => {
    if (typeof conversationId !== "string" || !/^[0-9a-f-]{36}$/i.test(conversationId)) return;
    if (await isMember(conversationId, userId)) socket.join("conversation:" + conversationId);
  });
});

const currentDir = path.dirname(fileURLToPath(import.meta.url));
app.use(express.static(path.join(currentDir, "public"), { extensions: ["html"] }));
app.use((req, res, next) => {
  if (req.method !== "GET") return next();
  if (req.path.startsWith("/api/")) return res.status(404).json({ error: "Route not found." });
  res.sendFile(path.join(currentDir, "public", "index.html"));
});

app.use((error, _req, res, _next) => {
  console.error("Request failed:", error?.message || "unknown error");
  if (res.headersSent) return;
  const status = Number(error?.statusCode || error?.status);
  if (status === 413) return res.status(413).json({ error: "Each audio track must be 20 MB or smaller." });
  res.status(status >= 400 && status < 500 ? status : 500).json({ error: "Something went wrong. Please try again." });
});

await prepareDatabase();
httpServer.listen(port, "0.0.0.0", () => {
  console.log("SceneSpool messaging server listening on port " + port);
});

async function shutdown() {
  io.close();
  await pool.end();
  process.exit(0);
}
process.on("SIGTERM", shutdown);
process.on("SIGINT", shutdown);

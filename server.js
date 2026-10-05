require("dotenv").config();

const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");
const multer = require("multer");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const http = require("http");
const { WebSocketServer } = require("ws");

const PORT = Number(process.env.PORT || 5000);
const DATABASE_URL = process.env.DATABASE_URL;
const JWT_SECRET = process.env.JWT_SECRET;
const JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET;
const FRONTEND_URL = process.env.FRONTEND_URL || "http://localhost:5500";
const UPLOAD_DIR = path.resolve(process.env.UPLOAD_DIR || "uploads");
const MAX_FILE_SIZE = Number(process.env.MAX_FILE_SIZE || 10 * 1024 * 1024);

if (!DATABASE_URL) console.warn("WARNING: DATABASE_URL is not set.");
if (!JWT_SECRET || JWT_SECRET.length < 32) console.warn("WARNING: JWT_SECRET should be a random string of at least 32 characters.");
if (!JWT_REFRESH_SECRET || JWT_REFRESH_SECRET.length < 32) console.warn("WARNING: JWT_REFRESH_SECRET should be a random string of at least 32 characters.");

fs.mkdirSync(UPLOAD_DIR, { recursive: true });

const app = express();
const server = http.createServer(app);

const allowedOrigins = FRONTEND_URL.split(",").map(s => s.trim()).filter(Boolean);
app.use(helmet({ crossOriginResourcePolicy: { policy: "cross-origin" } }));
app.use(cors({
  origin(origin, callback) {
    if (!origin || allowedOrigins.includes("*") || allowedOrigins.includes(origin)) return callback(null, true);
    return callback(new Error("CORS origin not allowed"));
  },
  credentials: true
}));
app.use(express.json({ limit: "2mb" }));
app.use(express.urlencoded({ extended: true }));

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 300,
  standardHeaders: "draft-7",
  legacyHeaders: false
});
app.use("/api/", apiLimiter);

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: process.env.NODE_ENV === "production" ? { rejectUnauthorized: false } : false,
  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000
});

pool.on("error", err => console.error("PostgreSQL pool error:", err));

function requireDb(req, res, next) {
  if (!DATABASE_URL) return res.status(503).json({ error: "Database is not configured on the server." });
  next();
}

app.use(requireDb);

function signAccessToken(user) {
  return jwt.sign(
    { sub: user.id, email: user.email, role: user.role, name: user.name },
    JWT_SECRET,
    { expiresIn: process.env.ACCESS_TOKEN_EXPIRES || "15m" }
  );
}

function signRefreshToken(user, sessionId) {
  return jwt.sign(
    { sub: user.id, sid: sessionId, type: "refresh" },
    JWT_REFRESH_SECRET,
    { expiresIn: process.env.REFRESH_TOKEN_EXPIRES || "30d" }
  );
}

function hashToken(token) {
  return crypto.createHash("sha256").update(token).digest("hex");
}

async function getUserById(id) {
  const { rows } = await pool.query(
    "SELECT id,email,name,role,office,permissions,active,created_at,updated_at FROM users WHERE id=$1",
    [id]
  );
  return rows[0] || null;
}

function asyncRoute(fn) {
  return (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
}

function auth(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: "Authentication required." });

  try {
    req.auth = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: "Invalid or expired access token." });
  }
}

function roles(...allowed) {
  return (req, res, next) => {
    if (!req.auth || !allowed.includes(req.auth.role)) {
      return res.status(403).json({ error: "You do not have permission for this action." });
    }
    next();
  };
}

function canEditPortal(req) {
  return ["admin", "chairman", "parliament_head", "executive", "sec"].includes(req.auth.role);
}

async function audit(userId, action, entityType, entityId, details = {}) {
  await pool.query(
    `INSERT INTO audit_logs(user_id,action,entity_type,entity_id,details)
     VALUES($1,$2,$3,$4,$5::jsonb)`,
    [userId || null, action, entityType || null, entityId || null, JSON.stringify(details)]
  );
}

const upload = multer({
  storage: multer.diskStorage({
    destination: (_req, _file, cb) => cb(null, UPLOAD_DIR),
    filename: (_req, file, cb) => {
      const safe = path.basename(file.originalname).replace(/[^a-zA-Z0-9._-]/g, "_");
      cb(null, `${Date.now()}-${crypto.randomBytes(8).toString("hex")}-${safe}`);
    }
  }),
  limits: { fileSize: MAX_FILE_SIZE }
});

app.get("/health", asyncRoute(async (_req, res) => {
  let db = "disconnected";
  if (DATABASE_URL) {
    try {
      await pool.query("SELECT 1");
      db = "connected";
    } catch {}
  }
  res.json({ ok: true, service: "sonainfo-backend", database: db, time: new Date().toISOString() });
}));

app.get("/", (_req, res) => {
  res.json({
    service: "Sonainfo Executive Portal API",
    status: "online",
    health: "/health",
    websocket: "/ws"
  });
});

// ---------- AUTH ----------
app.post("/api/auth/register", asyncRoute(async (req, res) => {
  const { email, password, name, role = "member", office = null, permissions = [] } = req.body;
  if (!email || !password || !name) return res.status(400).json({ error: "email, password and name are required." });
  if (password.length < 8) return res.status(400).json({ error: "Password must contain at least 8 characters." });

  const normalizedEmail = String(email).trim().toLowerCase();
  const existing = await pool.query("SELECT id FROM users WHERE email=$1", [normalizedEmail]);
  if (existing.rowCount) return res.status(409).json({ error: "Email already registered." });

  const passwordHash = await bcrypt.hash(password, 12);
  const { rows } = await pool.query(
    `INSERT INTO users(email,password_hash,name,role,office,permissions)
     VALUES($1,$2,$3,$4,$5,$6) RETURNING id,email,name,role,office,permissions,active,created_at,updated_at`,
    [normalizedEmail, passwordHash, name.trim(), role, office, permissions]
  );

  await audit(rows[0].id, "USER_REGISTERED", "user", rows[0].id, { email: normalizedEmail });
  res.status(201).json({ user: rows[0] });
}));

app.post("/api/auth/login", asyncRoute(async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: "email and password are required." });

  const { rows } = await pool.query("SELECT * FROM users WHERE email=$1", [String(email).trim().toLowerCase()]);
  const user = rows[0];
  if (!user || !user.active) return res.status(401).json({ error: "Invalid email/password or inactive account." });

  const ok = await bcrypt.compare(password, user.password_hash);
  if (!ok) return res.status(401).json({ error: "Invalid email/password." });

  const sessionId = crypto.randomUUID();
  const refreshToken = signRefreshToken(user, sessionId);
  const refreshHash = hashToken(refreshToken);
  const decoded = jwt.decode(refreshToken);
  const expiresAt = new Date(decoded.exp * 1000);

  await pool.query(
    `INSERT INTO sessions(id,user_id,refresh_hash,expires_at) VALUES($1,$2,$3,$4)`,
    [sessionId, user.id, refreshHash, expiresAt]
  );

  const accessToken = signAccessToken(user);
  await audit(user.id, "LOGIN", "session", sessionId);

  res.json({
    accessToken,
    refreshToken,
    user: {
      id: user.id, email: user.email, name: user.name, role: user.role,
      office: user.office, permissions: user.permissions, active: user.active
    }
  });
}));

app.post("/api/auth/refresh", asyncRoute(async (req, res) => {
  const { refreshToken } = req.body;
  if (!refreshToken) return res.status(400).json({ error: "refreshToken is required." });

  let payload;
  try {
    payload = jwt.verify(refreshToken, JWT_REFRESH_SECRET);
  } catch {
    return res.status(401).json({ error: "Invalid or expired refresh token." });
  }

  const { rows } = await pool.query(
    `SELECT s.*,u.email,u.name,u.role,u.office,u.permissions,u.active
     FROM sessions s JOIN users u ON u.id=s.user_id
     WHERE s.id=$1 AND s.revoked_at IS NULL AND s.expires_at > NOW()`,
    [payload.sid]
  );
  const session = rows[0];
  if (!session || hashToken(refreshToken) !== session.refresh_hash || !session.active) {
    return res.status(401).json({ error: "Refresh session is invalid." });
  }

  res.json({
    accessToken: signAccessToken(session),
    user: {
      id: session.user_id, email: session.email, name: session.name, role: session.role,
      office: session.office, permissions: session.permissions, active: session.active
    }
  });
}));

app.post("/api/auth/logout", asyncRoute(async (req, res) => {
  const { refreshToken } = req.body;
  if (refreshToken) {
    try {
      const payload = jwt.verify(refreshToken, JWT_REFRESH_SECRET);
      await pool.query("UPDATE sessions SET revoked_at=NOW() WHERE id=$1", [payload.sid]);
      if (payload.sub) await audit(payload.sub, "LOGOUT", "session", payload.sid);
    } catch {}
  }
  res.json({ ok: true });
}));

app.get("/api/auth/me", auth, asyncRoute(async (req, res) => {
  const user = await getUserById(req.auth.sub);
  if (!user || !user.active) return res.status(401).json({ error: "User is inactive or missing." });
  res.json({ user });
}));

// ---------- USERS ----------
app.get("/api/users", auth, roles("admin", "chairman", "parliament_head", "sec"), asyncRoute(async (req, res) => {
  const { rows } = await pool.query(
    `SELECT id,email,name,role,office,permissions,active,created_at,updated_at
     FROM users ORDER BY created_at DESC`
  );
  res.json({ users: rows });
}));

app.patch("/api/users/:id", auth, roles("admin", "chairman", "parliament_head"), asyncRoute(async (req, res) => {
  const { name, role, office, permissions, active } = req.body;
  const { rows } = await pool.query(
    `UPDATE users SET
      name=COALESCE($1,name),
      role=COALESCE($2,role),
      office=COALESCE($3,office),
      permissions=COALESCE($4,permissions),
      active=COALESCE($5,active),
      updated_at=NOW()
     WHERE id=$6
     RETURNING id,email,name,role,office,permissions,active,created_at,updated_at`,
    [name ?? null, role ?? null, office ?? null, permissions ?? null, active ?? null, req.params.id]
  );
  if (!rows[0]) return res.status(404).json({ error: "User not found." });
  await audit(req.auth.sub, "USER_UPDATED", "user", req.params.id, req.body);
  broadcast("user.updated", rows[0]);
  res.json({ user: rows[0] });
}));

// ---------- PORTAL DOCUMENTS / REALTIME STATE ----------
app.get("/api/portal/:docKey", auth, asyncRoute(async (req, res) => {
  const { rows } = await pool.query("SELECT * FROM portal_documents WHERE doc_key=$1", [req.params.docKey]);
  if (!rows[0]) return res.json({ docKey: req.params.docKey, data: {}, version: 0 });
  res.json(rows[0]);
}));

app.put("/api/portal/:docKey", auth, asyncRoute(async (req, res) => {
  if (!canEditPortal(req)) return res.status(403).json({ error: "Portal editing permission denied." });
  const data = req.body?.data ?? req.body;
  const expectedVersion = req.body?.expectedVersion;

  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const existing = await client.query("SELECT version FROM portal_documents WHERE doc_key=$1 FOR UPDATE", [req.params.docKey]);
    const currentVersion = existing.rows[0]?.version || 0;

    if (expectedVersion !== undefined && Number(expectedVersion) !== Number(currentVersion)) {
      await client.query("ROLLBACK");
      return res.status(409).json({ error: "Version conflict.", currentVersion });
    }

    const nextVersion = currentVersion + 1;
    const { rows } = await client.query(
      `INSERT INTO portal_documents(doc_key,data,version,updated_by,updated_at)
       VALUES($1,$2::jsonb,$3,$4,NOW())
       ON CONFLICT(doc_key) DO UPDATE SET
         data=EXCLUDED.data,version=EXCLUDED.version,updated_by=EXCLUDED.updated_by,updated_at=NOW()
       RETURNING *`,
      [req.params.docKey, JSON.stringify(data), nextVersion, req.auth.sub]
    );
    await client.query("COMMIT");

    await audit(req.auth.sub, "PORTAL_UPDATED", "portal_document", req.params.docKey, { version: nextVersion });
    broadcast("portal.updated", rows[0]);
    res.json(rows[0]);
  } catch (e) {
    await client.query("ROLLBACK").catch(() => {});
    throw e;
  } finally {
    client.release();
  }
}));

// ---------- MEDICAL LEAVES ----------
app.post("/api/leaves", auth, upload.single("attachment"), asyncRoute(async (req, res) => {
  const fromDate = req.body.from_date || req.body.fromDate;
  const toDate = req.body.to_date || req.body.toDate;
  const reason = req.body.reason;
  if (!fromDate || !toDate || !reason) return res.status(400).json({ error: "from_date, to_date and reason are required." });

  const file = req.file;
  const { rows } = await pool.query(
    `INSERT INTO medical_leaves(user_id,from_date,to_date,reason,attachment_name,attachment_path)
     VALUES($1,$2,$3,$4,$5,$6) RETURNING *`,
    [req.auth.sub, fromDate, toDate, reason, file?.originalname || null, file?.filename || null]
  );
  await audit(req.auth.sub, "LEAVE_CREATED", "medical_leave", rows[0].id);
  broadcast("leave.created", rows[0]);
  res.status(201).json(rows[0]);
}));

app.get("/api/leaves", auth, asyncRoute(async (req, res) => {
  const isManager = ["admin","chairman","parliament_head","sec","executive"].includes(req.auth.role);
  const query = isManager
    ? `SELECT ml.*,u.name as user_name,u.email as user_email FROM medical_leaves ml JOIN users u ON u.id=ml.user_id ORDER BY ml.created_at DESC`
    : `SELECT ml.*,u.name as user_name,u.email as user_email FROM medical_leaves ml JOIN users u ON u.id=ml.user_id WHERE ml.user_id=$1 ORDER BY ml.created_at DESC`;
  const { rows } = await pool.query(query, isManager ? [] : [req.auth.sub]);
  res.json({ leaves: rows });
}));

app.patch("/api/leaves/:id", auth, asyncRoute(async (req, res) => {
  const { status, remark } = req.body;
  const manager = ["admin","chairman","parliament_head","sec","executive"].includes(req.auth.role);
  if (!manager && status) return res.status(403).json({ error: "Only authorized managers can change leave status." });

  const { rows } = await pool.query(
    `UPDATE medical_leaves SET status=COALESCE($1,status),updated_at=NOW()
     WHERE id=$2 ${manager ? "" : "AND user_id=$3"} RETURNING *`,
    manager ? [status ?? null, req.params.id] : [status ?? null, req.params.id, req.auth.sub]
  );
  if (!rows[0]) return res.status(404).json({ error: "Leave not found or not permitted." });
  await audit(req.auth.sub, "LEAVE_UPDATED", "medical_leave", req.params.id, { status, remark });
  broadcast("leave.updated", rows[0]);
  res.json(rows[0]);
}));

// ---------- EXAM REQUESTS ----------
app.post("/api/exams", auth, upload.single("attachment"), asyncRoute(async (req, res) => {
  const { title, description = "" } = req.body;
  if (!title) return res.status(400).json({ error: "title is required." });
  const file = req.file;
  const { rows } = await pool.query(
    `INSERT INTO exam_requests(user_id,title,description,attachment_name,attachment_path)
     VALUES($1,$2,$3,$4,$5) RETURNING *`,
    [req.auth.sub, title, description, file?.originalname || null, file?.filename || null]
  );
  await audit(req.auth.sub, "EXAM_REQUEST_CREATED", "exam_request", rows[0].id);
  broadcast("exam.created", rows[0]);
  res.status(201).json(rows[0]);
}));

app.get("/api/exams", auth, asyncRoute(async (req, res) => {
  const manager = ["admin","chairman","parliament_head","sec","executive"].includes(req.auth.role);
  const q = manager
    ? `SELECT er.*,u.name as user_name,u.email as user_email FROM exam_requests er JOIN users u ON u.id=er.user_id ORDER BY er.created_at DESC`
    : `SELECT er.*,u.name as user_name,u.email as user_email FROM exam_requests er JOIN users u ON u.id=er.user_id WHERE er.user_id=$1 ORDER BY er.created_at DESC`;
  const { rows } = await pool.query(q, manager ? [] : [req.auth.sub]);
  res.json({ exams: rows });
}));

app.patch("/api/exams/:id", auth, asyncRoute(async (req, res) => {
  const manager = ["admin","chairman","parliament_head","sec","executive"].includes(req.auth.role);
  if (!manager && req.body.status) return res.status(403).json({ error: "Only authorized managers can change exam status." });
  const { rows } = await pool.query(
    `UPDATE exam_requests SET status=COALESCE($1,status),description=COALESCE($2,description),updated_at=NOW()
     WHERE id=$3 ${manager ? "" : "AND user_id=$4"} RETURNING *`,
    manager ? [req.body.status ?? null, req.body.description ?? null, req.params.id]
            : [req.body.status ?? null, req.body.description ?? null, req.params.id, req.auth.sub]
  );
  if (!rows[0]) return res.status(404).json({ error: "Exam request not found or not permitted." });
  await audit(req.auth.sub, "EXAM_REQUEST_UPDATED", "exam_request", req.params.id, req.body);
  broadcast("exam.updated", rows[0]);
  res.json(rows[0]);
}));

// ---------- NOTIFICATIONS ----------
app.get("/api/notifications", auth, asyncRoute(async (req, res) => {
  const limit = Math.min(Number(req.query.limit || 100), 200);
  const { rows } = await pool.query(
    `SELECT * FROM notifications WHERE user_id=$1 ORDER BY created_at DESC LIMIT $2`,
    [req.auth.sub, limit]
  );
  res.json({ notifications: rows });
}));

app.patch("/api/notifications/:id/read", auth, asyncRoute(async (req, res) => {
  const { rows } = await pool.query(
    `UPDATE notifications SET is_read=TRUE WHERE id=$1 AND user_id=$2 RETURNING *`,
    [req.params.id, req.auth.sub]
  );
  if (!rows[0]) return res.status(404).json({ error: "Notification not found." });
  broadcast("notification.read", rows[0]);
  res.json(rows[0]);
}));

async function createNotification(userId, type, title, message, entityType = null, entityId = null) {
  const { rows } = await pool.query(
    `INSERT INTO notifications(user_id,type,title,message,entity_type,entity_id)
     VALUES($1,$2,$3,$4,$5,$6) RETURNING *`,
    [userId,type,title,message,entityType,entityId]
  );
  broadcast("notification.created", rows[0]);
  return rows[0];
}

app.post("/api/notifications", auth, roles("admin","chairman","parliament_head","sec","executive"), asyncRoute(async (req,res)=>{
  const { userId, type="general", title, message, entityType=null, entityId=null } = req.body;
  if (!userId || !title || !message) return res.status(400).json({error:"userId, title and message are required."});
  const notification = await createNotification(userId,type,title,message,entityType,entityId);
  res.status(201).json(notification);
}));

// ---------- GENERIC JSON ENTITIES ----------
function jsonEntityRoutes(basePath, table, entityName, managerRoles = ["admin","chairman","parliament_head","sec","executive"]) {
  app.get(`/api/${basePath}`, auth, asyncRoute(async (req,res)=>{
    const manager = managerRoles.includes(req.auth.role);
    const q = manager
      ? `SELECT t.*,u.name as creator_name FROM ${table} t LEFT JOIN users u ON u.id=t.created_by ORDER BY t.created_at DESC`
      : `SELECT t.*,u.name as creator_name FROM ${table} t LEFT JOIN users u ON u.id=t.created_by WHERE t.created_by=$1 ORDER BY t.created_at DESC`;
    const {rows}=await pool.query(q, manager ? [] : [req.auth.sub]);
    res.json({[basePath]: rows});
  }));

  app.post(`/api/${basePath}`, auth, asyncRoute(async (req,res)=>{
    const data = req.body?.data ?? req.body;
    const {rows}=await pool.query(
      `INSERT INTO ${table}(data,created_by) VALUES($1::jsonb,$2) RETURNING *`,
      [JSON.stringify(data),req.auth.sub]
    );
    await audit(req.auth.sub, `${entityName.toUpperCase()}_CREATED`, entityName, rows[0].id);
    broadcast(`${entityName}.created`, rows[0]);
    res.status(201).json(rows[0]);
  }));

  app.get(`/api/${basePath}/:id`, auth, asyncRoute(async (req,res)=>{
    const {rows}=await pool.query(`SELECT * FROM ${table} WHERE id=$1`,[req.params.id]);
    if(!rows[0]) return res.status(404).json({error:"Not found."});
    const manager = managerRoles.includes(req.auth.role);
    if(!manager && String(rows[0].created_by)!==String(req.auth.sub)) return res.status(403).json({error:"Forbidden."});
    res.json(rows[0]);
  }));

  app.patch(`/api/${basePath}/:id`, auth, asyncRoute(async (req,res)=>{
    const existing=await pool.query(`SELECT * FROM ${table} WHERE id=$1`,[req.params.id]);
    if(!existing.rows[0]) return res.status(404).json({error:"Not found."});
    const manager=managerRoles.includes(req.auth.role);
    if(!manager && String(existing.rows[0].created_by)!==String(req.auth.sub)) return res.status(403).json({error:"Forbidden."});
    const data=req.body?.data ?? req.body;
    const {rows}=await pool.query(`UPDATE ${table} SET data=$1::jsonb,updated_at=NOW() WHERE id=$2 RETURNING *`,[JSON.stringify(data),req.params.id]);
    await audit(req.auth.sub, `${entityName.toUpperCase()}_UPDATED`, entityName, req.params.id);
    broadcast(`${entityName}.updated`, rows[0]);
    res.json(rows[0]);
  }));

  app.delete(`/api/${basePath}/:id`, auth, asyncRoute(async (req,res)=>{
    const existing=await pool.query(`SELECT * FROM ${table} WHERE id=$1`,[req.params.id]);
    if(!existing.rows[0]) return res.status(404).json({error:"Not found."});
    const manager=managerRoles.includes(req.auth.role);
    if(!manager && String(existing.rows[0].created_by)!==String(req.auth.sub)) return res.status(403).json({error:"Forbidden."});
    await pool.query(`DELETE FROM ${table} WHERE id=$1`,[req.params.id]);
    await audit(req.auth.sub, `${entityName.toUpperCase()}_DELETED`, entityName, req.params.id);
    broadcast(`${entityName}.deleted`, {id:req.params.id});
    res.json({ok:true,id:req.params.id});
  }));
}

jsonEntityRoutes("cases","cases","case");
jsonEntityRoutes("penalties","penalties","penalty");
jsonEntityRoutes("finance","finance_transactions","finance_transaction");

// ---------- AUDIT ----------
app.get("/api/audit-logs", auth, roles("admin","chairman","parliament_head","sec"), asyncRoute(async (req,res)=>{
  const limit=Math.min(Number(req.query.limit||200),500);
  const {rows}=await pool.query(
    `SELECT a.*,u.name as user_name,u.email as user_email
     FROM audit_logs a LEFT JOIN users u ON u.id=a.user_id
     ORDER BY a.created_at DESC LIMIT $1`,[limit]
  );
  res.json({logs:rows});
}));

// ---------- FILES ----------
app.get("/api/uploads/:filename", auth, (req,res)=>{
  const safeName=path.basename(req.params.filename);
  const filePath=path.join(UPLOAD_DIR,safeName);
  if(!fs.existsSync(filePath)) return res.status(404).json({error:"File not found."});
  res.sendFile(filePath);
});

app.post("/api/uploads", auth, upload.single("file"), (req,res)=>{
  if(!req.file) return res.status(400).json({error:"No file uploaded."});
  res.status(201).json({
    filename:req.file.filename,
    originalname:req.file.originalname,
    size:req.file.size,
    url:`/api/uploads/${encodeURIComponent(req.file.filename)}`
  });
});

// ---------- WEBSOCKET REALTIME ----------
const wss = new WebSocketServer({ server, path: "/ws" });
const clients = new Set();

function broadcast(event, data) {
  const message = JSON.stringify({ event, data, at: new Date().toISOString() });
  for (const client of clients) {
    if (client.readyState === 1 && client.user) {
      client.send(message);
    }
  }
}

wss.on("connection", (socket) => {
  const client = { socket, user: null };
  clients.add(client);

  socket.send(JSON.stringify({
    event: "connected",
    data: { message: "WebSocket connected. Send {type:'auth',token:'...'} to authenticate." }
  }));

  socket.on("message", async raw => {
    try {
      const msg = JSON.parse(raw.toString());
      if (msg.type === "ping") {
        socket.send(JSON.stringify({ event: "pong", at: new Date().toISOString() }));
        return;
      }
      if (msg.type === "auth") {
        const payload = jwt.verify(msg.token, JWT_SECRET);
        const user = await getUserById(payload.sub);
        if (!user || !user.active) throw new Error("Inactive user");
        client.user = user;
        socket.send(JSON.stringify({ event: "authenticated", data: { user } }));
        return;
      }
      if (msg.type === "subscribe") {
        if (!client.user) return socket.send(JSON.stringify({event:"error",data:{message:"Authenticate first."}}));
        socket.send(JSON.stringify({event:"subscribed",data:{channels:msg.channels || ["all"]}}));
      }
    } catch (e) {
      socket.send(JSON.stringify({ event:"error", data:{ message:"Invalid WebSocket message or authentication." }}));
    }
  });

  socket.on("close", () => clients.delete(client));
  socket.on("error", () => clients.delete(client));
});

setInterval(() => {
  for (const client of clients) {
    if (client.socket.readyState === 1) client.socket.ping();
  }
}, 30000);

// ---------- ERROR HANDLER ----------
app.use((err, req, res, _next) => {
  console.error(err);
  if (err instanceof multer.MulterError) {
    return res.status(400).json({ error: `Upload error: ${err.message}` });
  }
  if (err.message === "CORS origin not allowed") return res.status(403).json({ error: err.message });
  res.status(500).json({ error: "Internal server error." });
});

async function start() {
  if (!DATABASE_URL) {
    console.error("DATABASE_URL is missing. Set it before starting the server.");
    process.exit(1);
  }
  await pool.query("SELECT 1");
  server.listen(PORT, "0.0.0.0", () => {
    console.log(`Sonainfo backend listening on port ${PORT}`);
    console.log(`Health: http://localhost:${PORT}/health`);
    console.log(`WebSocket: ws://localhost:${PORT}/ws`);
  });
}

start().catch(err => {
  console.error("Failed to start server:", err);
  process.exit(1);
});

process.on("SIGTERM", async () => {
  server.close();
  await pool.end();
  process.exit(0);
});

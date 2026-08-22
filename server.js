const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const db = require("./db");
const { STAGES } = require("./stages");
const { signToken, requireAuth } = require("./auth");

const app = express();
app.use(cors());
app.use(express.json());

function serializeOrder(row) {
  return {
    id: row.id,
    patient: row.patient,
    clinic: row.clinic_name,
    workType: row.work_type,
    shade: row.shade,
    dueDate: row.due_date,
    stageIndex: row.stage_index,
    stage: STAGES[row.stage_index],
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

const ORDER_SELECT = `
  SELECT orders.*, clinics.name AS clinic_name
  FROM orders
  JOIN clinics ON clinics.id = orders.clinic_id
`;

app.post("/api/auth/login", (req, res) => {
  const { name, password } = req.body;
  if (!name || !password) return res.status(400).json({ error: "name and password are required" });

  const user = db.prepare("SELECT * FROM users WHERE name = ?").get(name);
  if (!user) return res.status(401).json({ error: "неверное имя или пароль" });

  const valid = bcrypt.compareSync(password, user.password_hash);
  if (!valid) return res.status(401).json({ error: "неверное имя или пароль" });

  const token = signToken(user);
  res.json({
    token,
    role: user.role,
    name: user.name,
    clinicId: user.clinic_id,
  });
});

app.post("/api/auth/change-password", requireAuth(), (req, res) => {
  const { newPassword } = req.body;
  if (!newPassword || newPassword.length < 4) {
    return res.status(400).json({ error: "password must be at least 4 characters" });
  }
  const hash = bcrypt.hashSync(newPassword, 10);
  db.prepare("UPDATE users SET password_hash = ? WHERE id = ?").run(hash, req.user.userId);
  res.json({ ok: true });
});

app.post("/api/auth/register-clinic", requireAuth("lab"), (req, res) => {
  const { clinicName, password } = req.body;
  if (!clinicName || !clinicName.trim()) return res.status(400).json({ error: "clinicName is required" });
  if (!password || password.length < 4) return res.status(400).json({ error: "password must be at least 4 characters" });

  let clinic = db.prepare("SELECT id FROM clinics WHERE name = ?").get(clinicName.trim());
  if (!clinic) {
    const info = db.prepare("INSERT INTO clinics (name) VALUES (?)").run(clinicName.trim());
    clinic = { id: info.lastInsertRowid };
  }

  const existingUser = db.prepare("SELECT id FROM users WHERE name = ?").get(clinicName.trim());
  if (existingUser) return res.status(409).json({ error: "аккаунт с таким именем уже есть" });

  const hash = bcrypt.hashSync(password, 10);
  db.prepare("INSERT INTO users (name, password_hash, role, clinic_id) VALUES (?, ?, 'clinic', ?)")
    .run(clinicName.trim(), hash, clinic.id);

  res.status(201).json({ ok: true, clinicId: clinic.id });
});

app.get("/api/clinics", requireAuth(), (req, res) => {
  const clinics = db.prepare("SELECT id, name FROM clinics ORDER BY name").all();
  res.json(clinics);
});

app.get("/api/orders", requireAuth(), (req, res) => {
  let rows;
  if (req.user.role === "clinic") {
    rows = db.prepare(`${ORDER_SELECT} WHERE orders.clinic_id = ? ORDER BY due_date ASC`).all(req.user.clinicId);
  } else {
app.get("/api/orders/:id/history", requireAuth(), (req, res) => {
  const { id } = req.params;
  const events = db.prepare("SELECT stage_index, changed_at FROM stage_events WHERE order_id = ? ORDER BY changed_at ASC").all(id);
  res.json(events.map((e) => ({ stage: STAGES[e.stage_index], changedAt: e.changed_at })));
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`Dental lab tracker API running on http://localhost:${PORT}`);
});

  

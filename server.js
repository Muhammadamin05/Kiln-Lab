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

// ---------- Auth ----------

// Login for both lab staff and clinics. Send { name, password }.
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

// Change your own password. Requires being logged in.
app.post("/api/auth/change-password", requireAuth(), (req, res) => {
  const { newPassword } = req.body;
  if (!newPassword || newPassword.length < 4) {
    return res.status(400).json({ error: "password must be at least 4 characters" });
  }
  const hash = bcrypt.hashSync(newPassword, 10);
  db.prepare("UPDATE users SET password_hash = ? WHERE id = ?").run(hash, req.user.userId);
  res.json({ ok: true });
});

// Lab-only: register a new clinic account.
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

// ---------- Clinics ----------

app.get("/api/clinics", requireAuth(), (req, res) => {
  const clinics = db.prepare("SELECT id, name FROM clinics ORDER BY name").all();
  res.json(clinics);
});

// ---------- Orders ----------

// List orders. Lab sees everything; a clinic only sees its own orders.
app.get("/api/orders", requireAuth(), (req, res) => {
  let rows;
  if (req.user.role === "clinic") {
    rows = db.prepare(`${ORDER_SELECT} WHERE orders.clinic_id = ? ORDER BY due_date ASC`).all(req.user.clinicId);
  } else {
    rows = db.prepare(`${ORDER_SELECT} ORDER BY due_date ASC`).all();
  }
  res.json(rows.map(serializeOrder));
});

// Create a new order. Only a clinic can do this, and only for itself.
app.post("/api/orders", requireAuth("clinic"), (req, res) => {
  const { patient, workType, shade, dueDate } = req.body;

  if (!patient || !patient.trim()) return res.status(400).json({ error: "patient is required" });
  if (!workType || !workType.trim()) return res.status(400).json({ error: "workType is required" });
  if (!dueDate) return res.status(400).json({ error: "dueDate is required" });

  const info = db.prepare(`
    INSERT INTO orders (patient, clinic_id, work_type, shade, due_date, stage_index)
    VALUES (?, ?, ?, ?, ?, 0)
  `).run(patient.trim(), req.user.clinicId, workType.trim(), shade || null, dueDate);

  db.prepare("INSERT INTO stage_events (order_id, stage_index) VALUES (?, 0)").run(info.lastInsertRowid);

  const row = db.prepare(`${ORDER_SELECT} WHERE orders.id = ?`).get(info.lastInsertRowid);
  res.status(201).json(serializeOrder(row));
});

// Advance an order to the next stage. Only lab staff can do this.
app.patch("/api/orders/:id/advance", requireAuth("lab"), (req, res) => {
  const { id } = req.params;
  const order = db.prepare("SELECT * FROM orders WHERE id = ?").get(id);
  if (!order) return res.status(404).json({ error: "order not found" });

  if (order.stage_index >= STAGES.length - 1) {
    return res.status(400).json({ error: "order already at final stage" });
  }

  const nextStage = order.stage_index + 1;
  db.prepare("UPDATE orders SET stage_index = ?, updated_at = datetime('now') WHERE id = ?").run(nextStage, id);
  db.prepare("INSERT INTO stage_events (order_id, stage_index) VALUES (?, ?)").run(id, nextStage);

  const row = db.prepare(`${ORDER_SELECT} WHERE orders.id = ?`).get(id);
  res.json(serializeOrder(row));
});

app.get("/api/orders/:id/history", requireAuth(), (req, res) => {
  const { id } = req.params;
  const events = db.prepare("SELECT stage_index, changed_at FROM stage_events WHERE order_id = ? ORDER BY changed_at ASC").all(id);
  res.json(events.map((e) => ({ stage: STAGES[e.stage_index], changedAt: e.changed_at })));
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`Dental lab tracker API running on http://localhost:${PORT}`);
});

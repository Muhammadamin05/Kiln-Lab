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
    doctor: row.doctor,
    toothCount: row.tooth_count,
    toothPositions: row.tooth_positions,
    workType: row.work_type,
    shade: row.shade,
    dueDate: row.due_date,
    stageIndex: row.stage_index,
    stage: STAGES[row.stage_index],
    modeling: {
      technician: row.modeling_technician,
      quantity: row.modeling_quantity,
      dueDate: row.modeling_due_date,
    },
    ceramist: {
      technician: row.ceramist_technician,
      quantity: row.ceramist_quantity,
      dueDate: row.ceramist_due_date,
    },
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

// Public self-registration for a new clinic account.
app.post("/api/auth/register", (req, res) => {
  const { clinicName, password } = req.body;
  if (!clinicName || !clinicName.trim()) return res.status(400).json({ error: "укажите название клиники" });
  if (!password || password.length < 4) return res.status(400).json({ error: "пароль должен быть не короче 4 символов" });

  const trimmedName = clinicName.trim();
  const existingUser = db.prepare("SELECT id FROM users WHERE name = ?").get(trimmedName);
  if (existingUser) return res.status(409).json({ error: "аккаунт с таким именем уже есть" });

  let clinic = db.prepare("SELECT id FROM clinics WHERE name = ?").get(trimmedName);
  if (!clinic) {
    const info = db.prepare("INSERT INTO clinics (name) VALUES (?)").run(trimmedName);
    clinic = { id: info.lastInsertRowid };
  }

  const hash = bcrypt.hashSync(password, 10);
  const userInfo = db.prepare(
    "INSERT INTO users (name, password_hash, role, clinic_id) VALUES (?, ?, 'clinic', ?)"
  ).run(trimmedName, hash, clinic.id);

  const user = db.prepare("SELECT * FROM users WHERE id = ?").get(userInfo.lastInsertRowid);
  const token = signToken(user);
  res.status(201).json({ token, role: user.role, name: user.name, clinicId: user.clinic_id });
});

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

// ---------- Clinics ----------

app.get("/api/clinics", requireAuth(), (req, res) => {
  const clinics = db.prepare("SELECT id, name FROM clinics ORDER BY name").all();
  res.json(clinics);
});

// ---------- Orders ----------

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
  const { patient, doctor, toothCount, toothPositions, workType, shade, dueDate } = req.body;

  if (!patient || !patient.trim()) return res.status(400).json({ error: "patient is required" });
  if (!workType || !workType.trim()) return res.status(400).json({ error: "workType is required" });
  if (!dueDate) return res.status(400).json({ error: "dueDate is required" });

  const info = db.prepare(`
    INSERT INTO orders (patient, clinic_id, doctor, tooth_count, tooth_positions, work_type, shade, due_date, stage_index)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0)
  `).run(
    patient.trim(),
    req.user.clinicId,
    doctor ? doctor.trim() : null,
    toothCount || null,
    toothPositions ? toothPositions.trim() : null,
    workType.trim(),
    shade || null,
    dueDate
  );

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

// Assign who's doing the modeling or ceramics work, how many units, and by when.
// Only lab staff can do this. taskType is "modeling" or "ceramist".
app.patch("/api/orders/:id/assign", requireAuth("lab"), (req, res) => {
  const { id } = req.params;
  const { taskType, technician, quantity, dueDate } = req.body;

  if (!["modeling", "ceramist"].includes(taskType)) {
    return res.status(400).json({ error: "taskType must be 'modeling' or 'ceramist'" });
  }

  const order = db.prepare("SELECT * FROM orders WHERE id = ?").get(id);
  if (!order) return res.status(404).json({ error: "order not found" });

  const prefix = taskType === "modeling" ? "modeling" : "ceramist";
  db.prepare(`
    UPDATE orders
    SET ${prefix}_technician = ?, ${prefix}_quantity = ?, ${prefix}_due_date = ?, updated_at = datetime('now')
    WHERE id = ?
  `).run(technician || null, quantity || null, dueDate || null, id);

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

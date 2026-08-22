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
    clinicId: row.clinic_id,
    doctor: row.doctor,
    toothCount: row.tooth_count,
    toothPositions: row.tooth_positions,
    workType: row.work_type,
    shade: row.shade,
    dueDate: row.due_date,
    trayInfo: row.tray_info,
    fittingDates: [row.fitting_date_1, row.fitting_date_2, row.fitting_date_3],
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
  res.json({ token, role: user.role, name: user.name, clinicId: user.clinic_id });
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

// Full clinic list with doctor + order counts. Useful for the lab's management screen.
app.get("/api/clinics", requireAuth(), (req, res) => {
  const clinics = db.prepare(`
    SELECT clinics.*,
      (SELECT COUNT(*) FROM doctors WHERE doctors.clinic_id = clinics.id) AS doctor_count,
      (SELECT COUNT(*) FROM orders WHERE orders.clinic_id = clinics.id) AS order_count
    FROM clinics ORDER BY name
  `).all();
  res.json(clinics.map((c) => ({ id: c.id, name: c.name, doctorCount: c.doctor_count, orderCount: c.order_count })));
});

// Lab can add a clinic to the roster ahead of it registering its own login.
app.post("/api/clinics", requireAuth("lab"), (req, res) => {
  const { name } = req.body;
  if (!name || !name.trim()) return res.status(400).json({ error: "name is required" });
  try {
    const info = db.prepare("INSERT INTO clinics (name) VALUES (?)").run(name.trim());
    res.status(201).json({ id: info.lastInsertRowid, name: name.trim(), doctorCount: 0, orderCount: 0 });
  } catch (err) {
    res.status(409).json({ error: "клиника с таким именем уже есть" });
  }
});

// ---------- Doctors ----------

// List doctors. Clinic sees only its own; lab can filter by clinicId or see all.
app.get("/api/doctors", requireAuth(), (req, res) => {
  let rows;
  if (req.user.role === "clinic") {
    rows = db.prepare("SELECT * FROM doctors WHERE clinic_id = ? ORDER BY name").all(req.user.clinicId);
  } else if (req.query.clinicId) {
    rows = db.prepare("SELECT * FROM doctors WHERE clinic_id = ? ORDER BY name").all(req.query.clinicId);
  } else {
    rows = db.prepare("SELECT * FROM doctors ORDER BY name").all();
  }
  res.json(rows.map((d) => ({ id: d.id, name: d.name, clinicId: d.clinic_id })));
});

// A clinic adds its own doctor; the lab can add a doctor to any clinic (needs clinicId).
app.post("/api/doctors", requireAuth(), (req, res) => {
  const { name, clinicId } = req.body;
  if (!name || !name.trim()) return res.status(400).json({ error: "name is required" });

  const targetClinicId = req.user.role === "clinic" ? req.user.clinicId : clinicId;
  if (!targetClinicId) return res.status(400).json({ error: "clinicId is required" });

  const info = db.prepare("INSERT INTO doctors (clinic_id, name) VALUES (?, ?)").run(targetClinicId, name.trim());
  res.status(201).json({ id: info.lastInsertRowid, name: name.trim(), clinicId: targetClinicId });
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

app.post("/api/orders", requireAuth("clinic"), (req, res) => {
  const {
    patient, doctor, toothCount, toothPositions, workType, shade, dueDate,
    trayInfo, fittingDates,
  } = req.body;

  if (!patient || !patient.trim()) return res.status(400).json({ error: "patient is required" });
  if (!workType || !workType.trim()) return res.status(400).json({ error: "workType is required" });
  if (!dueDate) return res.status(400).json({ error: "dueDate is required" });

  const fd = Array.isArray(fittingDates) ? fittingDates : [];

  const info = db.prepare(`
    INSERT INTO orders (
      patient, clinic_id, doctor, tooth_count, tooth_positions, work_type, shade, due_date,
      tray_info, fitting_date_1, fitting_date_2, fitting_date_3, stage_index
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)
  `).run(
    patient.trim(),
    req.user.clinicId,
    doctor ? doctor.trim() : null,
    toothCount || null,
    toothPositions ? toothPositions.trim() : null,
    workType.trim(),
    shade || null,
    dueDate,
    trayInfo ? trayInfo.trim() : null,
    fd[0] || null,
    fd[1] || null,
    fd[2] || null
  );

  db.prepare("INSERT INTO stage_events (order_id, stage_index) VALUES (?, 0)").run(info.lastInsertRowid);

  const row = db.prepare(`${ORDER_SELECT} WHERE orders.id = ?`).get(info.lastInsertRowid);
  res.status(201).json(serializeOrder(row));
});

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

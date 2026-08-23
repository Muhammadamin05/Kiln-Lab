const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const db = require("./db");
const { STAGES } = require("./stages");
const { signToken, requireAuth } = require("./auth");

const app = express();
app.use(cors());
app.use(express.json());

const TASK_TYPES = ["modeling", "ceramist", "cadcam"];

function serializeOrder(row) {
  const tasks = {};
  TASK_TYPES.forEach((t) => {
    tasks[t] = {
      technicianId: row[`${t}_technician_id`],
      technicianName: row[`${t}_technician_name`],
      quantity: row[`${t}_quantity`],
      dueDate: row[`${t}_due_date`],
      price: row[`${t}_price`],
      status: row[`${t}_status`],
      startedAt: row[`${t}_started_at`],
      completedAt: row[`${t}_completed_at`],
    };
  });
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
    ...tasks,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

const ORDER_SELECT = `
  SELECT orders.*, clinics.name AS clinic_name,
    mt.name AS modeling_technician_name, ct.name AS ceramist_technician_name, ctc.name AS cadcam_technician_name
  FROM orders
  JOIN clinics ON clinics.id = orders.clinic_id
  LEFT JOIN users mt ON mt.id = orders.modeling_technician_id
  LEFT JOIN users ct ON ct.id = orders.ceramist_technician_id
  LEFT JOIN users ctc ON ctc.id = orders.cadcam_technician_id
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

app.get("/api/clinics", requireAuth(), (req, res) => {
  const clinics = db.prepare(`
    SELECT clinics.*,
      (SELECT COUNT(*) FROM doctors WHERE doctors.clinic_id = clinics.id) AS doctor_count,
      (SELECT COUNT(*) FROM orders WHERE orders.clinic_id = clinics.id) AS order_count
    FROM clinics ORDER BY name
  `).all();
  res.json(clinics.map((c) => ({ id: c.id, name: c.name, doctorCount: c.doctor_count, orderCount: c.order_count })));
});

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

app.post("/api/doctors", requireAuth(), (req, res) => {
  const { name, clinicId } = req.body;
  if (!name || !name.trim()) return res.status(400).json({ error: "name is required" });

  const targetClinicId = req.user.role === "clinic" ? req.user.clinicId : clinicId;
  if (!targetClinicId) return res.status(400).json({ error: "clinicId is required" });

  const info = db.prepare("INSERT INTO doctors (clinic_id, name) VALUES (?, ?)").run(targetClinicId, name.trim());
  res.status(201).json({ id: info.lastInsertRowid, name: name.trim(), clinicId: targetClinicId });
});

// ---------- Technicians (lab manages these accounts) ----------

app.get("/api/technicians", requireAuth(), (req, res) => {
  const rows = db.prepare("SELECT id, name FROM users WHERE role = 'technician' ORDER BY name").all();
  res.json(rows);
});

app.post("/api/technicians", requireAuth("lab"), (req, res) => {
  const { name, password } = req.body;
  if (!name || !name.trim()) return res.status(400).json({ error: "name is required" });
  if (!password || password.length < 4) return res.status(400).json({ error: "пароль должен быть не короче 4 символов" });

  const existing = db.prepare("SELECT id FROM users WHERE name = ?").get(name.trim());
  if (existing) return res.status(409).json({ error: "аккаунт с таким именем уже есть" });

  const hash = bcrypt.hashSync(password, 10);
  const info = db.prepare("INSERT INTO users (name, password_hash, role, clinic_id) VALUES (?, ?, 'technician', NULL)")
    .run(name.trim(), hash);
  res.status(201).json({ id: info.lastInsertRowid, name: name.trim() });
});

// Remove a technician account. Any tasks assigned to them are unassigned first.
app.delete("/api/technicians/:id", requireAuth("lab"), (req, res) => {
  const { id } = req.params;
  const tech = db.prepare("SELECT id FROM users WHERE id = ? AND role = 'technician'").get(id);
  if (!tech) return res.status(404).json({ error: "technician not found" });

  TASK_TYPES.forEach((t) => {
    db.prepare(`
      UPDATE orders SET ${t}_technician_id = NULL, ${t}_status = 'pending', ${t}_started_at = NULL, ${t}_completed_at = NULL
      WHERE ${t}_technician_id = ?
    `).run(id);
  });
  db.prepare("DELETE FROM users WHERE id = ?").run(id);
  res.json({ ok: true });
});

// ---------- Price list (lab-managed default prices per work type × task type) ----------

app.get("/api/price-list", requireAuth(), (req, res) => {
  const rows = db.prepare("SELECT * FROM price_list").all();
  res.json(rows.map((r) => ({ id: r.id, workType: r.work_type, taskType: r.task_type, price: r.price })));
});

app.post("/api/price-list", requireAuth("lab"), (req, res) => {
  const { workType, taskType, price } = req.body;
  if (!workType || !TASK_TYPES.includes(taskType) || price == null) {
    return res.status(400).json({ error: "workType, taskType, price are required" });
  }
  db.prepare(`
    INSERT INTO price_list (work_type, task_type, price) VALUES (?, ?, ?)
    ON CONFLICT(work_type, task_type) DO UPDATE SET price = excluded.price
  `).run(workType, taskType, price);
  res.json({ ok: true });
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
      tray_info, fitting_date_1, fitting_date_2, fitting_date_3, stage_index,
      modeling_status, ceramist_status, cadcam_status
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 'pending', 'pending', 'pending')
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
  const { taskType, technicianId, quantity, dueDate, price } = req.body;

  if (!TASK_TYPES.includes(taskType)) {
    return res.status(400).json({ error: "invalid taskType" });
  }

  const order = db.prepare("SELECT * FROM orders WHERE id = ?").get(id);
  if (!order) return res.status(404).json({ error: "order not found" });

  db.prepare(`
    UPDATE orders
    SET ${taskType}_technician_id = ?, ${taskType}_quantity = ?, ${taskType}_due_date = ?, ${taskType}_price = ?,
        ${taskType}_status = 'pending', ${taskType}_started_at = NULL, ${taskType}_completed_at = NULL,
        updated_at = datetime('now')
    WHERE id = ?
  `).run(technicianId || null, quantity || null, dueDate || null, price || null, id);

  const row = db.prepare(`${ORDER_SELECT} WHERE orders.id = ?`).get(id);
  res.json(serializeOrder(row));
});

app.get("/api/orders/:id/history", requireAuth(), (req, res) => {
  const { id } = req.params;
  const events = db.prepare("SELECT stage_index, changed_at FROM stage_events WHERE order_id = ? ORDER BY changed_at ASC").all(id);
  res.json(events.map((e) => ({ stage: STAGES[e.stage_index], changedAt: e.changed_at })));
});

// ---------- Technician's own task queue ----------

function taskRowToTask(row, taskType) {
  return {
    orderId: row.id,
    taskType,
    patient: row.patient,
    clinic: row.clinic_name,
    workType: row.work_type,
    quantity: row[`${taskType}_quantity`],
    dueDate: row[`${taskType}_due_date`],
    price: row[`${taskType}_price`],
    status: row[`${taskType}_status`],
    startedAt: row[`${taskType}_started_at`],
    completedAt: row[`${taskType}_completed_at`],
  };
}

app.get("/api/tasks/mine", requireAuth("technician"), (req, res) => {
  const rows = db.prepare(`
    SELECT orders.*, clinics.name AS clinic_name FROM orders
    JOIN clinics ON clinics.id = orders.clinic_id
    WHERE orders.modeling_technician_id = ? OR orders.ceramist_technician_id = ? OR orders.cadcam_technician_id = ?
  `).all(req.user.userId, req.user.userId, req.user.userId);

  const tasks = [];
  rows.forEach((row) => {
    TASK_TYPES.forEach((t) => {
      if (row[`${t}_technician_id`] === req.user.userId) tasks.push(taskRowToTask(row, t));
    });
  });
  res.json(tasks);
});

app.get("/api/tasks/stats", requireAuth("technician"), (req, res) => {
  const rows = db.prepare(`
    SELECT * FROM orders
    WHERE modeling_technician_id = ? OR ceramist_technician_id = ? OR cadcam_technician_id = ?
  `).all(req.user.userId, req.user.userId, req.user.userId);

  const today = new Date().toISOString().slice(0, 10);
  let inProgress = 0, completedToday = 0, earnedToday = 0;

  rows.forEach((row) => {
    TASK_TYPES.forEach((t) => {
      if (row[`${t}_technician_id`] !== req.user.userId) return;
      if (row[`${t}_status`] === "in_progress") inProgress++;
      if (row[`${t}_status`] === "done" && (row[`${t}_completed_at`] || "").slice(0, 10) === today) {
        completedToday++;
        earnedToday += row[`${t}_price`] || 0;
      }
    });
  });

  res.json({ inProgress, completedToday, earnedToday });
});

app.patch("/api/tasks/:orderId/:taskType/:action", requireAuth("technician"), (req, res) => {
  const { orderId, taskType, action } = req.params;
  if (!TASK_TYPES.includes(taskType)) return res.status(400).json({ error: "invalid taskType" });
  if (!["start", "complete"].includes(action)) return res.status(400).json({ error: "invalid action" });

  const order = db.prepare("SELECT * FROM orders WHERE id = ?").get(orderId);
  if (!order) return res.status(404).json({ error: "order not found" });
  if (order[`${taskType}_technician_id`] !== req.user.userId) {
    return res.status(403).json({ error: "эта задача не назначена на вас" });
  }

  if (action === "start") {
    db.prepare(`UPDATE orders SET ${taskType}_status = 'in_progress', ${taskType}_started_at = datetime('now') WHERE id = ?`).run(orderId);
  } else {
    db.prepare(`UPDATE orders SET ${taskType}_status = 'done', ${taskType}_completed_at = datetime('now') WHERE id = ?`).run(orderId);
  }

  res.json({ ok: true });
});

// ---------- Lab-wide statistics ----------

// Per-technician totals: how many tasks completed and how much earned (all-time + today).
app.get("/api/stats/overview", requireAuth("lab"), (req, res) => {
  const technicians = db.prepare("SELECT id, name FROM users WHERE role = 'technician' ORDER BY name").all();
  const rows = db.prepare("SELECT * FROM orders").all();
  const today = new Date().toISOString().slice(0, 10);

  const result = technicians.map((tech) => {
    let completedTotal = 0, earnedTotal = 0, completedToday = 0, earnedToday = 0, inProgress = 0;
    rows.forEach((row) => {
      TASK_TYPES.forEach((t) => {
        if (row[`${t}_technician_id`] !== tech.id) return;
        if (row[`${t}_status`] === "in_progress") inProgress++;
        if (row[`${t}_status`] === "done") {
          completedTotal++;
          earnedTotal += row[`${t}_price`] || 0;
          if ((row[`${t}_completed_at`] || "").slice(0, 10) === today) {
            completedToday++;
            earnedToday += row[`${t}_price`] || 0;
          }
        }
      });
    });
    return { id: tech.id, name: tech.name, completedTotal, earnedTotal, completedToday, earnedToday, inProgress };
  });

  res.json(result);
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`Dental lab tracker API running on http://localhost:${PORT}`);
});

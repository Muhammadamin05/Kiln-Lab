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
const TRIAL_DAYS = db.TRIAL_DAYS || 14;
const FREE_CLINIC_LIMIT = 2;
const FREE_TECH_LIMIT = 1;

// ---------- Plan / tenant helpers ----------

function getLab(labId) {
  return db.prepare("SELECT * FROM labs WHERE id = ?").get(labId);
}

// Works out whether a lab is currently on an unrestricted plan (trial still
// running, or paid), or has fallen back to the limited free tier.
function getPlanStatus(lab) {
  const now = new Date();
  const trialEndsAt = lab.trial_ends_at ? new Date(lab.trial_ends_at) : null;
  const trialActive = lab.plan === "trial" && trialEndsAt && trialEndsAt > now;
  const unrestricted = lab.plan === "paid" || trialActive;
  const daysLeft = trialActive ? Math.max(0, Math.ceil((trialEndsAt - now) / (24 * 60 * 60 * 1000))) : 0;
  return {
    plan: lab.plan,
    trialActive,
    unrestricted,
    daysLeft,
    trialEndsAt: lab.trial_ends_at,
    limits: unrestricted ? null : { clinics: FREE_CLINIC_LIMIT, technicians: FREE_TECH_LIMIT },
  };
}

function requireWithinClinicLimit(labId, res) {
  const lab = getLab(labId);
  const status = getPlanStatus(lab);
  if (status.unrestricted) return true;
  const count = db.prepare("SELECT COUNT(*) AS n FROM clinics WHERE lab_id = ?").get(labId).n;
  if (count >= FREE_CLINIC_LIMIT) {
    res.status(402).json({ error: `На бесплатном тарифе доступно не больше ${FREE_CLINIC_LIMIT} клиник. Оформите платный тариф.` });
    return false;
  }
  return true;
}

function requireWithinTechLimit(labId, res) {
  const lab = getLab(labId);
  const status = getPlanStatus(lab);
  if (status.unrestricted) return true;
  const count = db.prepare("SELECT COUNT(*) AS n FROM users WHERE lab_id = ? AND role = 'technician'").get(labId).n;
  if (count >= FREE_TECH_LIMIT) {
    res.status(402).json({ error: `На бесплатном тарифе доступен не больше ${FREE_TECH_LIMIT} техник(а). Оформите платный тариф.` });
    return false;
  }
  return true;
}

// Resolve the lab_id that a request's data belongs to, regardless of role.
function labIdForRequest(req) {
  return req.user.labId;
}

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
  SELECT orders.*, clinics.name AS clinic_name, clinics.lab_id AS lab_id,
    mt.name AS modeling_technician_name, ct.name AS ceramist_technician_name, ctc.name AS cadcam_technician_name
  FROM orders
  JOIN clinics ON clinics.id = orders.clinic_id
  LEFT JOIN users mt ON mt.id = orders.modeling_technician_id
  LEFT JOIN users ct ON ct.id = orders.ceramist_technician_id
  LEFT JOIN users ctc ON ctc.id = orders.cadcam_technician_id
`;

// ---------- Auth ----------

// A lab registers itself as a new tenant. Gets a 14-day unrestricted trial.
app.post("/api/auth/register-lab", (req, res) => {
  const { name, password } = req.body;
  if (!name || !name.trim()) return res.status(400).json({ error: "укажите название лаборатории" });
  if (!password || password.length < 4) return res.status(400).json({ error: "пароль должен быть не короче 4 символов" });

  const trimmedName = name.trim();
  const existing = db.prepare("SELECT id FROM labs WHERE name = ?").get(trimmedName);
  if (existing) return res.status(409).json({ error: "лаборатория с таким именем уже зарегистрирована" });

  const hash = bcrypt.hashSync(password, 10);
  const trialEndsAt = new Date(Date.now() + TRIAL_DAYS * 24 * 60 * 60 * 1000).toISOString();
  const info = db.prepare(
    "INSERT INTO labs (name, password_hash, plan, trial_ends_at) VALUES (?, ?, 'trial', ?)"
  ).run(trimmedName, hash, trialEndsAt);

  const token = signToken({ role: "lab", labId: info.lastInsertRowid, name: trimmedName });
  res.status(201).json({ token, role: "lab", name: trimmedName, labId: info.lastInsertRowid });
});

// A clinic registers under a specific lab (its network). Needs the lab's name to join.
app.post("/api/auth/register", (req, res) => {
  const { labName, clinicName, password } = req.body;
  if (!labName || !labName.trim()) return res.status(400).json({ error: "укажите название лаборатории, к которой подключаетесь" });
  if (!clinicName || !clinicName.trim()) return res.status(400).json({ error: "укажите название клиники" });
  if (!password || password.length < 4) return res.status(400).json({ error: "пароль должен быть не короче 4 символов" });

  const lab = db.prepare("SELECT * FROM labs WHERE name = ?").get(labName.trim());
  if (!lab) return res.status(404).json({ error: "лаборатория с таким названием не найдена" });

  const trimmedClinicName = clinicName.trim();
  const existingUser = db.prepare("SELECT id FROM users WHERE name = ? AND lab_id = ?").get(trimmedClinicName, lab.id);
  if (existingUser) return res.status(409).json({ error: "аккаунт с таким именем уже есть в этой лаборатории" });

  if (!requireWithinClinicLimit(lab.id, res)) return;

  let clinic = db.prepare("SELECT id FROM clinics WHERE name = ? AND lab_id = ?").get(trimmedClinicName, lab.id);
  if (!clinic) {
    const info = db.prepare("INSERT INTO clinics (lab_id, name) VALUES (?, ?)").run(lab.id, trimmedClinicName);
    clinic = { id: info.lastInsertRowid };
  }

  const hash = bcrypt.hashSync(password, 10);
  const userInfo = db.prepare(
    "INSERT INTO users (name, password_hash, role, clinic_id, lab_id) VALUES (?, ?, 'clinic', ?, ?)"
  ).run(trimmedClinicName, hash, clinic.id, lab.id);

  const token = signToken({ role: "clinic", labId: lab.id, clinicId: clinic.id, userId: userInfo.lastInsertRowid, name: trimmedClinicName });
  res.status(201).json({ token, role: "clinic", name: trimmedClinicName, clinicId: clinic.id, labId: lab.id });
});

// Single login for all roles: checks labs (lab owners) first, then users (clinics/technicians).
app.post("/api/auth/login", (req, res) => {
  const { name, password } = req.body;
  if (!name || !password) return res.status(400).json({ error: "укажите имя и пароль" });

  const lab = db.prepare("SELECT * FROM labs WHERE name = ?").get(name);
  if (lab && bcrypt.compareSync(password, lab.password_hash)) {
    const token = signToken({ role: "lab", labId: lab.id, name: lab.name });
    const status = getPlanStatus(lab);
    return res.json({ token, role: "lab", name: lab.name, labId: lab.id, plan: status.plan, trialActive: status.trialActive, daysLeft: status.daysLeft });
  }

  const user = db.prepare("SELECT * FROM users WHERE name = ? AND role IN ('clinic','technician')").get(name);
  if (user && bcrypt.compareSync(password, user.password_hash)) {
    const token = signToken({
      role: user.role, labId: user.lab_id, clinicId: user.clinic_id, userId: user.id,
      name: user.name, isSenior: !!user.is_senior,
    });
    return res.json({
      token, role: user.role, name: user.name, clinicId: user.clinic_id, labId: user.lab_id,
      isSenior: !!user.is_senior,
    });
  }

  res.status(401).json({ error: "неверное имя или пароль" });
});

app.post("/api/auth/change-password", requireAuth(), (req, res) => {
  const { newPassword } = req.body;
  if (!newPassword || newPassword.length < 4) {
    return res.status(400).json({ error: "пароль должен быть не короче 4 символов" });
  }
  const hash = bcrypt.hashSync(newPassword, 10);
  if (req.user.role === "lab") {
    db.prepare("UPDATE labs SET password_hash = ? WHERE id = ?").run(hash, req.user.labId);
  } else {
    db.prepare("UPDATE users SET password_hash = ? WHERE id = ?").run(hash, req.user.userId);
  }
  res.json({ ok: true });
});

// Current tenant's plan/trial/usage — used to show a "Тариф" screen.
app.get("/api/lab/status", requireAuth(), (req, res) => {
  const lab = getLab(labIdForRequest(req));
  if (!lab) return res.status(404).json({ error: "lab not found" });
  const status = getPlanStatus(lab);
  const clinicCount = db.prepare("SELECT COUNT(*) AS n FROM clinics WHERE lab_id = ?").get(lab.id).n;
  const techCount = db.prepare("SELECT COUNT(*) AS n FROM users WHERE lab_id = ? AND role = 'technician'").get(lab.id).n;
  res.json({ ...status, labName: lab.name, clinicCount, techCount });
});

// ---------- Clinics ----------

app.get("/api/clinics", requireAuth(), (req, res) => {
  const labId = labIdForRequest(req);
  const clinics = db.prepare(`
    SELECT clinics.*,
      (SELECT COUNT(*) FROM doctors WHERE doctors.clinic_id = clinics.id) AS doctor_count,
      (SELECT COUNT(*) FROM orders WHERE orders.clinic_id = clinics.id) AS order_count
    FROM clinics WHERE clinics.lab_id = ? ORDER BY name
  `).all(labId);
  res.json(clinics.map((c) => ({ id: c.id, name: c.name, doctorCount: c.doctor_count, orderCount: c.order_count })));
});

app.post("/api/clinics", requireAuth("lab"), (req, res) => {
  const { name } = req.body;
  if (!name || !name.trim()) return res.status(400).json({ error: "name is required" });
  if (!requireWithinClinicLimit(req.user.labId, res)) return;
  try {
    const info = db.prepare("INSERT INTO clinics (lab_id, name) VALUES (?, ?)").run(req.user.labId, name.trim());
    res.status(201).json({ id: info.lastInsertRowid, name: name.trim(), doctorCount: 0, orderCount: 0 });
  } catch (err) {
    res.status(409).json({ error: "клиника с таким именем уже есть" });
  }
});

// ---------- Doctors ----------

app.get("/api/doctors", requireAuth(), (req, res) => {
  const labId = labIdForRequest(req);
  let rows;
  if (req.user.role === "clinic") {
    rows = db.prepare("SELECT * FROM doctors WHERE clinic_id = ? ORDER BY name").all(req.user.clinicId);
  } else if (req.query.clinicId) {
    rows = db.prepare(`
      SELECT doctors.* FROM doctors
      JOIN clinics ON clinics.id = doctors.clinic_id
      WHERE doctors.clinic_id = ? AND clinics.lab_id = ? ORDER BY doctors.name
    `).all(req.query.clinicId, labId);
  } else {
    rows = db.prepare(`
      SELECT doctors.* FROM doctors
      JOIN clinics ON clinics.id = doctors.clinic_id
      WHERE clinics.lab_id = ? ORDER BY doctors.name
    `).all(labId);
  }
  res.json(rows.map((d) => ({ id: d.id, name: d.name, clinicId: d.clinic_id })));
});

app.post("/api/doctors", requireAuth(), (req, res) => {
  const { name, clinicId } = req.body;
  if (!name || !name.trim()) return res.status(400).json({ error: "name is required" });

  const targetClinicId = req.user.role === "clinic" ? req.user.clinicId : clinicId;
  if (!targetClinicId) return res.status(400).json({ error: "clinicId is required" });

  const clinic = db.prepare("SELECT * FROM clinics WHERE id = ? AND lab_id = ?").get(targetClinicId, labIdForRequest(req));
  if (!clinic) return res.status(404).json({ error: "clinic not found" });

  const info = db.prepare("INSERT INTO doctors (clinic_id, name) VALUES (?, ?)").run(targetClinicId, name.trim());
  res.status(201).json({ id: info.lastInsertRowid, name: name.trim(), clinicId: targetClinicId });
});

// ---------- Technicians ----------

app.get("/api/technicians", requireAuth(), (req, res) => {
  const rows = db.prepare("SELECT id, name, is_senior FROM users WHERE role = 'technician' AND lab_id = ? ORDER BY name")
    .all(labIdForRequest(req));
  res.json(rows.map((r) => ({ id: r.id, name: r.name, isSenior: !!r.is_senior })));
});

app.post("/api/technicians", requireAuth("lab"), (req, res) => {
  const { name, password, isSenior } = req.body;
  if (!name || !name.trim()) return res.status(400).json({ error: "name is required" });
  if (!password || password.length < 4) return res.status(400).json({ error: "пароль должен быть не короче 4 символов" });

  const existing = db.prepare("SELECT id FROM users WHERE name = ? AND lab_id = ?").get(name.trim(), req.user.labId);
  if (existing) return res.status(409).json({ error: "аккаунт с таким именем уже есть" });

  if (!requireWithinTechLimit(req.user.labId, res)) return;

  const hash = bcrypt.hashSync(password, 10);
  const info = db.prepare(
    "INSERT INTO users (name, password_hash, role, clinic_id, lab_id, is_senior) VALUES (?, ?, 'technician', NULL, ?, ?)"
  ).run(name.trim(), hash, req.user.labId, isSenior ? 1 : 0);
  res.status(201).json({ id: info.lastInsertRowid, name: name.trim(), isSenior: !!isSenior });
});

app.delete("/api/technicians/:id", requireAuth("lab"), (req, res) => {
  const { id } = req.params;
  const tech = db.prepare("SELECT id FROM users WHERE id = ? AND role = 'technician' AND lab_id = ?").get(id, req.user.labId);
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

// ---------- Price list ----------

app.get("/api/price-list", requireAuth(), (req, res) => {
  const rows = db.prepare("SELECT * FROM price_list WHERE lab_id = ?").all(labIdForRequest(req));
  res.json(rows.map((r) => ({ id: r.id, workType: r.work_type, taskType: r.task_type, price: r.price })));
});

app.post("/api/price-list", requireAuth("lab"), (req, res) => {
  const { workType, taskType, price } = req.body;
  if (!workType || !TASK_TYPES.includes(taskType) || price == null) {
    return res.status(400).json({ error: "workType, taskType, price are required" });
  }
  db.prepare(`
    INSERT INTO price_list (lab_id, work_type, task_type, price) VALUES (?, ?, ?, ?)
    ON CONFLICT(lab_id, work_type, task_type) DO UPDATE SET price = excluded.price
  `).run(req.user.labId, workType, taskType, price);
  res.json({ ok: true });
});

// ---------- Orders ----------

app.get("/api/orders", requireAuth(), (req, res) => {
  let rows;
  if (req.user.role === "clinic") {
    rows = db.prepare(`${ORDER_SELECT} WHERE orders.clinic_id = ? ORDER BY due_date ASC`).all(req.user.clinicId);
  } else {
    rows = db.prepare(`${ORDER_SELECT} WHERE clinics.lab_id = ? ORDER BY due_date ASC`).all(labIdForRequest(req));
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
  const order = db.prepare(`${ORDER_SELECT} WHERE orders.id = ?`).get(id);
  if (!order || order.lab_id !== req.user.labId) return res.status(404).json({ error: "order not found" });

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

  const order = db.prepare(`${ORDER_SELECT} WHERE orders.id = ?`).get(id);
  if (!order || order.lab_id !== req.user.labId) return res.status(404).json({ error: "order not found" });

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

function csvEscape(value) {
  if (value === null || value === undefined) return "";
  const str = String(value);
  if (/[",\n]/.test(str)) return `"${str.replace(/"/g, '""')}"`;
  return str;
}

app.get("/api/orders/export.csv", requireAuth(), (req, res) => {
  let rows;
  if (req.user.role === "clinic") {
    rows = db.prepare(`${ORDER_SELECT} WHERE orders.clinic_id = ? ORDER BY due_date ASC`).all(req.user.clinicId);
  } else {
    rows = db.prepare(`${ORDER_SELECT} WHERE clinics.lab_id = ? ORDER BY due_date ASC`).all(labIdForRequest(req));
  }

  const header = [
    "Пациент", "Клиника", "Врач", "Тип работы", "Оттенок", "Зубы", "Срок сдачи", "Этап",
    "Моделировка (техник)", "Моделировка (сумма)", "Керамист (техник)", "Керамист (сумма)",
    "Cad/Cam (техник)", "Cad/Cam (сумма)",
  ];
  const lines = [header.map(csvEscape).join(",")];

  rows.forEach((row) => {
    const o = serializeOrder(row);
    lines.push([
      o.patient, o.clinic, o.doctor, o.workType, o.shade, o.toothPositions, o.dueDate, o.stage,
      o.modeling.technicianName, o.modeling.price, o.ceramist.technicianName, o.ceramist.price,
      o.cadcam.technicianName, o.cadcam.price,
    ].map(csvEscape).join(","));
  });

  const csv = "\uFEFF" + lines.join("\n");
  res.setHeader("Content-Type", "text/csv; charset=utf-8");
  res.setHeader("Content-Disposition", "attachment; filename=orders.csv");
  res.send(csv);
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
  const showAll = req.query.all === "true" && req.user.isSenior;

  if (showAll) {
    const rows = db.prepare(`${ORDER_SELECT} WHERE clinics.lab_id = ?`).all(req.user.labId);
    const tasks = [];
    rows.forEach((row) => {
      TASK_TYPES.forEach((t) => {
        if (!row[`${t}_technician_id`]) return;
        const task = taskRowToTask(row, t);
        task.technicianName = row[`${t}_technician_name`];
        task.mine = row[`${t}_technician_id`] === req.user.userId;
        if (!task.mine) task.price = null;
        tasks.push(task);
      });
    });
    return res.json(tasks);
  }

  const rows = db.prepare(`
    SELECT orders.*, clinics.name AS clinic_name FROM orders
    JOIN clinics ON clinics.id = orders.clinic_id
    WHERE orders.modeling_technician_id = ? OR orders.ceramist_technician_id = ? OR orders.cadcam_technician_id = ?
  `).all(req.user.userId, req.user.userId, req.user.userId);

  const tasks = [];
  rows.forEach((row) => {
    TASK_TYPES.forEach((t) => {
      if (row[`${t}_technician_id`] === req.user.userId) {
        const task = taskRowToTask(row, t);
        task.mine = true;
        tasks.push(task);
      }
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

app.get("/api/stats/overview", requireAuth("lab"), (req, res) => {
  const technicians = db.prepare("SELECT id, name FROM users WHERE role = 'technician' AND lab_id = ? ORDER BY name").all(req.user.labId);
  const rows = db.prepare(`${ORDER_SELECT} WHERE clinics.lab_id = ?`).all(req.user.labId);
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

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

function logAudit(labId, actor, entityType, entityId, action, details) {
  db.prepare(`
    INSERT INTO audit_events (lab_id, actor_name, actor_role, entity_type, entity_id, action, details)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `).run(labId, actor.name, actor.role, entityType, entityId || null, action, details ? JSON.stringify(details) : null);
}

function notify({ labId, clinicId, role, message, orderId }) {
  db.prepare(`
    INSERT INTO notifications (recipient_role, recipient_clinic_id, recipient_lab_id, type, message, order_id)
    VALUES (?, ?, ?, 'order_event', ?, ?)
  `).run(role, clinicId || null, labId || null, message, orderId || null);
}

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
    fileLink: row.file_link,
    clinicPriceSnapshot: row.clinic_price_snapshot,
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
      (SELECT COUNT(*) FROM orders WHERE orders.clinic_id = clinics.id) AS order_count,
      (SELECT MAX(created_at) FROM orders WHERE orders.clinic_id = clinics.id) AS last_order_at
    FROM clinics WHERE clinics.lab_id = ? ORDER BY name
  `).all(labId);
  res.json(clinics.map((c) => ({ id: c.id, name: c.name, doctorCount: c.doctor_count, orderCount: c.order_count, lastOrderAt: c.last_order_at })));
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
    trayInfo, fittingDates, fileLink,
  } = req.body;

  if (!patient || !patient.trim()) return res.status(400).json({ error: "patient is required" });
  if (!workType || !workType.trim()) return res.status(400).json({ error: "workType is required" });
  if (!dueDate) return res.status(400).json({ error: "dueDate is required" });

  const fd = Array.isArray(fittingDates) ? fittingDates : [];

  // Price snapshot: what THIS clinic pays for this work type, frozen at order time.
  // Falls back to null (lab fills it in manually) if no clinic price book entry exists yet.
  const priceRow = db.prepare("SELECT price FROM clinic_price_book WHERE clinic_id = ? AND work_type = ?")
    .get(req.user.clinicId, workType.trim());
  const priceSnapshot = priceRow ? priceRow.price : null;

  const info = db.prepare(`
    INSERT INTO orders (
      patient, clinic_id, doctor, tooth_count, tooth_positions, work_type, shade, due_date,
      tray_info, fitting_date_1, fitting_date_2, fitting_date_3, stage_index,
      modeling_status, ceramist_status, cadcam_status, file_link, clinic_price_snapshot
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 'pending', 'pending', 'pending', ?, ?)
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
    fd[2] || null,
    fileLink ? fileLink.trim() : null,
    priceSnapshot
  );

  db.prepare("INSERT INTO stage_events (order_id, stage_index) VALUES (?, 0)").run(info.lastInsertRowid);

  const clinic = db.prepare("SELECT lab_id FROM clinics WHERE id = ?").get(req.user.clinicId);
  logAudit(clinic.lab_id, req.user, "order", info.lastInsertRowid, "created", { patient: patient.trim() });
  notify({ labId: clinic.lab_id, role: "lab", message: `Новый заказ от клиники: ${patient.trim()}`, orderId: info.lastInsertRowid });

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
  logAudit(req.user.labId, req.user, "order", id, "stage_changed", { stage: STAGES[nextStage] });
  if (STAGES[nextStage] === "Готово") {
    notify({ clinicId: order.clinic_id, role: "clinic", message: `Заказ «${order.patient}» готов`, orderId: id });
  }

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

// ---------- Clinic price book (what clinics pay, separate from technician payouts) ----------

app.get("/api/clinic-price-book/:clinicId", requireAuth(), (req, res) => {
  const { clinicId } = req.params;
  const rows = db.prepare("SELECT * FROM clinic_price_book WHERE clinic_id = ?").all(clinicId);
  res.json(rows.map((r) => ({ id: r.id, workType: r.work_type, price: r.price })));
});

app.post("/api/clinic-price-book/:clinicId", requireAuth("lab"), (req, res) => {
  const { clinicId } = req.params;
  const { workType, price } = req.body;
  if (!workType || price == null) return res.status(400).json({ error: "workType and price are required" });
  db.prepare(`
    INSERT INTO clinic_price_book (lab_id, clinic_id, work_type, price) VALUES (?, ?, ?, ?)
    ON CONFLICT(clinic_id, work_type) DO UPDATE SET price = excluded.price
  `).run(req.user.labId, clinicId, workType, price);
  res.json({ ok: true });
});

// ---------- Invoices & payments ----------

app.post("/api/orders/:id/invoice", requireAuth("lab"), (req, res) => {
  const { id } = req.params;
  const order = db.prepare(`${ORDER_SELECT} WHERE orders.id = ?`).get(id);
  if (!order || order.lab_id !== req.user.labId) return res.status(404).json({ error: "order not found" });

  const existing = db.prepare("SELECT * FROM invoices WHERE order_id = ?").get(id);
  if (existing) return res.status(409).json({ error: "счёт по этому заказу уже создан" });

  const amount = order.clinic_price_snapshot || 0;
  const info = db.prepare(`
    INSERT INTO invoices (order_id, lab_id, clinic_id, amount, status) VALUES (?, ?, ?, ?, 'draft')
  `).run(id, req.user.labId, order.clinic_id, amount);

  logAudit(req.user.labId, req.user, "invoice", info.lastInsertRowid, "created", { amount });
  res.status(201).json({ id: info.lastInsertRowid, orderId: Number(id), amount, status: "draft" });
});

app.patch("/api/invoices/:id/issue", requireAuth("lab"), (req, res) => {
  const { id } = req.params;
  const invoice = db.prepare("SELECT * FROM invoices WHERE id = ? AND lab_id = ?").get(id, req.user.labId);
  if (!invoice) return res.status(404).json({ error: "invoice not found" });

  db.prepare("UPDATE invoices SET status = 'issued', issued_at = datetime('now') WHERE id = ?").run(id);
  logAudit(req.user.labId, req.user, "invoice", id, "issued", null);
  notify({ clinicId: invoice.clinic_id, role: "clinic", message: `Выставлен счёт на ${invoice.amount} ₽`, orderId: invoice.order_id });
  res.json({ ok: true });
});

function recomputeInvoiceStatus(invoiceId) {
  const invoice = db.prepare("SELECT * FROM invoices WHERE id = ?").get(invoiceId);
  const paid = db.prepare("SELECT COALESCE(SUM(amount),0) AS total FROM payments WHERE invoice_id = ?").get(invoiceId).total;
  let status = invoice.status === "draft" ? "draft" : "issued";
  if (paid >= invoice.amount && invoice.amount > 0) status = "paid";
  else if (paid > 0) status = "partially_paid";
  db.prepare("UPDATE invoices SET status = ? WHERE id = ?").run(status, invoiceId);
}

app.post("/api/invoices/:id/payments", requireAuth("lab"), (req, res) => {
  const { id } = req.params;
  const { amount, method, paidAt, comment } = req.body;
  if (!amount || amount <= 0) return res.status(400).json({ error: "amount must be positive" });

  const invoice = db.prepare("SELECT * FROM invoices WHERE id = ? AND lab_id = ?").get(id, req.user.labId);
  if (!invoice) return res.status(404).json({ error: "invoice not found" });

  db.prepare("INSERT INTO payments (invoice_id, amount, method, paid_at, comment) VALUES (?, ?, ?, ?, ?)")
    .run(id, amount, method || "cash", paidAt || new Date().toISOString().slice(0, 10), comment || null);
  recomputeInvoiceStatus(id);
  logAudit(req.user.labId, req.user, "payment", id, "recorded", { amount, method });
  notify({ clinicId: invoice.clinic_id, role: "clinic", message: `Зафиксирован платёж: ${amount} ₽`, orderId: invoice.order_id });

  const updated = db.prepare("SELECT * FROM invoices WHERE id = ?").get(id);
  res.status(201).json({ ok: true, invoiceStatus: updated.status });
});

app.get("/api/invoices", requireAuth(), (req, res) => {
  let rows;
  if (req.user.role === "clinic") {
    rows = db.prepare(`
      SELECT invoices.*, orders.patient FROM invoices
      JOIN orders ON orders.id = invoices.order_id
      WHERE invoices.clinic_id = ? ORDER BY invoices.created_at DESC
    `).all(req.user.clinicId);
  } else {
    rows = db.prepare(`
      SELECT invoices.*, orders.patient, clinics.name AS clinic_name FROM invoices
      JOIN orders ON orders.id = invoices.order_id
      JOIN clinics ON clinics.id = invoices.clinic_id
      WHERE invoices.lab_id = ? ORDER BY invoices.created_at DESC
    `).all(req.user.labId);
  }
  res.json(rows.map((r) => ({
    id: r.id, orderId: r.order_id, patient: r.patient, clinic: r.clinic_name,
    amount: r.amount, status: r.status, issuedAt: r.issued_at, createdAt: r.created_at,
  })));
});

app.get("/api/invoices/:id/payments", requireAuth(), (req, res) => {
  const rows = db.prepare("SELECT * FROM payments WHERE invoice_id = ? ORDER BY paid_at ASC").all(req.params.id);
  res.json(rows.map((r) => ({ id: r.id, amount: r.amount, method: r.method, paidAt: r.paid_at, comment: r.comment })));
});

// ---------- Deliveries & couriers ----------

app.post("/api/orders/:id/delivery", requireAuth("lab"), (req, res) => {
  const { id } = req.params;
  const { deliveryType, address, windowStart, windowEnd } = req.body;
  if (!deliveryType || !address) return res.status(400).json({ error: "deliveryType and address are required" });

  const info = db.prepare(`
    INSERT INTO deliveries (order_id, delivery_type, address, window_start, window_end, status)
    VALUES (?, ?, ?, ?, ?, 'unassigned')
  `).run(id, deliveryType, address, windowStart || null, windowEnd || null);
  logAudit(req.user.labId, req.user, "delivery", info.lastInsertRowid, "created", { deliveryType });
  res.status(201).json({ id: info.lastInsertRowid, status: "unassigned" });
});

app.get("/api/deliveries", requireAuth(), (req, res) => {
  let rows;
  if (req.user.role === "courier") {
    rows = db.prepare(`
      SELECT deliveries.*, orders.patient, clinics.name AS clinic_name FROM deliveries
      JOIN orders ON orders.id = deliveries.order_id
      JOIN clinics ON clinics.id = orders.clinic_id
      WHERE deliveries.courier_id = ? ORDER BY deliveries.window_start ASC
    `).all(req.user.userId);
  } else if (req.user.role === "lab") {
    rows = db.prepare(`
      SELECT deliveries.*, orders.patient, clinics.name AS clinic_name, u.name AS courier_name FROM deliveries
      JOIN orders ON orders.id = deliveries.order_id
      JOIN clinics ON clinics.id = orders.clinic_id
      LEFT JOIN users u ON u.id = deliveries.courier_id
      WHERE clinics.lab_id = ? ORDER BY deliveries.updated_at DESC
    `).all(req.user.labId);
  } else {
    rows = db.prepare(`
      SELECT deliveries.*, orders.patient FROM deliveries
      JOIN orders ON orders.id = deliveries.order_id
      WHERE orders.clinic_id = ? ORDER BY deliveries.updated_at DESC
    `).all(req.user.clinicId);
  }
  res.json(rows.map((r) => ({
    id: r.id, orderId: r.order_id, patient: r.patient, clinic: r.clinic_name,
    deliveryType: r.delivery_type, address: r.address, windowStart: r.window_start, windowEnd: r.window_end,
    courierId: r.courier_id, courierName: r.courier_name, status: r.status, statusNote: r.status_note,
  })));
});

app.patch("/api/deliveries/:id/assign", requireAuth("lab"), (req, res) => {
  const { id } = req.params;
  const { courierId } = req.body;
  db.prepare("UPDATE deliveries SET courier_id = ?, status = 'assigned', updated_at = datetime('now') WHERE id = ?").run(courierId, id);
  logAudit(req.user.labId, req.user, "delivery", id, "assigned", { courierId });
  res.json({ ok: true });
});

app.patch("/api/deliveries/:id/status", requireAuth(), (req, res) => {
  const { id } = req.params;
  const { status, note } = req.body;
  const valid = ["en_route", "arrived", "picked_up", "delivered"];
  if (!valid.includes(status)) return res.status(400).json({ error: "invalid status" });

  if (req.user.role === "courier") {
    const delivery = db.prepare("SELECT * FROM deliveries WHERE id = ?").get(id);
    if (!delivery || delivery.courier_id !== req.user.userId) return res.status(403).json({ error: "not your delivery" });
  }

  db.prepare("UPDATE deliveries SET status = ?, status_note = ?, updated_at = datetime('now') WHERE id = ?").run(status, note || null, id);
  logAudit(req.user.labId || null, req.user, "delivery", id, "status_changed", { status });
  res.json({ ok: true });
});

// ---------- Couriers (lab manages accounts, like technicians) ----------

app.get("/api/couriers", requireAuth("lab"), (req, res) => {
  const rows = db.prepare("SELECT id, name FROM users WHERE role = 'courier' AND lab_id = ? ORDER BY name").all(req.user.labId);
  res.json(rows);
});

app.post("/api/couriers", requireAuth("lab"), (req, res) => {
  const { name, password } = req.body;
  if (!name || !name.trim()) return res.status(400).json({ error: "name is required" });
  if (!password || password.length < 4) return res.status(400).json({ error: "пароль должен быть не короче 4 символов" });

  const existing = db.prepare("SELECT id FROM users WHERE name = ? AND lab_id = ?").get(name.trim(), req.user.labId);
  if (existing) return res.status(409).json({ error: "аккаунт с таким именем уже есть" });

  const hash = bcrypt.hashSync(password, 10);
  const info = db.prepare("INSERT INTO users (name, password_hash, role, clinic_id, lab_id) VALUES (?, ?, 'courier', NULL, ?)")
    .run(name.trim(), hash, req.user.labId);
  res.status(201).json({ id: info.lastInsertRowid, name: name.trim() });
});

// ---------- Notifications ----------

app.get("/api/notifications", requireAuth(), (req, res) => {
  let rows;
  if (req.user.role === "clinic") {
    rows = db.prepare("SELECT * FROM notifications WHERE recipient_role = 'clinic' AND recipient_clinic_id = ? ORDER BY created_at DESC LIMIT 30").all(req.user.clinicId);
  } else if (req.user.role === "lab") {
    rows = db.prepare("SELECT * FROM notifications WHERE recipient_role = 'lab' AND recipient_lab_id = ? ORDER BY created_at DESC LIMIT 30").all(req.user.labId);
  } else {
    rows = [];
  }
  res.json(rows.map((r) => ({ id: r.id, message: r.message, orderId: r.order_id, isRead: !!r.is_read, createdAt: r.created_at })));
});

app.patch("/api/notifications/:id/read", requireAuth(), (req, res) => {
  db.prepare("UPDATE notifications SET is_read = 1 WHERE id = ?").run(req.params.id);
  res.json({ ok: true });
});

// ---------- Audit log ----------

app.get("/api/audit-events", requireAuth("lab"), (req, res) => {
  const rows = db.prepare("SELECT * FROM audit_events WHERE lab_id = ? ORDER BY created_at DESC LIMIT 100").all(req.user.labId);
  res.json(rows.map((r) => ({
    id: r.id, actorName: r.actor_name, actorRole: r.actor_role, entityType: r.entity_type,
    entityId: r.entity_id, action: r.action, details: r.details ? JSON.parse(r.details) : null, createdAt: r.created_at,
  })));
});

// ---------- Order comments ----------

function orderBelongsToRequester(order, req) {
  if (!order) return false;
  if (req.user.role === "clinic") return order.clinic_id === req.user.clinicId;
  return order.lab_id === req.user.labId;
}

app.get("/api/orders/:id/comments", requireAuth(), (req, res) => {
  const { id } = req.params;
  const order = db.prepare(`${ORDER_SELECT} WHERE orders.id = ?`).get(id);
  if (!orderBelongsToRequester(order, req)) return res.status(404).json({ error: "order not found" });

  const rows = db.prepare("SELECT * FROM order_comments WHERE order_id = ? ORDER BY created_at ASC").all(id);
  res.json(rows.map((r) => ({ id: r.id, authorName: r.author_name, authorRole: r.author_role, text: r.text, createdAt: r.created_at })));
});

app.post("/api/orders/:id/comments", requireAuth(), (req, res) => {
  const { id } = req.params;
  const { text } = req.body;
  if (!text || !text.trim()) return res.status(400).json({ error: "text is required" });

  const order = db.prepare(`${ORDER_SELECT} WHERE orders.id = ?`).get(id);
  if (!orderBelongsToRequester(order, req)) return res.status(404).json({ error: "order not found" });

  const info = db.prepare("INSERT INTO order_comments (order_id, author_name, author_role, text) VALUES (?, ?, ?, ?)")
    .run(id, req.user.name, req.user.role, text.trim());
  const row = db.prepare("SELECT * FROM order_comments WHERE id = ?").get(info.lastInsertRowid);
  res.status(201).json({ id: row.id, authorName: row.author_name, authorRole: row.author_role, text: row.text, createdAt: row.created_at });
});

// ---------- Activity feed (lab-wide) ----------

app.get("/api/activity", requireAuth("lab"), (req, res) => {
  const stageEvents = db.prepare(`
    SELECT stage_events.changed_at AS at, orders.patient AS patient, clinics.name AS clinic, stage_events.stage_index AS stage_index
    FROM stage_events
    JOIN orders ON orders.id = stage_events.order_id
    JOIN clinics ON clinics.id = orders.clinic_id
    WHERE clinics.lab_id = ?
    ORDER BY stage_events.changed_at DESC LIMIT 20
  `).all(req.user.labId);

  const comments = db.prepare(`
    SELECT order_comments.created_at AS at, orders.patient AS patient, clinics.name AS clinic,
      order_comments.author_name AS author_name, order_comments.text AS text
    FROM order_comments
    JOIN orders ON orders.id = order_comments.order_id
    JOIN clinics ON clinics.id = orders.clinic_id
    WHERE clinics.lab_id = ?
    ORDER BY order_comments.created_at DESC LIMIT 20
  `).all(req.user.labId);

  const events = [
    ...stageEvents.map((e) => ({ type: "stage", at: e.at, patient: e.patient, clinic: e.clinic, stage: STAGES[e.stage_index] })),
    ...comments.map((c) => ({ type: "comment", at: c.at, patient: c.patient, clinic: c.clinic, author: c.author_name, text: c.text })),
  ].sort((a, b) => (a.at < b.at ? 1 : -1)).slice(0, 25);

  res.json(events);
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

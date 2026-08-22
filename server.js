const express = require("express");
const cors = require("cors");
const db = require("./db");
const { STAGES } = require("./stages");

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

// List clinics (for populating the "new order" form)
app.get("/api/clinics", (req, res) => {
  const clinics = db.prepare("SELECT id, name FROM clinics ORDER BY name").all();
  res.json(clinics);
});

app.post("/api/clinics", (req, res) => {
  const { name } = req.body;
  if (!name || !name.trim()) {
    return res.status(400).json({ error: "name is required" });
  }
  try {
    const info = db.prepare("INSERT INTO clinics (name) VALUES (?)").run(name.trim());
    res.status(201).json({ id: info.lastInsertRowid, name: name.trim() });
  } catch (err) {
    res.status(409).json({ error: "clinic already exists" });
  }
});

// List orders, newest due date first, optionally filtered by clinic
app.get("/api/orders", (req, res) => {
  const { clinicId } = req.query;
  let rows;
  if (clinicId) {
    rows = db.prepare(`${ORDER_SELECT} WHERE orders.clinic_id = ? ORDER BY due_date ASC`).all(clinicId);
  } else {
    rows = db.prepare(`${ORDER_SELECT} ORDER BY due_date ASC`).all();
  }
  res.json(rows.map(serializeOrder));
});

// Create a new order (clinic-side action)
app.post("/api/orders", (req, res) => {
  const { patient, clinicId, workType, shade, dueDate } = req.body;

  if (!patient || !patient.trim()) return res.status(400).json({ error: "patient is required" });
  if (!clinicId) return res.status(400).json({ error: "clinicId is required" });
  if (!workType || !workType.trim()) return res.status(400).json({ error: "workType is required" });
  if (!dueDate) return res.status(400).json({ error: "dueDate is required" });

  const clinic = db.prepare("SELECT id FROM clinics WHERE id = ?").get(clinicId);
  if (!clinic) return res.status(404).json({ error: "clinic not found" });

  const info = db.prepare(`
    INSERT INTO orders (patient, clinic_id, work_type, shade, due_date, stage_index)
    VALUES (?, ?, ?, ?, ?, 0)
  `).run(patient.trim(), clinicId, workType.trim(), shade || null, dueDate);

  db.prepare("INSERT INTO stage_events (order_id, stage_index) VALUES (?, 0)").run(info.lastInsertRowid);

  const row = db.prepare(`${ORDER_SELECT} WHERE orders.id = ?`).get(info.lastInsertRowid);
  res.status(201).json(serializeOrder(row));
});

// Advance an order to the next stage (lab-side action)
app.patch("/api/orders/:id/advance", (req, res) => {
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

// Full stage history for one order (useful for an audit trail / timeline view)
app.get("/api/orders/:id/history", (req, res) => {
  const { id } = req.params;
  const events = db.prepare("SELECT stage_index, changed_at FROM stage_events WHERE order_id = ? ORDER BY changed_at ASC").all(id);
  res.json(events.map((e) => ({ stage: STAGES[e.stage_index], changedAt: e.changed_at })));
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`Dental lab tracker API running on http://localhost:${PORT}`);
});

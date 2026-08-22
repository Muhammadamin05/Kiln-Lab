const Database = require("better-sqlite3");
const path = require("path");

const db = new Database(path.join(__dirname, "tracker.db"));
db.pragma("journal_mode = WAL");

db.exec(`
CREATE TABLE IF NOT EXISTS clinics (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS orders (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  patient TEXT NOT NULL,
  clinic_id INTEGER NOT NULL REFERENCES clinics(id),
  work_type TEXT NOT NULL,
  shade TEXT,
  due_date TEXT NOT NULL,
  stage_index INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS stage_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  order_id INTEGER NOT NULL REFERENCES orders(id),
  stage_index INTEGER NOT NULL,
  changed_at TEXT NOT NULL DEFAULT (datetime('now'))
);
`);

const seedCount = db.prepare("SELECT COUNT(*) AS n FROM clinics").get().n;
if (seedCount === 0) {
  const insertClinic = db.prepare("INSERT INTO clinics (name) VALUES (?)");
  ["Дентал+", "Смайл клиник", "Ортодонт-1"].forEach((name) => insertClinic.run(name));
}

module.exports = db;

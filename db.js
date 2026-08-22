const Database = require("better-sqlite3");
const path = require("path");
const bcrypt = require("bcryptjs");

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

CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('lab', 'clinic')),
  clinic_id INTEGER REFERENCES clinics(id),
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
`);

const clinicCount = db.prepare("SELECT COUNT(*) AS n FROM clinics").get().n;
if (clinicCount === 0) {
  const insertClinic = db.prepare("INSERT INTO clinics (name) VALUES (?)");
  ["Дентал+", "Смайл клиник", "Ортодонт-1"].forEach((name) => insertClinic.run(name));
}

const userCount = db.prepare("SELECT COUNT(*) AS n FROM users").get().n;
if (userCount === 0) {
  const insertUser = db.prepare(
    "INSERT INTO users (name, password_hash, role, clinic_id) VALUES (?, ?, ?, ?)"
  );

  const labHash = bcrypt.hashSync("lab123", 10);
  insertUser.run("Лаборатория", labHash, "lab", null);

  const clinics = db.prepare("SELECT id, name FROM clinics").all();
  const clinicHash = bcrypt.hashSync("clinic123", 10);
  clinics.forEach((c) => {
    insertUser.run(c.name, clinicHash, "clinic", c.id);
  });

  console.log("Созданы аккаунты по умолчанию:");
  console.log("  Лаборатория — пароль: lab123");
  clinics.forEach((c) => console.log(`  ${c.name} — пароль: clinic123`));
  console.log("Смени эти пароли после первого входа.");
}

module.exports = db;

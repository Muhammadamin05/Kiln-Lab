const Database = require("better-sqlite3");
const path = require("path");
const bcrypt = require("bcryptjs");

const db = new Database(path.join(__dirname, "tracker.db"));
db.pragma("journal_mode = WAL");

db.exec(`
CREATE TABLE IF NOT EXISTS schema_meta (
  key TEXT PRIMARY KEY,
  value TEXT
);

CREATE TABLE IF NOT EXISTS clinics (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS doctors (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  clinic_id INTEGER NOT NULL REFERENCES clinics(id),
  name TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
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
  role TEXT NOT NULL,
  clinic_id INTEGER REFERENCES clinics(id),
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
`);

// One-time migration: older deployments created `users.role` with a CHECK
// constraint limited to ('lab','clinic'). Rebuild the table without that
// restriction so 'technician' accounts can be inserted too.
const migrated = db.prepare("SELECT value FROM schema_meta WHERE key = 'users_role_open'").get();
if (!migrated) {
  db.exec(`
    CREATE TABLE users_new (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL,
      clinic_id INTEGER REFERENCES clinics(id),
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );
    INSERT INTO users_new SELECT id, name, password_hash, role, clinic_id, created_at FROM users;
    DROP TABLE users;
    ALTER TABLE users_new RENAME TO users;
  `);
  db.prepare("INSERT INTO schema_meta (key, value) VALUES ('users_role_open', '1')").run();
}

function ensureColumn(table, column, definition) {
  const cols = db.prepare(`PRAGMA table_info(${table})`).all();
  const exists = cols.some((c) => c.name === column);
  if (!exists) {
    db.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`);
  }
}

ensureColumn("orders", "doctor", "TEXT");
ensureColumn("orders", "tooth_count", "INTEGER");
ensureColumn("orders", "tooth_positions", "TEXT");
ensureColumn("orders", "tray_info", "TEXT");
ensureColumn("orders", "fitting_date_1", "TEXT");
ensureColumn("orders", "fitting_date_2", "TEXT");
ensureColumn("orders", "fitting_date_3", "TEXT");

["modeling", "ceramist"].forEach((prefix) => {
  ensureColumn("orders", `${prefix}_technician_id`, "INTEGER REFERENCES users(id)");
  ensureColumn("orders", `${prefix}_quantity`, "INTEGER");
  ensureColumn("orders", `${prefix}_due_date`, "TEXT");
  ensureColumn("orders", `${prefix}_price`, "REAL");
  ensureColumn("orders", `${prefix}_status`, "TEXT DEFAULT 'pending'");
  ensureColumn("orders", `${prefix}_started_at`, "TEXT");
  ensureColumn("orders", `${prefix}_completed_at`, "TEXT");
});

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

  const techHash = bcrypt.hashSync("tech123", 10);
  insertUser.run("Техник 1", techHash, "technician", null);

  console.log("Созданы аккаунты по умолчанию:");
  console.log("  Лаборатория — пароль: lab123");
  clinics.forEach((c) => console.log(`  ${c.name} — пароль: clinic123`));
  console.log("  Техник 1 — пароль: tech123");
  console.log("Смени эти пароли после первого входа.");
}

module.exports = db;

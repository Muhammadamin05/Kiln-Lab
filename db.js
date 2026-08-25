const Database = require("better-sqlite3");
const path = require("path");
const bcrypt = require("bcryptjs");

const db = new Database(path.join(__dirname, "tracker.db"));
db.pragma("journal_mode = WAL");

const TRIAL_DAYS = 14;

db.exec(`
CREATE TABLE IF NOT EXISTS schema_meta (
  key TEXT PRIMARY KEY,
  value TEXT
);

-- A lab is a tenant: its own isolated space with clinics, technicians, orders.
CREATE TABLE IF NOT EXISTS labs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  plan TEXT NOT NULL DEFAULT 'trial',
  trial_ends_at TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS clinics (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  lab_id INTEGER REFERENCES labs(id),
  name TEXT NOT NULL
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

-- Clinic and technician logins. Each belongs to exactly one lab via lab_id.
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL,
  clinic_id INTEGER REFERENCES clinics(id),
  lab_id INTEGER REFERENCES labs(id),
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS price_list (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  lab_id INTEGER REFERENCES labs(id),
  work_type TEXT NOT NULL,
  task_type TEXT NOT NULL,
  price REAL NOT NULL,
  UNIQUE(lab_id, work_type, task_type)
);

CREATE TABLE IF NOT EXISTS order_comments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  order_id INTEGER NOT NULL REFERENCES orders(id),
  author_name TEXT NOT NULL,
  author_role TEXT NOT NULL,
  text TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
`);

function ensureColumn(table, column, definition) {
  const cols = db.prepare(`PRAGMA table_info(${table})`).all();
  const exists = cols.some((c) => c.name === column);
  if (!exists) {
    db.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`);
  }
}

// Older deployments had users.role restricted by a CHECK constraint and no lab_id column.
const rolesMigrated = db.prepare("SELECT value FROM schema_meta WHERE key = 'users_role_open'").get();
if (!rolesMigrated) {
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

ensureColumn("orders", "doctor", "TEXT");
ensureColumn("orders", "tooth_count", "INTEGER");
ensureColumn("orders", "tooth_positions", "TEXT");
ensureColumn("orders", "tray_info", "TEXT");
ensureColumn("orders", "fitting_date_1", "TEXT");
ensureColumn("orders", "fitting_date_2", "TEXT");
ensureColumn("orders", "fitting_date_3", "TEXT");

["modeling", "ceramist", "cadcam"].forEach((prefix) => {
  ensureColumn("orders", `${prefix}_technician_id`, "INTEGER REFERENCES users(id)");
  ensureColumn("orders", `${prefix}_quantity`, "INTEGER");
  ensureColumn("orders", `${prefix}_due_date`, "TEXT");
  ensureColumn("orders", `${prefix}_price`, "REAL");
  ensureColumn("orders", `${prefix}_status`, "TEXT DEFAULT 'pending'");
  ensureColumn("orders", `${prefix}_started_at`, "TEXT");
  ensureColumn("orders", `${prefix}_completed_at`, "TEXT");
});

ensureColumn("users", "is_senior", "INTEGER DEFAULT 0");
ensureColumn("users", "lab_id", "INTEGER REFERENCES labs(id)");
ensureColumn("clinics", "lab_id", "INTEGER REFERENCES labs(id)");
ensureColumn("price_list", "lab_id", "INTEGER REFERENCES labs(id)");

// One-time tenancy migration: turn the original single "Лаборатория" account
// into a real lab tenant, and attach all existing clinics/technicians/prices to it.
const tenancyMigrated = db.prepare("SELECT value FROM schema_meta WHERE key = 'tenancy_migrated'").get();
if (!tenancyMigrated) {
  const oldLabUser = db.prepare("SELECT * FROM users WHERE role = 'lab'").get();
  let labId = null;

  if (oldLabUser) {
    const trialEnds = new Date(Date.now() + TRIAL_DAYS * 24 * 60 * 60 * 1000).toISOString();
    const info = db.prepare(
      "INSERT INTO labs (name, password_hash, plan, trial_ends_at) VALUES (?, ?, 'paid', NULL)"
    ).run(oldLabUser.name, oldLabUser.password_hash);
    labId = info.lastInsertRowid;

    db.prepare("UPDATE clinics SET lab_id = ? WHERE lab_id IS NULL").run(labId);
    db.prepare("UPDATE users SET lab_id = ? WHERE lab_id IS NULL AND role IN ('clinic','technician')").run(labId);
    db.prepare("UPDATE price_list SET lab_id = ? WHERE lab_id IS NULL").run(labId);
  }

  db.prepare("INSERT INTO schema_meta (key, value) VALUES ('tenancy_migrated', '1')").run();
}

// Seed a demo lab + accounts only if the database is completely empty (fresh install).
const labCount = db.prepare("SELECT COUNT(*) AS n FROM labs").get().n;
if (labCount === 0) {
  const labHash = bcrypt.hashSync("lab123", 10);
  const labInfo = db.prepare(
    "INSERT INTO labs (name, password_hash, plan, trial_ends_at) VALUES (?, ?, 'trial', ?)"
  ).run("Лаборатория", labHash, new Date(Date.now() + TRIAL_DAYS * 24 * 60 * 60 * 1000).toISOString());
  const labId = labInfo.lastInsertRowid;

  const insertClinic = db.prepare("INSERT INTO clinics (lab_id, name) VALUES (?, ?)");
  const insertUser = db.prepare(
    "INSERT INTO users (name, password_hash, role, clinic_id, lab_id) VALUES (?, ?, ?, ?, ?)"
  );
  const clinicHash = bcrypt.hashSync("clinic123", 10);

  ["Дентал+", "Смайл клиник", "Ортодонт-1"].forEach((name) => {
    const c = insertClinic.run(labId, name);
    insertUser.run(name, clinicHash, "clinic", c.lastInsertRowid, labId);
  });

  const techHash = bcrypt.hashSync("tech123", 10);
  insertUser.run("Техник 1", techHash, "technician", null, labId);

  console.log("Созданы демо-аккаунты:");
  console.log("  Лаборатория 'Лаборатория' — пароль: lab123");
  console.log("  Клиники — пароль: clinic123");
  console.log("  Техник 1 — пароль: tech123");
}

module.exports = db;
module.exports.TRIAL_DAYS = TRIAL_DAYS;

const Database = require("better-sqlite3");

const db = new Database("netguard.db");


// ==========================================
// USERS TABLE
// ==========================================

db.prepare(`
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
`).run();


// ==========================================
// NETWORK ACTIVITY TABLE
// ==========================================

db.prepare(`
    CREATE TABLE IF NOT EXISTS network_activity (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip_address TEXT NOT NULL,
        method TEXT,
        endpoint TEXT,
        status TEXT,
        activity_type TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
`).run();


// ==========================================
// AUTHORIZED DEVICES TABLE
// ==========================================

db.prepare(`
    CREATE TABLE IF NOT EXISTS devices (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        device_name TEXT NOT NULL,
        device_type TEXT,
        ip_address TEXT,
        device_token TEXT UNIQUE NOT NULL,
        status TEXT DEFAULT 'AUTHORIZED',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
`).run();


console.log("NETGUARD database connected.");
console.log("Users table ready.");
console.log("Network activity table ready.");
console.log("Devices table ready.");


module.exports = db;
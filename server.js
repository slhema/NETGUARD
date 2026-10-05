const express = require("express");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const db = require("./database");

const app = express();

const PORT = 3000;

// Suspicious behavior threshold
const SUSPICIOUS_REQUEST_LIMIT = 10;
const SUSPICIOUS_TIME_WINDOW = 5000; // 5 seconds


app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(express.static("public"));


// ==========================================
// NETWORK ACTIVITY MONITOR
// ==========================================

app.use((req, res, next) => {

    // Do not record NETGUARD's own monitoring request
    if (req.path === "/api/network-activity") {
        return next();
    }

    // Do not record device-list request
    if (req.path === "/api/devices") {
        return next();
    }

    // Device communication handles
    // its own security classification
    if (req.path === "/api/device-communication") {
        return next();
    }

    const ip =
        req.headers["x-forwarded-for"] ||
        req.socket.remoteAddress ||
        "Unknown";

    const cleanIP = ip.replace("::ffff:", "");

    try {

        db.prepare(`
            INSERT INTO network_activity
            (ip_address, method, endpoint, status, activity_type)
            VALUES (?, ?, ?, ?, ?)
        `).run(
            cleanIP,
            req.method,
            req.originalUrl,
            "RECEIVED",
            "Network Request"
        );

    } catch (error) {

        console.error(
            "Network activity logging error:",
            error
        );

    }

    next();
});


// ==========================================
// REGISTER USER
// ==========================================

app.post("/api/register", async (req, res) => {

    try {

        const { name, email, password } = req.body;

        if (!name || !email || !password) {

            return res.status(400).json({
                success: false,
                message: "All fields are required."
            });

        }

        const existingUser = db
            .prepare(
                "SELECT * FROM users WHERE email = ?"
            )
            .get(email);

        if (existingUser) {

            return res.status(400).json({
                success: false,
                message: "Email already registered."
            });

        }

        const hashedPassword =
            await bcrypt.hash(password, 10);

        db.prepare(`
            INSERT INTO users
            (name, email, password)
            VALUES (?, ?, ?)
        `).run(
            name,
            email,
            hashedPassword
        );

        res.json({
            success: true,
            message: "Account created successfully."
        });

    } catch (error) {

        console.error(error);

        res.status(500).json({
            success: false,
            message: "Server error."
        });

    }

});


// ==========================================
// LOGIN USER
// ==========================================

app.post("/api/login", async (req, res) => {

    try {

        const { email, password } = req.body;

        const user = db
            .prepare(
                "SELECT * FROM users WHERE email = ?"
            )
            .get(email);

        if (!user) {

            return res.status(401).json({
                success: false,
                message: "Invalid email or password."
            });

        }

        const passwordMatch =
            await bcrypt.compare(
                password,
                user.password
            );

        if (!passwordMatch) {

            return res.status(401).json({
                success: false,
                message: "Invalid email or password."
            });

        }

        res.json({

            success: true,

            message: "Login successful.",

            user: {

                id: user.id,

                name: user.name,

                email: user.email

            }

        });

    } catch (error) {

        console.error(error);

        res.status(500).json({
            success: false,
            message: "Server error."
        });

    }

});


// ==========================================
// REGISTER AUTHORIZED DEVICE
// ==========================================

app.post("/api/devices/register", (req, res) => {

    try {

        const {
            device_name,
            device_type,
            ip_address
        } = req.body;

        if (!device_name) {

            return res.status(400).json({

                success: false,

                message:
                    "Device name is required."

            });

        }

        // Generate unique security token
        const deviceToken =
            crypto.randomBytes(16).toString("hex");

        const result = db.prepare(`
            INSERT INTO devices
            (
                device_name,
                device_type,
                ip_address,
                device_token,
                status
            )
            VALUES (?, ?, ?, ?, ?)
        `).run(

            device_name,

            device_type || "Unknown",

            ip_address || "Unknown",

            deviceToken,

            "AUTHORIZED"

        );

        res.json({

            success: true,

            message:
                "Device registered successfully.",

            device: {

                id: result.lastInsertRowid,

                device_name: device_name,

                device_type:
                    device_type || "Unknown",

                ip_address:
                    ip_address || "Unknown",

                device_token:
                    deviceToken,

                status: "AUTHORIZED"

            }

        });

    } catch (error) {

        console.error(error);

        res.status(500).json({

            success: false,

            message:
                "Unable to register device."

        });

    }

});


// ==========================================
// DEVICE COMMUNICATION SECURITY CHECK
// ==========================================

app.post("/api/device-communication", (req, res) => {

    try {

        const {
            device_token
        } = req.body;

        // Get IP address
        const ip =
            req.headers["x-forwarded-for"] ||
            req.socket.remoteAddress ||
            "Unknown";

        const cleanIP =
            ip.replace("::ffff:", "");


        // ==========================================
        // NO TOKEN
        // ==========================================

        if (!device_token) {

            db.prepare(`
                INSERT INTO network_activity
                (ip_address, method, endpoint, status, activity_type)
                VALUES (?, ?, ?, ?, ?)
            `).run(
                cleanIP,
                "POST",
                "/api/device-communication",
                "UNAUTHORIZED",
                "Unauthorized Device"
            );

            return res.status(401).json({

                success: false,

                status: "UNAUTHORIZED",

                message:
                    "Device is not registered with NETGUARD."

            });

        }


        // ==========================================
        // CHECK DEVICE TOKEN
        // ==========================================

        const device = db
            .prepare(`
                SELECT *
                FROM devices
                WHERE device_token = ?
            `)
            .get(device_token);


        // ==========================================
        // TOKEN NOT FOUND
        // ==========================================

        if (!device) {

            db.prepare(`
                INSERT INTO network_activity
                (ip_address, method, endpoint, status, activity_type)
                VALUES (?, ?, ?, ?, ?)
            `).run(
                cleanIP,
                "POST",
                "/api/device-communication",
                "UNAUTHORIZED",
                "Unauthorized Device"
            );

            return res.status(401).json({

                success: false,

                status: "UNAUTHORIZED",

                message:
                    "Unauthorized device detected.",

                ip_address:
                    cleanIP

            });

        }


        // ==========================================
        // SUSPICIOUS BEHAVIOR DETECTION
        // ==========================================

        const recentRequests = db.prepare(`
            SELECT COUNT(*) AS request_count
            FROM network_activity
            WHERE ip_address = ?
              AND activity_type = 'Authorized Device'
              AND created_at >= datetime('now', '-5 seconds')
        `).get(cleanIP);


        if (
            recentRequests.request_count >=
            SUSPICIOUS_REQUEST_LIMIT
        ) {

            db.prepare(`
                INSERT INTO network_activity
                (ip_address, method, endpoint, status, activity_type)
                VALUES (?, ?, ?, ?, ?)
            `).run(
                cleanIP,
                "POST",
                "/api/device-communication",
                "SUSPICIOUS",
                "Suspicious Network Behavior"
            );

            return res.status(429).json({

                success: false,

                status: "SUSPICIOUS",

                message:
                    "Unusual network behavior detected.",

                reason:
                    "Too many requests from the authorized device within a short time.",

                ip_address:
                    cleanIP

            });

        }


        // ==========================================
        // AUTHORIZED DEVICE
        // ==========================================

        db.prepare(`
            INSERT INTO network_activity
            (ip_address, method, endpoint, status, activity_type)
            VALUES (?, ?, ?, ?, ?)
        `).run(
            cleanIP,
            "POST",
            "/api/device-communication",
            "AUTHORIZED",
            "Authorized Device"
        );


        res.json({

            success: true,

            status: "AUTHORIZED",

            message:
                "Device communication approved.",

            device: {

                name:
                    device.device_name,

                type:
                    device.device_type,

                registered_ip:
                    device.ip_address

            }

        });

    } catch (error) {

        console.error(
            "Device communication error:",
            error
        );

        res.status(500).json({

            success: false,

            message:
                "Security verification failed."

        });

    }

});


// ==========================================
// GET AUTHORIZED DEVICES
// ==========================================

app.get("/api/devices", (req, res) => {

    try {

        const devices = db.prepare(`
            SELECT
                id,
                device_name,
                device_type,
                ip_address,
                status,
                created_at
            FROM devices
            ORDER BY id DESC
        `).all();

        res.json({

            success: true,

            devices: devices

        });

    } catch (error) {

        console.error(error);

        res.status(500).json({

            success: false,

            message:
                "Unable to fetch devices."

        });

    }

});


// ==========================================
// GET SECURITY ALERTS
// ==========================================

app.get("/api/security-alerts", (req, res) => {

    try {

        const alerts = db.prepare(`
            SELECT *
            FROM network_activity
            WHERE status = 'UNAUTHORIZED'
               OR status = 'SUSPICIOUS'
               OR activity_type = 'Unauthorized Device'
               OR activity_type = 'Suspicious Network Behavior'
            ORDER BY id DESC
            LIMIT 20
        `).all();

        res.json({

            success: true,

            alerts: alerts

        });

    } catch (error) {

        console.error(
            "Security alerts error:",
            error
        );

        res.status(500).json({

            success: false,

            message:
                "Unable to fetch security alerts."

        });

    }

});


// ==========================================
// GET NETWORK ACTIVITY
// ==========================================

app.get("/api/network-activity", (req, res) => {

    try {

        const activities = db.prepare(`
            SELECT *
            FROM network_activity
            ORDER BY id DESC
            LIMIT 50
        `).all();

        res.json({

            success: true,

            activities: activities

        });

    } catch (error) {

        console.error(error);

        res.status(500).json({

            success: false,

            message:
                "Unable to fetch network activity."

        });

    }

});


// ==========================================
// START SERVER
// ==========================================

app.listen(PORT, "0.0.0.0", () => {

    console.log(
        `NETGUARD server running on port ${PORT}`
    );

});
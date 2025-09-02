require("dotenv").config()
const express = require("express")
const cors = require("cors")
const multer = require("multer")
const multerS3 = require("multer-s3")
const jwt = require("jsonwebtoken")
const dotenv = require("dotenv")
const { Pool } = require("pg")
const bcrypt = require("bcrypt")
const cron = require("node-cron")
const nodemailer = require("nodemailer")
const { v4: uuidv4 } = require("uuid")
const path = require("path")
const fs = require("fs")
const { S3Client, PutObjectCommand } = require("@aws-sdk/client-s3")

const otpRequestLimit = new Map()

dotenv.config()

const app = express()
const pool = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_NAME,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT,
  ssl: { rejectUnauthorized: false },
})

// Ensure required tables/columns exist
const ensureSchema = async () => {
  try {
    // password_resets table (used by reset password flow)
    await pool.query(`
      CREATE TABLE IF NOT EXISTS password_resets (
        email TEXT PRIMARY KEY,
        token TEXT NOT NULL,
        expires_at TIMESTAMP NOT NULL
      )
    `)

    // reservations.reminder_sent column (used by reminder cron)
    await pool.query(`
      ALTER TABLE reservations
      ADD COLUMN IF NOT EXISTS reminder_sent BOOLEAN DEFAULT FALSE
    `)

    // restaurant_admins table (for admin management)
    await pool.query(`
      CREATE TABLE IF NOT EXISTS restaurant_admins (
        id SERIAL PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'admin',
        created_at TIMESTAMP DEFAULT NOW()
      )
    `)

    // settings.restaurant_email for notifications
    await pool.query(`
      ALTER TABLE settings
      ADD COLUMN IF NOT EXISTS restaurant_email TEXT
    `)

    console.log("✅ Schema ensured: password_resets, reservations.reminder_sent, restaurant_admins, settings.restaurant_email")
  } catch (schemaError) {
    console.error("❌ Error ensuring schema:", schemaError)
  }
}

ensureSchema()

// CORS configuration - ปรับปรุงให้รองรับหลาย origin
app.use(
  cors({
    origin: [
      "http://localhost:3000",
      process.env.FRONTEND_URL,
    ],
    credentials: true,
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
  }),
)

app.use(express.json())
app.use("/uploads", express.static("uploads"))
app.use(express.urlencoded({ extended: true }))

const PORT = process.env.PORT || 5000

// ===== HEALTH CHECK API =====
app.get("/api/health", (req, res) => {
  res.json({
    status: "OK",
    message: "Server is running",
    timestamp: new Date().toISOString(),
    port: PORT,
  })
})

// R2 S3 Client (ใช้ R2_ENDPOINT สำหรับอัปโหลด)
const r2 = new S3Client({
  region: "auto",
  endpoint: process.env.R2_ENDPOINT,
  credentials: {
    accessKeyId: process.env.R2_ACCESS_KEY_ID,
    secretAccessKey: process.env.R2_SECRET_ACCESS_KEY,
  },
})

// ตั้งค่า multer ให้เก็บไฟล์ลง R2 โดยตรง
const sanitizeFilename = (name) => name.replace(/\s+/g, "-").replace(/[^a-zA-Z0-9._-]/g, "")

const upload = multer({
  storage: multerS3({
    s3: r2,
    bucket: process.env.R2_BUCKET_NAME,
    acl: "public-read",
    contentType: multerS3.AUTO_CONTENT_TYPE,
    key: (req, file, cb) => {
      const timestamp = Date.now()
      const original = sanitizeFilename(file.originalname || "upload.bin")
      // เส้นทางเริ่มต้นจะถูกกำหนดในแต่ละ endpoint หากต้องการเฉพาะเจาะจง
      // ที่นี่ตั้งค่า default โฟลเดอร์
      const defaultFolder = req._uploadPrefix || "uploads"
      cb(null, `${defaultFolder}/${timestamp}-${original}`)
    },
  }),
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith("image/")) return cb(null, true)
    return cb(new Error("กรุณาอัปโหลดไฟล์รูปภาพเท่านั้น"), false)
  },
})

// หมายเหตุ: ใช้ multer-s3 แล้ว ไม่ต้องอัปโหลดเองด้วย PutObjectCommand

// Cron job to reset table status daily
cron.schedule("0 0 * * *", async () => {
  try {
    await pool.query("UPDATE table_layout SET status = 1")
    console.log("Reset table status to 1")
  } catch (error) {
    console.error("Error resetting booking count:", error)
  }
})

// Email transporter
const transporter = nodemailer.createTransport({
  service: "Gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
})

// Utility functions
const generateOTP = () => {
  return Math.floor(100000 + Math.random() * 900000).toString()
}

const generateToken = (user, expiresIn = "1h") => {
  return jwt.sign(
    {
      id: user.id,
      userId: user.id, // เพิ่ม userId เพื่อความเข้ากันได้
      email: user.email,
      role: user.role || "user", // แนบบทบาทลงใน token (ค่าเริ่มต้น user)
    },
    process.env.JWT_SECRET,
    { expiresIn },
  )
}

const generateResetToken = (user) => {
  return jwt.sign({ id: user.id, email: user.email }, process.env.JWT_SECRET, { expiresIn: "1h" })
}

// Authentication middleware - ปรับปรุงให้รองรับทั้ง id และ userId
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers.authorization
  const token = authHeader && authHeader.split(" ")[1]

  if (!token) {
    return res.status(401).json({ success: false, message: "Token ไม่ถูกต้อง" })
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(403).json({ success: false, message: "Token หมดอายุหรือไม่ถูกต้อง" })
    }
    // รองรับทั้ง id และ userId
    req.user = {
      ...decoded,
      userId: decoded.userId || decoded.id,
      id: decoded.id || decoded.userId,
    }
    next()
  })
}

// Authorization middleware for role-based access control
const authorizeRoles = (...allowedRoles) => {
  return (req, res, next) => {
    if (!req.user || !req.user.role) {
      return res.status(403).json({ success: false, message: "ไม่มีสิทธิ์เข้าถึง" })
    }
    if (!allowedRoles.includes(req.user.role)) {
      return res.status(403).json({ success: false, message: "สิทธิ์ไม่เพียงพอ" })
    }
    next()
  }
}

// Cleanup expired temp users
const cleanupExpiredTempUsers = async () => {
  try {
    const now = new Date()
    const result = await pool.query("DELETE FROM temp_users WHERE otp_expires < $1 RETURNING *", [now])
    if (result.rows.length > 0) {
      console.log(`Deleted ${result.rows.length} expired temporary users`)
    }
  } catch (err) {
    console.error("Error cleaning up expired temp users:", err)
  }
}

cleanupExpiredTempUsers()
setInterval(cleanupExpiredTempUsers, 60000)

// ===== RESTAURANT ADMIN AUTHENTICATION API =====

// POST - ล็อกอินสำหรับ Restaurant Admin
app.post("/api/restaurant/login", async (req, res) => {
  try {
    const { username, password } = req.body

    if (!username || !password) {
      return res.status(400).json({
        success: false,
        message: "กรุณากรอกชื่อผู้ใช้และรหัสผ่าน"
      })
    }

    // ค้นหา admin จากฐานข้อมูล
    const result = await pool.query(
      "SELECT * FROM restaurant_admins WHERE username = $1",
      [username]
    )

    if (result.rows.length === 0) {
      return res.status(401).json({
        success: false,
        message: "ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง"
      })
    }

    const admin = result.rows[0]

    // ตรวจสอบรหัสผ่าน
    const isValidPassword = await bcrypt.compare(password, admin.password_hash)

    if (!isValidPassword) {
      return res.status(401).json({
        success: false,
        message: "ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง"
      })
    }

    // สร้าง JWT token
    const token = generateToken(admin, "24h")

    res.json({
      success: true,
      message: "ล็อกอินสำเร็จ",
      token,
      admin: {
        id: admin.id,
        username: admin.username,
        role: admin.role
      }
    })

  } catch (error) {
    console.error("Error in restaurant login:", error)
    res.status(500).json({
      success: false,
      message: "เกิดข้อผิดพลาดในเซิร์ฟเวอร์"
    })
  }
})

// ===== RESTAURANT ADMIN MANAGEMENT (CRUD) =====

// Create admin
app.post("/api/restaurant/admins", authenticateToken, authorizeRoles("admin"), async (req, res) => {
  try {
    const { username, password, role } = req.body
    if (!username || !password) {
      return res.status(400).json({ success: false, message: "กรุณาระบุ username และ password" })
    }
    const hashed = await bcrypt.hash(password, 10)
    const result = await pool.query(
      `INSERT INTO restaurant_admins (username, password_hash, role) VALUES ($1, $2, $3) RETURNING id, username, role`,
      [username, hashed, role || "admin"],
    )
    res.json({ success: true, admin: result.rows[0] })
  } catch (error) {
    if (error.code === "23505") {
      return res.status(409).json({ success: false, message: "username นี้ถูกใช้งานแล้ว" })
    }
    console.error("Create admin error:", error)
    res.status(500).json({ success: false, message: "เกิดข้อผิดพลาดในระบบ" })
  }
})

// List admins
app.get("/api/restaurant/admins", authenticateToken, authorizeRoles("admin"), async (req, res) => {
  try {
    const result = await pool.query(`SELECT id, username, role, created_at FROM restaurant_admins ORDER BY id ASC`)
    res.json({ success: true, admins: result.rows })
  } catch (error) {
    console.error("List admins error:", error)
    res.status(500).json({ success: false, message: "เกิดข้อผิดพลาดในระบบ" })
  }
})

// Update admin
app.put("/api/restaurant/admins/:id", authenticateToken, authorizeRoles("admin"), async (req, res) => {
  try {
    const { id } = req.params
    const { username, password, role } = req.body
    const fields = []
    const values = []
    let idx = 1

    if (username !== undefined) { fields.push(`username = $${idx++}`); values.push(username) }
    if (password !== undefined && password !== "") {
      const hashed = await bcrypt.hash(password, 10)
      fields.push(`password_hash = $${idx++}`)
      values.push(hashed)
    }
    if (role !== undefined) { fields.push(`role = $${idx++}`); values.push(role) }

    if (fields.length === 0) {
      return res.status(400).json({ success: false, message: "ไม่มีข้อมูลสำหรับอัปเดต" })
    }

    values.push(id)
    const result = await pool.query(`UPDATE restaurant_admins SET ${fields.join(", ")} WHERE id = $${idx} RETURNING id, username, role`, values)
    if (result.rowCount === 0) return res.status(404).json({ success: false, message: "ไม่พบผู้ดูแลระบบ" })
    res.json({ success: true, admin: result.rows[0] })
  } catch (error) {
    if (error.code === "23505") {
      return res.status(409).json({ success: false, message: "username นี้ถูกใช้งานแล้ว" })
    }
    console.error("Update admin error:", error)
    res.status(500).json({ success: false, message: "เกิดข้อผิดพลาดในระบบ" })
  }
})

// Delete admin
app.delete("/api/restaurant/admins/:id", authenticateToken, authorizeRoles("admin"), async (req, res) => {
  try {
    const { id } = req.params
    const result = await pool.query(`DELETE FROM restaurant_admins WHERE id = $1`, [id])
    if (result.rowCount === 0) return res.status(404).json({ success: false, message: "ไม่พบผู้ดูแลระบบ" })
    res.json({ success: true })
  } catch (error) {
    console.error("Delete admin error:", error)
    res.status(500).json({ success: false, message: "เกิดข้อผิดพลาดในระบบ" })
  }
})

// GET - ตรวจสอบสถานะการล็อกอิน
app.get("/api/restaurant/verify", authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT id, username, role FROM restaurant_admins WHERE id = $1",
      [req.user.id]
    )

    if (result.rows.length === 0) {
      return res.status(401).json({
        success: false,
        message: "ไม่พบข้อมูลผู้ใช้"
      })
    }

    res.json({
      success: true,
      admin: result.rows[0]
    })

  } catch (error) {
    console.error("Error verifying restaurant admin:", error)
    res.status(500).json({
      success: false,
      message: "เกิดข้อผิดพลาดในเซิร์ฟเวอร์"
    })
  }
})

// ===== QR PAYMENT SETTINGS API =====

// GET - ดึงการตั้งค่า QR ทั้งหมด
app.get("/api/settings/qr-payment", authenticateToken, authorizeRoles("admin"), async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT enable_qr_payment, require_qr_before_reserve, promptpay_number FROM settings LIMIT 1",
    )

    const row = result.rows[0] || {}

    res.json({
      success: true,
      enableQR: row.enable_qr_payment || false,
      requireQR: row.require_qr_before_reserve || false,
      promptpayNumber: row.promptpay_number || "",
    })
  } catch (error) {
    console.error("Error fetching QR settings:", error)
    res.status(500).json({ success: false, message: "Server error" })
  }
})

// PUT - อัปเดตการตั้งค่า QR ทั้งหมด
app.put("/api/settings/qr-payment", authenticateToken, authorizeRoles("admin"), async (req, res) => {
  const { enableQR, requireQR, promptpayNumber } = req.body

  // รองรับกรณีไม่ได้ส่ง requireQR มา (เช่น ปิดการตั้งค่านี้ในหน้า UI)
  const normalizedRequireQR = typeof requireQR === "boolean" ? requireQR : false

  console.log("Received data:", { enableQR, requireQR: normalizedRequireQR, promptpayNumber })

  // ตรวจสอบว่าต้องมีเลขพร้อมเพย์ถ้าเปิดใช้งาน QR
  if (enableQR && (!promptpayNumber || promptpayNumber.trim() === "")) {
    return res.status(400).json({
      success: false,
      message: "กรุณาใส่เลขพร้อมเพย์ก่อนเปิดใช้งาน QR",
    })
  }

  // ตรวจสอบรูปแบบเลขพร้อมเพย์
  if (promptpayNumber && !/^[0-9]{10,13}$/.test(promptpayNumber.replace(/[-\s]/g, ""))) {
    return res.status(400).json({
      success: false,
      message: "เลขพร้อมเพย์ต้องเป็นตัวเลข 10-13 หลัก",
    })
  }

  const client = await pool.connect()
  try {
    await client.query("BEGIN")

    // ตรวจสอบว่ามีข้อมูลในตาราง settings หรือไม่
    const checkResult = await client.query("SELECT COUNT(*) FROM settings")
    const hasData = Number.parseInt(checkResult.rows[0].count) > 0

    if (hasData) {
      // อัปเดตข้อมูลที่มีอยู่
      await client.query(
        `UPDATE settings SET 
         enable_qr_payment = $1, 
         require_qr_before_reserve = $2, 
         promptpay_number = $3`,
        [enableQR, normalizedRequireQR, promptpayNumber || null],
      )
    } else {
      // เพิ่มข้อมูลใหม่
      await client.query(
        `INSERT INTO settings (enable_qr_payment, require_qr_before_reserve, promptpay_number) 
         VALUES ($1, $2, $3)`,
        [enableQR, normalizedRequireQR, promptpayNumber || null],
      )
    }

    await client.query("COMMIT")

    console.log("Settings updated successfully")
    res.json({ success: true, message: "อัปเดตการตั้งค่าสำเร็จ" })
  } catch (error) {
    await client.query("ROLLBACK")
    console.error("Error updating QR settings:", error)
    res.status(500).json({ success: false, message: "เกิดข้อผิดพลาดในการบันทึก" })
  } finally {
    client.release()
  }
})

// ===== RESERVATION WINDOW SETTINGS API =====

// GET - ดึงการตั้งค่าเวลาเปิด/ปิดการจอง
app.get("/api/settings/reservation-window", async (req, res) => {
  const client = await pool.connect()
  try {
    // สร้างคอลัมน์ถ้ายังไม่มี
    await client.query(
      `ALTER TABLE settings 
       ADD COLUMN IF NOT EXISTS reservation_enabled BOOLEAN DEFAULT FALSE,
       ADD COLUMN IF NOT EXISTS reservation_open_time TIME,
       ADD COLUMN IF NOT EXISTS reservation_close_time TIME`
    )

    const result = await client.query(
      `SELECT reservation_enabled, 
              to_char(reservation_open_time, 'HH24:MI') AS open_time,
              to_char(reservation_close_time, 'HH24:MI') AS close_time
       FROM settings LIMIT 1`
    )

    const row = result.rows[0] || {}
    res.json({
      success: true,
      enabled: row.reservation_enabled || false,
      openTime: row.open_time || "",
      closeTime: row.close_time || "",
    })
  } catch (error) {
    console.error("Error fetching reservation window settings:", error)
    res.status(500).json({ success: false, message: "Server error" })
  } finally {
    client.release()
  }
})

// PUT - อัปเดตการตั้งค่าเวลาเปิด/ปิดการจอง
app.put("/api/settings/reservation-window", authenticateToken, authorizeRoles("admin"), async (req, res) => {
  const { enabled, openTime, closeTime } = req.body
  const client = await pool.connect()

  // ตรวจสอบรูปแบบเวลา (HH:MM) เมื่อ enabled = true
  if (enabled) {
    const timeRegex = /^\d{2}:\d{2}$/
    if (!timeRegex.test(openTime || "") || !timeRegex.test(closeTime || "")) {
      client.release()
      return res.status(400).json({ success: false, message: "รูปแบบเวลาต้องเป็น HH:MM" })
    }
  }

  try {
    await client.query("BEGIN")

    // สร้างคอลัมน์ถ้ายังไม่มี
    await client.query(
      `ALTER TABLE settings 
       ADD COLUMN IF NOT EXISTS reservation_enabled BOOLEAN DEFAULT FALSE,
       ADD COLUMN IF NOT EXISTS reservation_open_time TIME,
       ADD COLUMN IF NOT EXISTS reservation_close_time TIME`
    )

    // ตรวจสอบว่ามี row อยู่หรือยัง
    const check = await client.query("SELECT COUNT(*) FROM settings")
    const hasData = Number.parseInt(check.rows[0].count) > 0

    if (hasData) {
      await client.query(
        `UPDATE settings SET 
           reservation_enabled = $1,
           reservation_open_time = $2,
           reservation_close_time = $3`,
        [Boolean(enabled), enabled ? openTime : null, enabled ? closeTime : null]
      )
    } else {
      await client.query(
        `INSERT INTO settings (reservation_enabled, reservation_open_time, reservation_close_time)
         VALUES ($1, $2, $3)`,
        [Boolean(enabled), enabled ? openTime : null, enabled ? closeTime : null]
      )
    }

    await client.query("COMMIT")
    res.json({ success: true, message: "อัปเดตเวลาเปิด/ปิดการจองสำเร็จ" })
  } catch (error) {
    await client.query("ROLLBACK")
    console.error("Error updating reservation window settings:", error)
    res.status(500).json({ success: false, message: "เกิดข้อผิดพลาดในการบันทึก" })
  } finally {
    client.release()
  }
})

// API เฉพาะสำหรับดึงเลขพร้อมเพย์ (สำหรับหน้า PaymentQR)
app.get("/api/settings/promptpay", async (req, res) => {
  try {
    const result = await pool.query("SELECT promptpay_number FROM settings LIMIT 1")
    const promptpayNumber = result.rows[0]?.promptpay_number || ""
    res.json({ success: true, promptpayNumber })
  } catch (error) {
    console.error("Error fetching promptpay number:", error)
    res.status(500).json({ success: false, message: "Server error" })
  }
})

// ===== PAYMENT SLIP UPLOAD APIs =====

// API สำหรับอัปโหลดสลิปการจ่ายเงิน
app.post("/api/upload-payment-slip", authenticateToken, (req, res, next) => { req._uploadPrefix = `payment-slips/${req.user.userId || 'anonymous'}`; next(); }, upload.single("paymentSlip"), async (req, res) => {
  try {
    const { reservationData } = req.body
    const userId = req.user.userId
    const email = req.user.email

    if (!req.file) {
      return res.status(400).json({ success: false, message: "กรุณาเลือกไฟล์สลิป" })
    }

    const parsedReservationData = JSON.parse(reservationData)

    // สร้าง URL สำหรับเปิดดูสาธารณะด้วย R2_PUBLIC_URL
    const publicUrl = `${process.env.R2_PUBLIC_URL}/${req.file.key}`

    console.log("Payment slip uploaded to R2:", publicUrl)

    const client = await pool.connect()
    try {
      await client.query("BEGIN")

      // บันทึกข้อมูลสลิปการจ่ายเงิน (เก็บเป็น URL)
      const slipResult = await client.query(
        `INSERT INTO payment_slips (user_id, email, slip_path, amount, reservation_data, status, created_at) 
         VALUES ($1, $2, $3, $4, $5, $6, NOW()) RETURNING id`,
        [
          userId,
          email,
          publicUrl,
          parsedReservationData.totalAmount,
          JSON.stringify(parsedReservationData),
          "pending",
        ],
      )

      await client.query("COMMIT")

      res.json({
        success: true,
        message: "อัปโหลดสลิปสำเร็จ",
        uploadId: slipResult.rows[0].id,
        slipUrl: publicUrl,
      })
    } catch (error) {
      await client.query("ROLLBACK")
      throw error
    } finally {
      client.release()
    }
  } catch (error) {
    console.error("Error uploading payment slip:", error)
    res.status(500).json({ success: false, message: "เกิดข้อผิดพลาดในการอัปโหลด" })
  }
})

// API สำหรับดูสลิปการจ่ายเงินทั้งหมด (สำหรับร้าน)
app.get("/api/payment-slips", authenticateToken, authorizeRoles("admin"), async (req, res) => {
  try {
    const { status, date } = req.query
    let query = `
      SELECT ps.*, u.username 
      FROM payment_slips ps 
      LEFT JOIN users u ON ps.user_id = u.id 
      WHERE 1=1
    `
    const params = []

    if (status) {
      query += ` AND ps.status = $${params.length + 1}`
      params.push(status)
    }

    if (date) {
      query += ` AND DATE(ps.created_at) = $${params.length + 1}`
      params.push(date)
    }

    query += ` ORDER BY ps.created_at DESC`

    const result = await pool.query(query, params)

    res.json({
      success: true,
      slips: result.rows.map((slip) => ({
        ...slip,
        reservation_data:
          typeof slip.reservation_data === "string" ? JSON.parse(slip.reservation_data) : slip.reservation_data,
      })),
    })
  } catch (error) {
    console.error("Error fetching payment slips:", error)
    res.status(500).json({ success: false, message: "เกิดข้อผิดพลาดในการดึงข้อมูล" })
  }
})

// API สำหรับอัปเดตสถานะสลิป (อนุมัติ/ปฏิเสธ)
app.put("/api/payment-slips/:id/status", authenticateToken, authorizeRoles("admin"), async (req, res) => {
  const client = await pool.connect()
  try {
    const { id } = req.params
    const { status, note } = req.body // status: 'approved', 'rejected'

    if (!["approved", "rejected"].includes(status)) {
      return res.status(400).json({ success: false, message: "สถานะไม่ถูกต้อง" })
    }

    await client.query("BEGIN")

    // ดึงข้อมูลสลิปและข้อมูลการจอง
    const slipResult = await client.query(
      `SELECT ps.*, ps.reservation_data 
       FROM payment_slips ps 
       WHERE ps.id = $1`,
      [id],
    )

    if (slipResult.rows.length === 0) {
      await client.query("ROLLBACK")
      return res.status(404).json({ success: false, message: "ไม่พบสลิปการจ่ายเงิน" })
    }

    const slip = slipResult.rows[0]
    const reservationData =
      typeof slip.reservation_data === "string" ? JSON.parse(slip.reservation_data) : slip.reservation_data

    console.log("🔍 ข้อมูลสลิป:", {
      slipId: slip.id,
      email: slip.email,
      reservationData: reservationData,
    })
    
    // Debug: แสดงข้อมูลโต๊ะจาก reservationData
    if (reservationData && reservationData.tableNames) {
      console.log("🎯 โต๊ะจาก reservationData:", reservationData.tableNames)
    }

    // อัปเดตสถานะสลิป
    const updateResult = await client.query(
      `UPDATE payment_slips 
       SET status = $1, admin_note = $2, updated_at = NOW() 
       WHERE id = $3 RETURNING *`,
      [status, note || null, id],
    )

    // ถ้าปฏิเสธสลิป ให้ยกเลิกการจองด้วย
    if (status === "rejected" && reservationData) {
      const email = slip.email

      console.log("🔍 ข้อมูล reservationData ทั้งหมด:", JSON.stringify(reservationData, null, 2))
      console.log("🔥 เริ่มกระบวนการยกเลิกการจอง สำหรับ email:", email)

      if (email) {
        // ค้นหาการจองทั้งหมดด้วย email (ไม่ใช่แค่ล่าสุด)
        console.log("🔍 ค้นหาการจองทั้งหมดด้วย email")
        const reservationResult = await client.query(
          "SELECT id, setable, date FROM reservations WHERE email = $1 ORDER BY id DESC",
          [email],
        )
        console.log(`🔍 พบการจอง: ${reservationResult.rows.length} รายการ`)

        if (reservationResult.rows.length > 0) {
          // รวบรวมโต๊ะทั้งหมดจากทุกการจอง
          let allTables = []
          let totalUpdatedTables = 0
          let totalReservations = reservationResult.rows.length

          console.log("🔍 ข้อมูลการจองทั้งหมดที่พบ:")
          for (const reservation of reservationResult.rows) {
            const setableRaw = reservation.setable || ""

            console.log("📋 ข้อมูลการจองที่พบ:", {
              reservationId: reservation.id,
              setable: setableRaw,
              date: reservation.date,
            })

            // แยกชื่อโต๊ะด้วยวิธีที่ครอบคลุมมากขึ้น
            const tables = setableRaw
              .replace(/$$ต่อโต๊ะ$$/g, "") // ลบคำ "(ต่อโต๊ะ)"
              .replace(/\s+/g, " ") // แทนที่ช่องว่างหลายตัวด้วยช่องว่างเดียว
              .split(/[,\n]/) // แยกด้วยคอมมาหรือขึ้นบรรทัดใหม่
              .map((t) => t.trim()) // ตัดช่องว่าง
              .filter(Boolean) // กรองค่าว่าง

            // เพิ่มโต๊ะจากการจองนี้เข้าไปในรายการทั้งหมด
            allTables = [...allTables, ...tables]

            console.log("🎯 โต๊ะจากการจองนี้:", tables)
          }

          console.log("📊 รายการโต๊ะทั้งหมด (รวม):", allTables)

          // ลบโต๊ะที่ซ้ำกัน
          const uniqueTables = [...new Set(allTables)]
          console.log("🎯 โต๊ะทั้งหมดที่ต้องการปลดสถานะ (ไม่ซ้ำ):", uniqueTables)
          
          // เพิ่มโต๊ะจาก reservationData ถ้ามี
          if (reservationData && reservationData.tableNames) {
            const reservationTables = reservationData.tableNames
              .split(/[,\n]/)
              .map(t => t.trim())
              .filter(Boolean)
            
            console.log("🎯 โต๊ะจาก reservationData:", reservationTables)
            
            // รวมโต๊ะจากทั้งสองแหล่ง
            const combinedTables = [...new Set([...uniqueTables, ...reservationTables])]
            console.log("🎯 โต๊ะรวมจากทั้งสองแหล่ง:", combinedTables)
            
            // ใช้โต๊ะที่รวมแล้ว
            uniqueTables.length = 0
            uniqueTables.push(...combinedTables)
          }

          // อัปเดตสถานะโต๊ะเป็นว่าง (status = 1) สำหรับทุกโต๊ะ
          for (const table of uniqueTables) {
            console.log(`🔍 กำลังค้นหาโต๊ะ: "${table}"`)
            
            // ลองหลายเงื่อนไขในการค้นหาโต๊ะ
            const updateTableResult = await client.query(
              `UPDATE table_layout 
               SET status = 1 
               WHERE TRIM(LOWER(tname)) = TRIM(LOWER($1)) 
                  OR CAST(tnumber AS TEXT) = $1 
                  OR TRIM(LOWER(tname)) LIKE TRIM(LOWER($1))
                  OR CONCAT(TRIM(LOWER(tname)), ' ', CAST(tnumber AS TEXT)) = TRIM(LOWER($1))
                  OR TRIM(LOWER(tname)) LIKE '%' || TRIM(LOWER($1)) || '%'
                  OR TRIM(LOWER(tname)) = TRIM(LOWER($1)) || ' '
                  OR TRIM(LOWER(tname)) = ' ' || TRIM(LOWER($1))
                  OR TRIM(LOWER(tname)) LIKE TRIM(LOWER($1)) || '%'
                  OR TRIM(LOWER(tname)) LIKE '%' || TRIM(LOWER($1))`,
              [table],
            )

            if (updateTableResult.rowCount > 0) {
              console.log(`✅ ปรับสถานะโต๊ะสำเร็จ: ${table} (${updateTableResult.rowCount} แถว)`)
              totalUpdatedTables++
            } else {
              console.log(`❌ ไม่พบโต๊ะ: ${table}`)

              // ลองค้นหาโต๊ะที่มีอยู่เพื่อ debug
              const debugResult = await client.query(
                "SELECT tnumber, tname, status FROM table_layout WHERE tname IS NOT NULL OR tnumber IS NOT NULL",
              )
              console.log("🔍 โต๊ะทั้งหมดในระบบ:", debugResult.rows)
              
              // ลองค้นหาโต๊ะที่คล้ายกัน
              const similarResult = await client.query(
                `SELECT tnumber, tname, status FROM table_layout 
                 WHERE LOWER(tname) LIKE '%' || LOWER($1) || '%' 
                    OR LOWER(tname) LIKE LOWER($1) || '%'
                    OR LOWER(tname) LIKE '%' || LOWER($1)
                    OR CAST(tnumber AS TEXT) LIKE '%' || $1 || '%'`,
                [table],
              )
              if (similarResult.rows.length > 0) {
                console.log(`🔍 โต๊ะที่คล้ายกันกับ "${table}":`, similarResult.rows)
              }
            }
          }

          // ลบข้อมูลใน reservation_foods สำหรับทุกการจอง
          for (const reservation of reservationResult.rows) {
            await client.query("DELETE FROM reservation_foods WHERE reservation_id = $1", [reservation.id])
          }

          // ลบข้อมูลการจองทั้งหมด
          const deleteResult = await client.query("DELETE FROM reservations WHERE email = $1", [email])

          if (deleteResult.rowCount > 0) {
            console.log(`✅ ยกเลิกการจองสำเร็จสำหรับ: ${email}`)
            console.log(`📊 สรุป: อัปเดตโต๊ะ ${totalUpdatedTables}/${uniqueTables.length} โต๊ะ จาก ${totalReservations} การจอง`)
          }
        } else {
          console.log(`❌ ไม่พบการจองสำหรับ email: ${email}`)

          // Debug: แสดงการจองทั้งหมดของ email นี้
          const allReservations = await client.query("SELECT id, date, setable FROM reservations WHERE email = $1", [
            email,
          ])
          console.log("🔍 การจองทั้งหมดของ email นี้:", allReservations.rows)
        }
      } else {
        console.log("❌ ไม่มีข้อมูล email")
      }
    }

    await client.query("COMMIT")

    const message = status === "approved" ? "อนุมัติสลิปสำเร็จ" : "ปฏิเสธสลิปและยกเลิกการจองเรียบร้อยแล้ว"

    // ส่งอีเมลแจ้งเตือนลูกค้า
    try {
      const toEmail = slip.email
      let latestReservation = null
      // ดึงการจองล่าสุดของอีเมลนี้เพื่อใช้เป็น fallback ให้วันที่/เวลาในอีเมล
      if (toEmail) {
        const latestRes = await pool.query(
          "SELECT date, time FROM reservations WHERE email = $1 ORDER BY id DESC LIMIT 1",
          [toEmail],
        )
        latestReservation = latestRes.rows[0] || null
      }
      if (toEmail) {
        if (status === "approved") {
          const mailOptions = {
            from: process.env.EMAIL_USER,
            to: toEmail,
            subject: "ยืนยันการจองโต๊ะสำเร็จ",
            html: `
              <p>เรียนคุณ ${reservationData?.fullName || "ลูกค้า"},</p>
              <p>การจองโต๊ะของคุณได้รับการยืนยันเรียบร้อยแล้ว</p>
              <p><strong>รายละเอียดการจอง</strong></p>
              <ul>
                <li>โต๊ะ: ${reservationData?.tableNames || "-"}</li>
                <li>วันที่: ${
                  reservationData?.date ||
                  reservationData?.currentDate ||
                  reservationData?.reservationDate ||
                  latestReservation?.date ||
                  "-"
                }</li>
                <li>เวลา: ${reservationData?.time || latestReservation?.time || "-"}</li>
                <li>จำนวนคน: ${reservationData?.peopleCount || "-"}</li>
                <li>ยอดชำระ: ฿${Number(slip.amount || 0).toLocaleString()}</li>
              </ul>
              <p>ขอบคุณที่ใช้บริการ</p>
            `,
          }
          await transporter.sendMail(mailOptions)
        } else if (status === "rejected") {
          const mailOptions = {
            from: process.env.EMAIL_USER,
            to: toEmail,
            subject: "การชำระเงินถูกปฏิเสธและยกเลิกการจอง",
            html: `
              <p>เรียนคุณ ${reservationData?.fullName || "ลูกค้า"},</p>
              <p>สลิปการชำระเงินของคุณถูกปฏิเสธ และการจองได้ถูกยกเลิกแล้ว</p>
              ${note ? `<p><strong>เหตุผลจากผู้ดูแลระบบ:</strong> ${note}</p>` : ""}
              <p>หากมีข้อสงสัย กรุณาติดต่อร้าน</p>
            `,
          }
          await transporter.sendMail(mailOptions)
        }
      }
    } catch (mailError) {
      console.error("❌ Error sending email notification:", mailError)
      // ไม่ block การตอบกลับ ถ้าอีเมลล้มเหลว
    }

    res.json({
      success: true,
      message,
      slip: updateResult.rows[0],
    })
  } catch (error) {
    await client.query("ROLLBACK")
    console.error("❌ Error updating payment slip status:", error)
    res.status(500).json({ success: false, message: "เกิดข้อผิดพลาดในการอัปเดต" })
  } finally {
    client.release()
  }
})

// API สำหรับดูสลิปของผู้ใช้เอง
app.get("/api/user/payment-slips", authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId

    const result = await pool.query(
      `SELECT * FROM payment_slips 
       WHERE user_id = $1 
       ORDER BY created_at DESC`,
      [userId],
    )

    res.json({
      success: true,
      slips: result.rows.map((slip) => ({
        ...slip,
        reservation_data:
          typeof slip.reservation_data === "string" ? JSON.parse(slip.reservation_data) : slip.reservation_data,
      })),
    })
  } catch (error) {
    console.error("Error fetching user payment slips:", error)
    res.status(500).json({ success: false, message: "เกิดข้อผิดพลาดในการดึงข้อมูล" })
  }
})

// ===== USER REGISTRATION & AUTHENTICATION =====

app.post("/api/register", async (req, res) => {
  const { username, email, phone, password } = req.body
  const otp = generateOTP()
  const otpExpires = new Date(Date.now() + 20 * 60 * 1000)
  const hashedPassword = await bcrypt.hash(password, 10)

  try {
    const emailCheck = await pool.query("SELECT * FROM users WHERE email = $1", [email])
    if (emailCheck.rows.length > 0) {
      return res.status(400).json({
        success: false,
        message: "อีเมลนี้ถูกใช้งานแล้ว",
      })
    }

    const tempCheck = await pool.query("SELECT * FROM temp_users WHERE email = $1 OR phone = $2", [email, phone])
    if (tempCheck.rows.length > 0) {
      return res.status(400).json({
        status: "error",
        message: "อีเมลหรือเบอร์โทรศัพท์นี้กำลังรอการยืนยัน",
      })
    }

    const result = await pool.query(
      "INSERT INTO temp_users (username, email, phone, password, status, otp, otp_expires) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *",
      [username, email, phone, hashedPassword, 1, otp, otpExpires],
    )

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: "รหัส OTP",
      text: `รหัส OTP ของคุณคือ ${otp} รหัสนี้จะหมดอายุภายใน 20 นาที`,
    }

    await transporter.sendMail(mailOptions).catch((mailErr) => {
      console.error("Email sending failed:", mailErr)
      throw new Error("ไม่สามารถส่งอีเมล OTP ได้")
    })

    res.json({
      status: "ok",
      message: "ส่ง OTP ไปยังอีเมลของคุณแล้ว",
      userId: result.rows[0].id,
      expiresAt: otpExpires.getTime(),
    })
  } catch (err) {
    console.error("Register error:", err)
    res.status(500).json({
      status: "error",
      message: err.message || "เกิดข้อผิดพลาดในระบบ",
    })
  }
})

app.post("/api/verify-otp", async (req, res) => {
  const { userId, otp } = req.body
  if (!userId || !otp) {
    return res.status(400).json({ status: "error", message: "กรุณากรอกข้อมูลให้ครบถ้วน" })
  }

  try {
    const result = await pool.query("SELECT * FROM temp_users WHERE id = $1", [userId])
    if (result.rows.length === 0) {
      return res.status(404).json({ status: "error", message: "ไม่พบผู้ใช้" })
    }

    const tempUser = result.rows[0]
    const now = new Date()

    if (tempUser.otp !== otp) {
      return res.status(400).json({
        status: "error",
        message: "รหัส OTP ไม่ถูกต้อง",
      })
    }

    if (now > tempUser.otp_expires) {
      return res.status(400).json({
        status: "error",
        message: "รหัส OTP หมดอายุแล้ว",
      })
    }

    const userResult = await pool.query(
      "INSERT INTO users (username, email, phone, password, status) VALUES ($1, $2, $3, $4, $5) RETURNING *",
      [tempUser.username, tempUser.email, tempUser.phone, tempUser.password, tempUser.status],
    )

    await pool.query("DELETE FROM temp_users WHERE id = $1", [userId])

    const user = userResult.rows[0]
    const token = generateToken(user)

    res.json({
      status: "ok",
      message: "ยืนยัน OTP สำเร็จ",
      accessToken: token,
    })
  } catch (err) {
    console.error("Verify OTP error:", err)
    res.status(500).json({ status: "error", message: "เกิดข้อผิดพลาดในระบบ" })
  }
})

app.post("/api/login", async (req, res) => {
  const { username, password } = req.body

  try {
    const result = await pool.query("SELECT * FROM users WHERE email = $1", [username])
    const user = result.rows[0]

    if (!user) {
      return res.json({
        success: false,
        message: "อีเมลหรือรหัสผ่านไม่ถูกต้อง",
      })
    }

    const isMatch = await bcrypt.compare(password, user.password)
    if (!isMatch) {
      return res.json({
        success: false,
        message: "อีเมลหรือรหัสผ่านไม่ถูกต้อง",
      })
    }

    await pool.query("UPDATE users SET last_login_time = $1 WHERE email = $2", [new Date(), username])

    const token = generateToken(user)

    res.json({
      success: true,
      message: "เข้าสู่ระบบสำเร็จ",
      token,
    })
  } catch (error) {
    console.error(error)
    res.status(500).json({ success: false, message: "ไม่สามารถเชื่อมต่อกับฐานข้อมูล" })
  }
})

// API สำหรับออกจากระบบ (Logout) session หมดอายุ ลบ token ใน server
app.post("/api/logout", (req, res) => {
  res.json({ success: true, message: "ออกจากระบบสำเร็จ" })
})

// API user เปลี่ยนรหัสผ่าน
app.post("/api/changepassword", authenticateToken, async (req, res) => {
  const { password } = req.body
  const userId = req.user.userId // ใช้ userId จากข้อมูลที่ decode ใน token

  if (!password) {
    return res.status(400).json({ success: false, message: "กรุณาระบุรหัสผ่านใหม่" })
  }

  try {
    // ดึงรหัสผ่านเก่าจากฐานข้อมูล
    const result = await pool.query("SELECT password FROM users WHERE id = $1", [userId])
    const currentPassword = result.rows[0]?.password

    // เช็คว่า รหัสผ่านใหม่ตรงกับรหัสเดิมหรือไม่
    const isMatch = await bcrypt.compare(password, currentPassword)
    if (isMatch) {
      return res.status(400).json({
        success: false,
        message: "รหัสผ่านใหม่ต้องไม่ซ้ำกับรหัสผ่านเดิม",
      })
    }

    // ถ้ารหัสผ่านใหม่ไม่ซ้ำกับเก่า ก็จะทำการแฮชและอัปเดต
    const hashedPassword = await bcrypt.hash(password, 10)

    // อัปเดตรหัสผ่านในฐานข้อมูล
    await pool.query("UPDATE users SET password = $1 WHERE id = $2", [hashedPassword, userId])

    res.json({ success: true, message: "เปลี่ยนรหัสผ่านสำเร็จ" })
  } catch (error) {
    // console.error("Error updating password:", error);
    res.status(500).json({ success: false, message: "เกิดข้อผิดพลาดในการเปลี่ยนรหัสผ่าน" })
  }
})

// สำหรับ ทดสอบว่ามี token ส่งกลับไหม
app.get("/api/checkToken", authenticateToken, (req, res) => {
  const authHeader = req.headers["authorization"]
  const token = authHeader && authHeader.split(" ")[1] // Bearer <token>

  if (!token) {
    return res.status(401).json({ message: "No token provided" })
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET)
    return res.status(200).json({ message: "Token is valid", user: decoded })
  } catch (error) {
    return res.status(401).json({ message: "Invalid or expired token" })
  }
})

// API บันทึกข้อมูลเมนู
app.post("/api/menus", authenticateToken, authorizeRoles("admin"), (req, res, next) => { req._uploadPrefix = "menus"; next(); }, upload.single("image"), async (req, res) => {
  try {
    const { name, price, description, category } = req.body

    let imageUrl = req.file ? `${process.env.R2_PUBLIC_URL}/${req.file.key}` : null

    const result = await pool.query(
      "INSERT INTO menus (name, price, description, image_url, category) VALUES ($1, $2, $3, $4 ,$5) RETURNING *",
      [name, price, description, imageUrl, category],
    )

    res.json({ success: true, menu: result.rows[0] })
  } catch (error) {
    console.error(error)
    res.status(500).json({ success: false, message: "Server Error" })
  }
})

// API ดึงข้อมูลเมนูทั้งหมด
app.get("/api/menus", async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT id, name, description, category, available, image_url, CAST(price AS INTEGER) AS price FROM menus",
    )
    if (result.rows.length > 0) {
      res.json({ success: true, menus: result.rows })
    } else {
      res.json({ success: true, menus: [] })
    }
  } catch (error) {
    console.error("Error fetching menus:", error)
    res.status(500).json({ success: false, message: "Server Error" })
  }
})

//ดึงข้อมูลเมนูจาก id มา มาเเสดงในหน้าเเก้ไข ชื่อ,ราคา เมนูอาหาร
app.get("/api/menus/:id", async (req, res) => {
  const { id } = req.params
  try {
    const result = await pool.query(
      "SELECT id, name, description, category, available, image_url, CAST(price AS INTEGER) AS price FROM menus WHERE id = $1",
      [id],
    )
    if (result.rows.length > 0) {
      res.json({ success: true, menu: result.rows[0] })
    } else {
      res.status(404).json({ success: false, message: "ไม่พบเมนู" })
    }
  } catch (error) {
    res.status(500).json({ success: false, message: "เกิดข้อผิดพลาด" })
  }
})

//เเก้ไข ชื่อ,ราคา เมนูอาหาร
app.put("/api/menus/:id", authenticateToken, authorizeRoles("admin"), (req, res, next) => { req._uploadPrefix = `menus/${req.params.id}`; next(); }, upload.single("image"), async (req, res) => {
  console.log("🔹 ข้อมูลที่ได้รับจาก Body:", req.body)
  console.log("🔹 ไฟล์ที่อัปโหลด:", req.file)

  try {
    const { id } = req.params
    const { name, price, description, category } = req.body
    let image = req.file ? `${process.env.R2_PUBLIC_URL}/${req.file.key}` : null

    //ตรวจสอบว่า่ชื่อเมนูห้ามว่างไว้
    if (!name.trim()) {
      return res.status(400).json({ success: false, message: "ชื่อเมนูห้ามว่าง!" })
    }

    // ตรวจสอบว่ามีเมนูนี้อยู่ในฐานข้อมูลหรือไม่
    const checkMenu = await pool.query("SELECT * FROM menus WHERE id = $1", [id])
    if (checkMenu.rows.length === 0) {
      return res.status(404).json({ success: false, message: "ไม่พบเมนู" })
    }

    // อัปเดตข้อมูลเมนูใน PostgreSQL
    const result = await pool.query(
      "UPDATE menus SET name = $1, price = $2, description = $3, image_url = COALESCE($4, image_url) , category = $5 WHERE id = $6 RETURNING *",
      [name, price, description, image, category, id],
    )

    res.json({
      success: true,
      message: "อัปเดตเมนูสำเร็จ",
      menu: result.rows[0],
    })
  } catch (error) {
    console.error("❌ API Error:", error)
    res.status(500).json({ success: false, message: "เกิดข้อผิดพลาด" })
  }
})

//อัปเดทสถานะเมนู
app.put("/api/menus/:id/status", authenticateToken, authorizeRoles("admin"), async (req, res) => {
  const { id } = req.params
  const { available } = req.body

  try {
    const result = await pool.query("UPDATE menus SET available = $1 WHERE id = $2 RETURNING *", [available, id])

    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, message: "ไม่พบเมนู" })
    }

    res.json({
      success: true,
      message: "อัปเดตสถานะสำเร็จ",
      menu: result.rows[0],
    })
  } catch (error) {
    console.error("❌ API Error:", error)
    res.status(500).json({ success: false, message: "เกิดข้อผิดพลาด" })
  }
})

//ลบข้อมูลเมนู
app.delete("/api/menus/:id", authenticateToken, authorizeRoles("admin"), async (req, res) => {
  const { id } = req.params
  try {
    await pool.query("DELETE FROM menus WHERE id = $1", [id])
    res.json({ success: true, message: "ลบเมนูสำเร็จ" })
  } catch (error) {
    res.status(500).json({ success: false, message: "เกิดข้อผิดพลาด" })
  }
})

// ดึงข้อมูลมาเเสดงในช่องหมวดหมู่ใน
app.get("/api/categories/", async (req, res) => {
  try {
    const result = await pool.query("SELECT name FROM category ORDER BY name ASC")
    res.json({
      success: true,
      categories: result.rows,
    })
  } catch (error) {
    console.error("Error fetching categories:", error)
    res.status(500).json({ success: false, message: "เกิดข้อผิดพลาดในการดึงหมวดหมู่" })
  }
})

// บันทึกหมวดหมู่ใหม่ลง category
app.post("/api/category/", authenticateToken, authorizeRoles("admin"), async (req, res) => {
  const { name } = req.body

  if (!name || name.trim() === "") {
    return res.status(400).json({ message: "ชื่อหมวดหมู่ห้ามเว้นว่าง" })
  }

  try {
    const result = await pool.query("INSERT INTO category (name) VALUES ($1) RETURNING *", [name.trim()])
    res.status(201).json({ success: true, category: result.rows[0] })
  } catch (error) {
    if (error.code === "23505") {
      // รหัส error สำหรับ unique violation
      return res.status(409).json({ message: "หมวดหมู่นี้มีอยู่แล้ว" })
    }
    console.error("Error inserting category:", error)
    res.status(500).json({ message: "เกิดข้อผิดพลาดภายในเซิร์ฟเวอร์" })
  }
})

// API อัปโหลดรูปภาพแผงผังโต๊ะ
app.post("/api/table_map", authenticateToken, authorizeRoles("admin"), (req, res, next) => { req._uploadPrefix = "table-maps"; next(); }, upload.single("image"), async (req, res) => {
  if (!req.file) {
    return res.status(400).json({ success: false, message: "กรุณาอัปโหลดรูปภาพ" })
  }

  try {
    const imagePath = `${process.env.R2_PUBLIC_URL}/${req.file.key}`

    const client = await pool.connect()
    try {
      const tableMapQuery = `INSERT INTO table_map (image_path) VALUES ($1) RETURNING *`
      const tableMapResult = await client.query(tableMapQuery, [imagePath])
      res.json({ success: true, table_map: tableMapResult.rows[0] })
    } catch (error) {
      console.error("Error saving image data: ", error)
      res.status(500).json({ success: false, message: "เกิดข้อผิดพลาดในการบันทึกข้อมูล" })
    } finally {
      client.release()
    }
  } catch (error) {
    console.error("Error uploading table map to R2:", error)
    res.status(500).json({ success: false, message: "เกิดข้อผิดพลาดในการอัปโหลดรูป" })
  }
})

// บันทึกข้อมูลลง Table_Layouts
app.post("/api/table_layout", authenticateToken, authorizeRoles("admin"), upload.none(), async (req, res) => {
  const { tnumber, tname, time_required } = req.body
  const client = await pool.connect()

  try {
    const insertedRows = []
    const tableLayoutQuery = `INSERT INTO table_layout (tnumber, tname, status, time_required) VALUES ($1, $2, 1, $3) RETURNING id;`

    // 🔹 กรณีมีค่า tnumber → เพิ่มหมายเลขโต๊ะก่อน
    if (tnumber && !isNaN(tnumber) && Number.parseInt(tnumber, 10) > 0) {
      const tableNumber = Number.parseInt(tnumber, 10)

      for (let i = 1; i <= tableNumber; i++) {
        const result = await client.query(tableLayoutQuery, [i, null, time_required])
        insertedRows.push(result.rows[0])
      }
    }

    // 🔹 กรณีมีค่า tname → เพิ่มเฉพาะชื่อโต๊ะได้
    if (tname) {
      const tableNames = tname.split(",").map((name) => name.trim().replace(/^\d+\./, ""))

      for (const name of tableNames) {
        const result = await client.query(tableLayoutQuery, [null, name, time_required])
        insertedRows.push(result.rows[0])
      }
    }

    // ถ้าไม่มีข้อมูลอะไรเลย -> ส่ง error
    if (insertedRows.length === 0) {
      return res.status(400).json({
        success: false,
        message: "กรุณาระบุกรอกข้อมูล",
      })
    }

    res.json({
      success: true,
      message: `เพิ่มข้อมูลสำเร็จ: ${insertedRows.length} รายการ`,
      table_layouts: insertedRows,
    })
  } catch (error) {
    console.error("❌ Error saving table layout:", error)
    res.status(500).json({
      success: false,
      message: "เกิดข้อผิดพลาดภายในเซิร์ฟเวอร์",
    })
  } finally {
    client.release()
  }
})

// API อัปเดตสถานะของโต๊ะเมื่อมีการจอง
app.put("/api/table_layout/:id/status", authenticateToken, authorizeRoles("admin"), async (req, res) => {
  const { id } = req.params // รับ id ของโต๊ะจาก URL
  const { status } = req.body // รับ status จาก body (ต้องเป็น 2 สำหรับจองโต๊ะ)

  if (status !== 2) {
    return res.status(400).json({ success: false, message: "สถานะต้องเป็น 2 เพื่อจองโต๊ะ" })
  }

  try {
    const result = await pool.query("UPDATE table_layout SET status = $1 WHERE id = $2 RETURNING *", [status, id])

    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, message: "ไม่พบโต๊ะ" })
    }

    res.json({
      success: true,
      message: "อัปเดตสถานะโต๊ะเป็นจองแล้ว",
      table: result.rows[0],
    })
  } catch (error) {
    console.error("❌ API Error:", error)
    res.status(500).json({ success: false, message: "เกิดข้อผิดพลาด" })
  }
})

// API ดึงรูปแผนผังโต๊ะ
app.get("/api/table_map", async (req, res) => {
  try {
    const client = await pool.connect()
    const result = await client.query("SELECT * FROM table_map ORDER BY id DESC LIMIT 1")
    client.release()
    res.json({ success: true, table_maps: result.rows })
  } catch (error) {
    console.error("Error fetching table maps:", error)
    res.status(500).json({ success: false, message: "เกิดข้อผิดพลาดในการดึงข้อมูล" })
  }
})

// สร้าง API สำหรับดึงชื่อร้าน สโลเเเกน
app.get("/api/Nrestaurant", async (req, res) => {
  try {
    const result = await pool.query("SELECT name, description FROM table_map LIMIT 1") // Query จาก table_map เพื่อดึงชื่อร้านและสโลแกน
    if (result.rows.length > 0) {
      res.json({
        name: result.rows[0].name,
        description: result.rows[0].description,
      })
    } else {
      res.status(404).json({ message: "Restaurant data not found" })
    }
  } catch (error) {
    console.error("Error fetching restaurant data:", error)
    res.status(500).json({ message: "Server error" })
  }
})

// API ดึงข้อมูล ชื่อโต๊ะ เลขโต๊ะ
app.get("/api/table_layout", async (req, res) => {
  const client = await pool.connect()
  try {
    const query = "SELECT tnumber, tname, status, time_required FROM table_layout ORDER BY tnumber ASC"
    const result = await client.query(query)

    res.json({
      success: true,
      tables: result.rows,
    })
  } catch (error) {
    console.error("Error fetching table layout:", error)
    res.status(500).json({ success: false, message: "เกิดข้อผิดพลาดในการดึงข้อมูลโต๊ะ" })
  } finally {
    client.release()
  }
})

// API ดึงข้อมูล ชื่อโต๊ะ เลขโต๊ะ ของตอนจอง
app.get("/api/Rtable_layout", async (req, res) => {
  const client = await pool.connect()
  try {
    const query = "SELECT tnumber, tname , status FROM table_layout WHERE status != 2 ORDER  BY tnumber ASC"
    const result = await client.query(query)

    res.json({
      success: true,
      tables: result.rows,
    })
  } catch (error) {
    console.error("Error fetching table layout:", error)
    res.status(500).json({ success: false, message: "เกิดข้อผิดพลาดในการดึงข้อมูลโต๊ะ" })
  } finally {
    client.release()
  }
})

// API ดึงข้อมูล ชื่อโต๊ะ เลขโต๊ะของวันปัจจุบัน
app.get("/api/table_today", authenticateToken, authorizeRoles("admin"), async (req, res) => {
  const client = await pool.connect()
  try {
    const query = "SELECT id, tnumber, tname, status FROM table_layout ORDER BY tnumber ASC"
    console.log('Executing query:', query); // Debug log
    
    const result = await client.query(query)
    console.log('Database result rows:', result.rows); // Debug log
    console.log('Number of rows returned:', result.rowCount); // Debug log

    res.json({
      success: true,
      tables: result.rows,
    })
  } catch (error) {
    console.error("Error fetching table layout:", error)
    res.status(500).json({ success: false, message: "เกิดข้อผิดพลาดในการดึงข้อมูลโต๊ะ" })
  } finally {
    client.release()
  }
})

// ดึงข้อมูลการจองโต๊ะของวันปัจจุบันมาแสดงในสถานะโต๊ะ
app.get("/api/reservation_by_table", authenticateToken, authorizeRoles("admin"), async (req, res) => {
  try {
    const tableName = req.query.table // รับจาก query string เช่น "A 3"

    if (!tableName) {
      return res.status(400).json({ error: "Missing table parameter" })
    }

    const today = new Date()
    const day = today.getDate()
    const month = today.getMonth() + 1
    const buddhistYear = today.getFullYear() + 543
    const formattedDate = `${day}/${month}/${buddhistYear}`

    // แยกชื่อโต๊ะจาก query string เช่น "T4,T5" เป็น array
    const tableNames = tableName.split(",")

    // สร้างเงื่อนไข WHERE สำหรับการค้นหาโต๊ะหลายตัว
    const whereCondition = tableNames.map((table, index) => `r.setable LIKE '%${table}%'`).join(" OR ")

    const result = await pool.query(
      `
      SELECT r.id, r.username, r.email, r.date, r.time, r.people, r.detail, r.setable,
        COALESCE(
          json_agg(
            json_build_object(
              'name', f.name,
              'quantity', f.quantity,
              'price', f.price
            )
          ) FILTER (WHERE f.id IS NOT NULL),
          '[]'
        ) AS foodorder
      FROM reservations r
      LEFT JOIN reservation_foods f ON r.id = f.reservation_id
      WHERE r.date = $1 AND (${whereCondition})
      GROUP BY r.id
      ORDER BY r.id DESC;
    `,
      [formattedDate],
    )

    const reservation = result.rows[0] || null

    // คำนวณราคารวมจาก foodorder ถ้ามี

    if (reservation && Array.isArray(reservation.foodorder)) {
      reservation.foodorder = reservation.foodorder.map((food) => ({
        ...food,
        totalpq: Number(food.price) * Number(food.quantity),
      }))

      reservation.total = reservation.foodorder.reduce((sum, f) => sum + f.totalpq, 0)
    }

    res.json({ success: true, reservation })
  } catch (error) {
    console.error("Error fetching reservation by table:", error)
    res.status(500).json({ success: false, error: "Server error" })
  }
})

// อัปเดตสถานะโต๊ะเดี่ยว
app.put("/api/table_status/:id", authenticateToken, authorizeRoles("admin"), async (req, res) => {
  try {
    const { id } = req.params;
    const { status } = req.body;
    
    if (![1, 2].includes(status)) {
      return res.status(400).json({ 
        success: false, 
        error: "Status must be 1 (available) or 2 (occupied)" 
      });
    }

    const result = await pool.query(
      "UPDATE table_layout SET status = $1 WHERE id = $2 RETURNING *",
      [status, id]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({ 
        success: false, 
        error: "Table not found" 
      });
    }

    res.json({ 
      success: true, 
      message: "Table status updated successfully",
      table: result.rows[0]
    });
  } catch (error) {
    console.error("Error updating table status:", error);
    res.status(500).json({ 
      success: false, 
      error: "Server error" 
    });
  }
});

// อัปเดตสถานะโต๊ะทั้งหมด
app.put("/api/table_status/all", authenticateToken, authorizeRoles("admin"), async (req, res) => {
  let client;
  try {
    const { status } = req.body;
    
    console.log('Updating all tables status to:', status); // Debug log
    
    if (![1, 2].includes(status)) {
      return res.status(400).json({ 
        success: false, 
        error: "Status must be 1 (available) or 2 (occupied)" 
      });
    }

    // ใช้ pool.query แทน client.connect() เพื่อความปลอดภัย
    // ตรวจสอบว่ามีโต๊ะในตารางหรือไม่
    const tableCountResult = await pool.query('SELECT COUNT(*) FROM table_layout');
    const tableCount = parseInt(tableCountResult.rows[0].count);
    console.log('Total tables in table_layout:', tableCount); // Debug log

    if (tableCount === 0) {
      return res.status(404).json({ 
        success: false, 
        error: "No tables found in table_layout" 
      });
    }

    // อัปเดตสถานะโต๊ะทั้งหมด
    const result = await pool.query(
      "UPDATE table_layout SET status = $1 RETURNING id, tname, status",
      [status]
    );

    console.log('Update result:', result.rows); // Debug log

    res.json({ 
      success: true, 
      message: `All tables status updated to ${status === 1 ? 'available' : 'occupied'}`,
      updatedCount: result.rowCount,
      updatedTables: result.rows
    });
  } catch (error) {
    console.error("Error updating all tables status:", error);
    res.status(500).json({ 
      success: false, 
      error: "Server error",
      details: error.message,
      stack: error.stack
    });
  }
});

// เเสดงข้อมูลรายการจองโต๊ะปัจจุบัน
app.get("/api/all_reservations_today", async (req, res) => {
  const client = await pool.connect()
  try {
    const { date } = req.query

    function convertToThaiDate(isoDate) {
      const [year, month, day] = isoDate.split("-")
      const buddhistYear = Number.parseInt(year) + 543
      return `${Number.parseInt(day)}/${Number.parseInt(month)}/${buddhistYear}`
    }

    const thaiDate = convertToThaiDate(date)

    const reservations = await client.query(
      `
      SELECT * FROM reservations 
      WHERE date = $1 
      ORDER BY time ASC
    `,
      [thaiDate],
    )

    const enrichedReservations = await Promise.all(
      reservations.rows.map(async (reser) => {
        const foodRes = await client.query(
          `
        SELECT name, quantity, price 
        FROM reservation_foods 
        WHERE reservation_id = $1
      `,
          [reser.id],
        )

        return {
          ...reser,
          foodorder: foodRes.rows.map((food) => ({
            ...food,
            totalpq: Number(food.quantity) * Number(food.price),
          })),
          total: foodRes.rows.reduce((sum, food) => sum + Number(food.quantity) * Number(food.price), 0),
        }
      }),
    )

    res.json({ success: true, reservations: enrichedReservations })
  } catch (err) {
    console.error(err)
    res.status(500).json({ success: false, message: "ไม่สามารถโหลดข้อมูลได้" })
  } finally {
    client.release() // 🔥 สำคัญมาก
  }
})

// ลบข้อมูลในรายการจองโต๊ะปัจจุบัน
app.delete("/api/delete_reservation/:id", async (req, res) => {
  const client = await pool.connect()
  const { id } = req.params

  try {
    // ดึงชื่อโต๊ะจากฐานข้อมูล
    const getRes = await client.query("SELECT setable FROM reservations WHERE id = $1", [id])

    const setableRaw = getRes.rows[0]?.setable || ""

    // กำจัดคำ "(ต่อโต๊ะ)" และแยกชื่อโต๊ะโดยใช้คอมมาและบรรทัดใหม่
    const tables = setableRaw
      .replace("(ต่อโต๊ะ)", "") // ลบคำ "(ต่อโต๊ะ)"
      .split(",") // แยกตามเครื่องหมายคอมมา
      .map((t) => t.trim()) // ตัดช่องว่างที่ไม่จำเป็น
      .filter(Boolean) // กรองค่า empty string ออก

    console.log("โต๊ะที่ต้องการปรับสถานะ: ", tables) // เพิ่มการตรวจสอบ

    // ลบรายการอาหารก่อน เพราะอิง foreign key
    await client.query("DELETE FROM reservation_foods WHERE reservation_id = $1", [id])
    // แล้วค่อยลบการจอง
    await client.query("DELETE FROM reservations WHERE id = $1", [id])

    // อัปเดต status = 1 สำหรับแต่ละโต๊ะ
    for (const table of tables) {
      const updateRes = await client.query(
        `UPDATE table_layout 
         SET status = 1 
         WHERE TRIM(tname) = $1 OR tnumber = $1`,
        [table],
      )

      if (updateRes.rowCount > 0) {
        console.log(`✅ ปรับสถานะโต๊ะ: ${table}`)
      } else {
        console.log(`❌ ไม่พบโต๊ะ: ${table}`)
      }
    }

    res.json({ success: true })
  } catch (err) {
    console.error(err)
    res.status(500).json({ success: false, message: "เกิดข้อผิดพลาดในการลบข้อมูล" })
  } finally {
    client.release()
  }
})

// ลบข้อมูลเมื่อเเก้ไข ข้อมูลเลขโต๊ะ ชื่อโต๊ะ เเผนที่โต๊ะ
app.post("/api/delete_table_data", authenticateToken, authorizeRoles("admin"), async (req, res) => {
  const { imageChanged, tnameChanged, tnumberChanged } = req.body

  console.log("imageChanged:", imageChanged)
  console.log("tnameChanged:", tnameChanged)
  console.log("tnumberChanged:", tnumberChanged)

  try {
    // ลบข้อมูลเก่าก่อนเสมอ
    if (imageChanged) {
      console.log("Deleting table_map...")
      await pool.query("DELETE FROM table_map") // ลบแผนที่โต๊ะ
    }

    if (tnameChanged || tnumberChanged) {
      console.log("Deleting from table_layout where tname or tnumber is not null...")
      await pool.query("DELETE FROM table_layout WHERE tname IS NOT NULL OR tnumber IS NOT NULL") // ลบข้อมูลโต๊ะที่มีอยู่
    }

    res.json({ success: true })
  } catch (error) {
    console.error("Error deleting data:", error)
    res.status(500).json({ success: false, message: "Server error" })
  }
})

// อัปเดตเวลา time_required สำหรับโต๊ะทั้งหมด (ไม่เปลี่ยนชื่อ/หมายเลขโต๊ะ)
app.put("/api/table_layout/time-required", authenticateToken, authorizeRoles("admin"), async (req, res) => {
  const { time_required } = req.body
  if (!time_required) {
    return res.status(400).json({ success: false, message: "กรุณาระบุเวลา" })
  }

  try {
    const result = await pool.query(
      `UPDATE table_layout 
       SET time_required = $1 
       WHERE tname IS NOT NULL OR tnumber IS NOT NULL`,
      [time_required],
    )

    return res.json({ success: true, updated: result.rowCount })
  } catch (error) {
    console.error("Error updating time_required:", error)
    return res.status(500).json({ success: false, message: "Server error" })
  }
})

// API ดึงข้อมูลผู้ใช้จาก token
app.get("/api/user", async (req, res) => {
  const token = req.headers.authorization?.split(" ")[1] // ดึง token จาก header

  if (!token) {
    return res.status(401).json({ success: false, message: "Token ไม่ถูกต้อง" })
  }

  try {
    // ตรวจสอบความถูกต้องของ token
    const decoded = jwt.verify(token, process.env.JWT_SECRET) // เปลี่ยนเป็น key ที่ใช้งานจริง
    const userId = decoded.userId || decoded.id

    // ดึงข้อมูลผู้ใช้จากฐานข้อมูล
    const result = await pool.query("SELECT * FROM users WHERE id = $1", [userId])

    if (result.rows.length > 0) {
      const user = result.rows[0]
      res.json({
        success: true,
        user: {
          fullName: user.username, // หรือใช้ field ที่ต้องการ เช่น username, email ฯลฯ
          email: user.email,
        },
      })
    } else {
      res.status(404).json({ success: false, message: "ไม่พบผู้ใช้" })
    }
  } catch (error) {
    console.error(error)
    res.status(500).json({ success: false, message: "ไม่สามารถดึงข้อมูลผู้ใช้" })
  }
})

// Endpoint สำหรับดึงข้อมูลผู้ใช้
app.get("/api/profile", authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId // token จะมีข้อมูล userId
    const result = await pool.query("SELECT username, email, phone FROM users WHERE id = $1", [userId])

    if (result.rows.length > 0) {
      const { username, email, phone } = result.rows[0]
      res.json({ success: true, user: { username, email, phone } })
    } else {
      res.status(404).json({ success: false, message: "ไม่พบข้อมูลผู้ใช้" })
    }
  } catch (error) {
    console.error("Error fetching user profile:", error)
    res.status(500).json({ success: false, message: "เกิดข้อผิดพลาดในการดึงข้อมูลผู้ใช้" })
  }
})

// Endpoint สำหรับอัปเดตข้อมูลผู้ใช้
app.put("/api/profile", authenticateToken, async (req, res) => {
  const userId = req.user.userId // ได้จาก token
  const { username, email, phone } = req.body

  // เตรียมอัปเดตเฉพาะค่าที่ถูกส่งมา
  const fields = []
  const values = []
  let queryIndex = 1

  if (username !== undefined) {
    fields.push(`username = $${queryIndex++}`)
    values.push(username)
  }
  if (email !== undefined) {
    fields.push(`email = $${queryIndex++}`)
    values.push(email)
  }
  if (phone !== undefined) {
    fields.push(`phone = $${queryIndex++}`)
    values.push(phone)
  }

  if (fields.length === 0) {
    return res.status(400).json({ success: false, message: "ไม่มีข้อมูลสำหรับอัปเดต" })
  }

  values.push(userId) // เพิ่ม userId เป็นพารามิเตอร์สุดท้าย

  const query = `UPDATE users SET ${fields.join(", ")} WHERE id = $${queryIndex}`

  try {
    await pool.query(query, values)
    res.json({ success: true, message: "อัปเดตข้อมูลสำเร็จ" })
  } catch (error) {
    console.error("Error updating user profile:", error)
    res.status(500).json({
      success: false,
      message: "เกิดข้อผิดพลาดในการอัปเดตข้อมูลผู้ใช้",
    })
  }
})

// API บันทึกข้อมูลการจองโต๊ะเเละสั่งอาหาร
app.post("/api/reservation", authenticateToken, async (req, res) => {
  const { username, email, people, date, time, setable, detail, foodorder, tables, paymentSlipId } = req.body

  const client = await pool.connect() // 👈 สร้าง connection ที่สามารถ release ได้

  try {
    await client.query("BEGIN")

    const reservationResult = await client.query(
      `INSERT INTO reservations (username, people, date, time, setable, detail, email, payment_slip_id)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
       RETURNING id`,
      [username, people, date, time, setable, detail, email, paymentSlipId || null],
    )

    const reservationId = reservationResult.rows[0].id

    for (const item of foodorder) {
      await client.query(
        `INSERT INTO reservation_foods (reservation_id, name, price, quantity)
         VALUES ($1, $2, $3, $4)`,
        [reservationId, item.name, item.price, item.quantity],
      )
    }

    await client.query(
      `UPDATE table_layout 
       SET status = 2 
       WHERE tname = ANY($1::text[]) OR tnumber = ANY($1::text[])`,
      [tables],
    )

    // อัปเดตสถานะสลิปเป็น 'used' ถ้ามี
    if (paymentSlipId) {
      await client.query(`UPDATE payment_slips SET status = 'used', updated_at = NOW() WHERE id = $1`, [paymentSlipId])
    }

    await client.query("COMMIT")

    // Notify restaurant by email (best-effort; does not block response)
    try {
      const settings = await pool.query("SELECT restaurant_email FROM settings LIMIT 1")
      const restaurantEmail = settings.rows[0]?.restaurant_email || process.env.RESTAURANT_EMAIL
      if (restaurantEmail) {
        const foodLines = (foodorder || []).map(f => `<li>${f.name} x ${f.quantity} - ฿${Number(f.price).toLocaleString()}</li>`).join("")
        await transporter.sendMail({
          from: process.env.EMAIL_USER,
          to: restaurantEmail,
          subject: "มีการจองโต๊ะใหม่",
          html: `
            <h3>มีการจองใหม่</h3>
            <p><strong>ชื่อ:</strong> ${username}</p>
            <p><strong>อีเมล:</strong> ${email}</p>
            <p><strong>วันที่:</strong> ${date}</p>
            <p><strong>เวลา:</strong> ${time}</p>
            <p><strong>โต๊ะ:</strong> ${setable}</p>
            <p><strong>จำนวนคน:</strong> ${people}</p>
            ${foodLines ? `<p><strong>รายการอาหาร:</strong></p><ul>${foodLines}</ul>` : ""}
            ${detail ? `<p><strong>รายละเอียดเพิ่มเติม:</strong> ${detail}</p>` : ""}
          `,
        })
      }
    } catch (mailErr) {
      console.error("❌ Error sending restaurant notification:", mailErr)
    }

    res.json({ success: true, message: "จองโต๊ะเรียบร้อยเเล้ว" })
  } catch (error) {
    await client.query("ROLLBACK")
    console.error("Error saving reservation:", error)
    res.status(500).json({ success: false, message: "เกิดข้อผิดพลาดในระบบ" })
  } finally {
    client.release()
  }
})

// ===== ADMIN: Edit reservation by id (edit foods and tables) =====
app.put("/api/reservations/:id", authenticateToken, authorizeRoles("admin"), async (req, res) => {
  const { id } = req.params
  const { username, email, people, date, time, setable, detail, foodorder, tables } = req.body
  const client = await pool.connect()
  try {
    await client.query("BEGIN")

    // Fetch current reservation for reverting table statuses
    const currentRes = await client.query(`SELECT setable FROM reservations WHERE id = $1`, [id])
    if (currentRes.rowCount === 0) {
      await client.query("ROLLBACK")
      return res.status(404).json({ success: false, message: "ไม่พบการจอง" })
    }

    const parseTables = (setableStr) => (setableStr || "")
      .replace("(ต่อโต๊ะ)", "")
      .split(",")
      .map(t => t.trim())
      .filter(Boolean)

    const oldTables = parseTables(currentRes.rows[0].setable)

    // Update reservation core fields
    await client.query(
      `UPDATE reservations SET username = COALESCE($1, username), email = COALESCE($2, email), people = COALESCE($3, people), date = COALESCE($4, date), time = COALESCE($5, time), setable = COALESCE($6, setable), detail = COALESCE($7, detail) WHERE id = $8`,
      [username ?? null, email ?? null, people ?? null, date ?? null, time ?? null, setable ?? null, detail ?? null, id]
    )

    // Replace foods if provided
    if (Array.isArray(foodorder)) {
      await client.query(`DELETE FROM reservation_foods WHERE reservation_id = $1`, [id])
      for (const item of foodorder) {
        await client.query(
          `INSERT INTO reservation_foods (reservation_id, name, price, quantity) VALUES ($1, $2, $3, $4)`,
          [id, item.name, item.price, item.quantity]
        )
      }
    }

    // Update table statuses if tables provided
    if (Array.isArray(tables)) {
      // Free old tables
      for (const t of oldTables) {
        await client.query(
          `UPDATE table_layout SET status = 1 WHERE TRIM(tname) = $1 OR CAST(tnumber AS TEXT) = $1`,
          [t]
        )
      }
      // Occupy new tables
      await client.query(
        `UPDATE table_layout SET status = 2 WHERE tname = ANY($1::text[]) OR tnumber = ANY($1::text[])`,
        [tables]
      )
    }

    await client.query("COMMIT")
    res.json({ success: true, message: "อัปเดตการจองสำเร็จ" })
  } catch (error) {
    await client.query("ROLLBACK")
    console.error("❌ Error updating reservation:", error)
    res.status(500).json({ success: false, message: "เกิดข้อผิดพลาดในระบบ" })
  } finally {
    client.release()
  }
})

// API บันทึกข้อมูลเเก้ไขจองโต๊ะเเละสั่งอาหาร
app.post("/api/reseredit", authenticateToken, async (req, res) => {
  const { people, time, detail, foodorder } = req.body

  const email = req.user.email
  const client = await pool.connect() // 👈 สร้าง connection ที่สามารถ release ได้
  console.log("email:", email)
  // console.log("foodorder:", foodorder);

  try {
    await client.query("BEGIN")

    // 1. ค้นหา reservation ล่าสุดของผู้ใช้
    const reservationRes = await client.query(`SELECT id FROM reservations WHERE email = $1 ORDER BY id DESC LIMIT 1`, [
      email,
    ])

    if (reservationRes.rows.length === 0) {
      return res.status(404).json({ success: false, message: "ไม่พบการจองของผู้ใช้นี้" })
    }

    const reservationId = reservationRes.rows[0].id
    console.log("อัปเ ดตรายการอาหาร reservation_id:", reservationId)

    // 2. อัปเดต people, time, detail
    await client.query(
      `UPDATE reservations
       SET people = $1, time = $2, detail = $3
       WHERE id = $4`,
      [people, time, detail, reservationId],
    )

    // 3. ลบอาหารเก่าก่อน
    await client.query(`DELETE FROM reservation_foods WHERE reservation_id = $1`, [reservationId])

    // 4. เพิ่มอาหารใหม่
    for (const item of foodorder) {
      await client.query(
        `INSERT INTO reservation_foods (reservation_id, name, price, quantity)
         VALUES ($1, $2, $3, $4)`,
        [reservationId, item.name, item.price, item.quantity],
      )
    }

    await client.query("COMMIT")
    res.json({ success: true, message: "อัปเดทการจองเรียบร้อยเเล้ว" })
  } catch (error) {
    await client.query("ROLLBACK")
    console.error("Error saving reservation:", error)
    res.status(500).json({ success: false, message: "เกิดข้อผิดพลาดในระบบ" })
  } finally {
    client.release() //  ใช้ release กับ client ไม่ใช่ pool
  }
})

// API ยกเลิกการจองของ user เเล้วปรับสถานะโต๊ะให้ว่างอัตโนมัติ
app.delete("/api/reservation/cancel", async (req, res) => {
  const client = await pool.connect()
  const { email, date } = req.body

  try {
    // 1. ดึงชื่อโต๊ะจากข้อมูลการจอง
    const getRes = await client.query("SELECT setable FROM reservations WHERE email = $1 AND date = $2", [email, date])

    if (getRes.rowCount === 0) {
      return res.status(404).json({ message: "ไม่พบการจองในวันนี้ของผู้ใช้นี้" })
    }

    const setableRaw = getRes.rows[0].setable || ""

    const tables = setableRaw
      .replace("(ต่อโต๊ะ)", "")
      .split(",")
      .map((t) => t.trim())
      .filter(Boolean)

    console.log("โต๊ะที่ต้องการปลดสถานะ: ", tables)

    // 2. อัปเดตสถานะโต๊ะเป็นว่าง (status = 1)
    for (const table of tables) {
      const updateRes = await client.query(
        `UPDATE table_layout 
         SET status = 1 
         WHERE TRIM(tname) = $1 OR tnumber = $1`,
        [table],
      )

      if (updateRes.rowCount > 0) {
        console.log(`✅ ปรับสถานะโต๊ะ: ${table}`)
      } else {
        console.log(`❌ ไม่พบโต๊ะ: ${table}`)
      }
    }

    // 3. ลบข้อมูลใน reservation_foods (อิง foreign key)
    await client.query(
      "DELETE FROM reservation_foods WHERE reservation_id IN (SELECT id FROM reservations WHERE email = $1 AND date = $2)",
      [email, date],
    )

    // 4. ลบข้อมูลการจอง
    const result = await client.query("DELETE FROM reservations WHERE email = $1 AND date = $2", [email, date])

    if (result.rowCount > 0) {
      console.log(`✅ ลบการจองสำหรับ: ${email} วันที่: ${date}`)
      res.json({ message: "ยกเลิกการจองเรียบร้อยแล้ว" })
    } else {
      res.status(404).json({ message: "ไม่พบการจองในวันนี้ของผู้ใช้นี้" })
    }
  } catch (err) {
    console.error(err)
    res.status(500).json({ message: "เกิดข้อผิดพลาดภายในเซิร์ฟเวอร์" })
  } finally {
    client.release()
  }
})

//API ร้าน ดูประวัติการจองทั้งหมดของร้าน
app.get("/api/restaurant/history", authenticateToken, authorizeRoles("admin"), async (req, res) => {
  try {
    // ดึงการจองทั้งหมด
    const reservationsRes = await pool.query("SELECT * FROM reservations ORDER BY date DESC, time DESC")
    const reservations = reservationsRes.rows

    // ดึงรายการอาหารทั้งหมดแบบรวม
    const foodRes = await pool.query("SELECT * FROM reservation_foods")
    const allFoods = foodRes.rows

    // สร้าง array ของการจองแต่ละรายการ พร้อมรายการอาหารที่เกี่ยวข้อง
    const result = reservations.map((res) => {
      const foods = allFoods
        .filter((f) => f.reservation_id === res.id)
        .map((f) => ({
          name: f.name,
          quantity: f.quantity,
          totalpq: Number(f.price) * Number(f.quantity), // คำนวณ total เอง
        }))

      const totalPrice = foods.reduce((sum, food) => sum + food.totalpq, 0)

      return {
        ...res,
        foods,
        total: totalPrice,
      }
    })

    res.json(result)
  } catch (error) {
    console.error("Error fetching history:", error)
    res.status(500).json({ error: "Internal server error" })
  }
})

//API user ดูประวัติการจองทั้งหมดของไอดีตัวเอง
app.get("/api/user/history", authenticateToken, async (req, res) => {
  try {
    const userEmail = req.user.email // ดึง email จาก token
    const reservationsRes = await pool.query(
      "SELECT * FROM reservations WHERE email = $1 ORDER BY date DESC, time DESC",
      [userEmail],
    )
    // console.log("🔥 JWT payload:", req.user.email); // <<--- สำคัญสุด!
    const reservations = reservationsRes.rows

    if (reservations.length === 0) {
      return res.json([]) // ไม่มีประวัติ
    }

    const reservationIds = reservations.map((r) => r.id)
    const foodRes = await pool.query("SELECT * FROM reservation_foods WHERE reservation_id = ANY($1::int[])", [
      reservationIds,
    ])
    const allFoods = foodRes.rows

    const result = reservations.map((res) => {
      const foods = allFoods
        .filter((f) => f.reservation_id === res.id)
        .map((f) => ({
          name: f.name,
          quantity: f.quantity,
          totalpq: Number(f.price) * Number(f.quantity), // คำนวณ total เอง
        }))

      const totalPrice = foods.reduce((sum, food) => sum + food.totalpq, 0)

      return {
        ...res,
        foods,
        total: totalPrice,
      }
    })

    res.json(result)
  } catch (error) {
    console.error("Error fetching history:", error)
    res.status(500).json({ error: "Internal server error" })
  }
})

//API user ดูประวัติการจองของวันปัจจุบัน
app.get("/api/reservation/today", authenticateToken, async (req, res) => {
  try {
    const email = req.user.email
    const today = new Date()
    const day = today.getDate()
    const month = today.getMonth() + 1
    const buddhistYear = today.getFullYear() + 543
    const formattedDate = `${day}/${month}/${buddhistYear}` // เเสดงวัน/เดือน/ปี ตัวอย่าง 12/4/2568

    // console.log("Querying for date:", formattedDate, "email:", email);

    // ดึงการจองพร้อมรายการอาหาร
    const result = await pool.query(
      `
      SELECT r.*, 
        COALESCE(
          json_agg(
            json_build_object(
              'name', f.name,
              'quantity', f.quantity,
              'price', f.price
            )
          ) FILTER (WHERE f.id IS NOT NULL),
          '[]'
        ) AS foodorder
      FROM reservations r
      LEFT JOIN reservation_foods f ON r.id = f.reservation_id
      WHERE r.date = $1 AND r.email = $2
      GROUP BY r.id
    `,
      [formattedDate, email],
    )

    res.json(result.rows)
  } catch (error) {
    console.error("Error fetching today's reservations:", error)
    res.status(500).json({ error: "Server error" })
  }
})

//ส่งลิ่งเปลื่ยนรหัส

// ขอเปลี่ยนรหัสผ่าน
app.post("/api/request-reset-password", async (req, res) => {
  const { email } = req.body

  try {
    const userResult = await pool.query("SELECT * FROM users WHERE email = $1", [email])

    if (userResult.rows.length === 0) {
      return res.status(404).json({ success: false, message: "ไม่พบอีเมลนี้ในระบบ" })
    }

    const token = uuidv4() // UUID สำหรับ reset
    const expires = new Date(Date.now() + 10 * 60 * 1000) // 10 นาที

    await pool.query(
      `INSERT INTO password_resets (email, token, expires_at) VALUES ($1, $2, $3)
       ON CONFLICT (email) DO UPDATE SET token = EXCLUDED.token, expires_at = EXCLUDED.expires_at`,
      [email, token, expires],
    )

    const resetLink = `http://localhost:3000/reset-password/${token}`

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: "ลิงก์เปลี่ยนรหัสผ่าน",
      html: `<p>คลิกที่ลิงก์ด้านล่างเพื่อเปลี่ยนรหัสผ่านของคุณ:</p>
             <a href="${resetLink}">${resetLink}</a>
             <p>ลิงก์นี้จะหมดอายุใน 1 ชั่วโมง</p>`,
    }

    await transporter.sendMail(mailOptions)

    res.json({ success: true, message: "ส่งลิงก์เปลี่ยนรหัสผ่านเรียบร้อยแล้ว" })
  } catch (err) {
    console.error("Request reset error:", err)
    res.status(500).json({ success: false, message: "เกิดข้อผิดพลาดในระบบ" })
  }
})

//เพิ่ม API: ตรวจสอบและรีเซ็ตรหัสผ่าน
app.post("/api/reset-password", async (req, res) => {
  const { token, newPassword } = req.body

  try {
    const result = await pool.query("SELECT * FROM password_resets WHERE token = $1 AND expires_at > NOW()", [token])

    if (result.rows.length === 0) {
      return res.status(400).json({ success: false, message: "Token ไม่ถูกต้องหรือหมดอายุแล้ว" })
    }

    const email = result.rows[0].email
    const hashedPassword = await bcrypt.hash(newPassword, 10)

    await pool.query("UPDATE users SET password = $1 WHERE email = $2", [hashedPassword, email])
    await pool.query("DELETE FROM password_resets WHERE email = $1", [email])

    res.json({ success: true, message: "เปลี่ยนรหัสผ่านสำเร็จแล้ว" })
  } catch (err) {
    console.error("Reset password error:", err)
    res.status(500).json({ success: false, message: "เกิดข้อผิดพลาดในระบบ" })
  }
})

// เพิ่มแจ้งเตื่อนมาก่อน 20 นาที่

cron.schedule("* * * * *", async () => {
  const now = new Date()
  const twentyMinutesLater = new Date(now.getTime() + 20 * 60 * 1000)

  // วันที่แบบ พ.ศ. สำหรับใช้กับฐานข้อมูล
  const day = now.getDate()
  const month = now.getMonth() + 1
  const year = now.getFullYear() + 543
  const formattedDate = `${day}/${month}/${year}` // DD/MM/พ.ศ.

  try {
    const result = await pool.query(
      `SELECT * FROM reservations 
       WHERE date = $1 
         AND reminder_sent = FALSE`,
      [formattedDate],
    )

    for (const reservation of result.rows) {
      const [resHour, resMinute] = reservation.time.split(":").map(Number)

      // แปลง พ.ศ. → ค.ศ. สำหรับ Date
      const gregorianYear = year - 543
      const reservationTime = new Date(gregorianYear, month - 1, day, resHour, resMinute)

      const timeDiff = reservationTime.getTime() - now.getTime()

      if (timeDiff > 0 && timeDiff <= 20 * 60 * 1000) {
        const mailOptions = {
          from: process.env.EMAIL_USER,
          to: reservation.email,
          subject: "ใกล้ถึงเวลาจองโต๊ะแล้ว",
          html: `
            <p>เรียนคุณ ${reservation.username},</p>
            <p>นี่คือการแจ้งเตือนว่าคุณได้จองโต๊ะไว้วันนี้ เวลา ${reservation.time}</p>
            <p>ระบบแจ้งเตือนล่วงหน้า 20 นาที</p>
            <p>ขอบคุณที่ใช้บริการ</p>
          `,
        }

        await transporter.sendMail(mailOptions)

        await pool.query(`UPDATE reservations SET reminder_sent = TRUE WHERE id = $1`, [reservation.id])

        console.log(`✅ ส่งอีเมลแจ้งเตือนล่วงหน้าให้ ${reservation.email}`)
      }
    }
  } catch (error) {
    console.error("❌ Error sending reminders:", error)
  }
})

// Cron Job รีเซ็ตการจองโต๊ะหลัง 00:10 น. ทุกวัน
cron.schedule("15 0 * * *", async () => {
  try {
    const now = new Date()
    const today = new Date(now.getFullYear(), now.getMonth(), now.getDate()) // วันที่เริ่มต้นของวันปัจจุบัน

    // อัปเดตสถานะโต๊ะทั้งหมดเป็น 1 (ว่าง)
    await pool.query("UPDATE table_layout SET status = 1")

    // ลบการจองที่เก่ากว่าวันปัจจุบันจาก reservations
    await pool.query(
      "DELETE FROM reservations WHERE date < $1",
      [today.toLocaleDateString("en-GB")], // รูปแบบ DD/MM/YYYY
    )

    // ลบข้อมูลอาหารที่เกี่ยวข้องจาก reservation_foods
    await pool.query("DELETE FROM reservation_foods WHERE reservation_id NOT IN (SELECT id FROM reservations)")

    console.log("✅ รีเซ็ตสถานะโต๊ะและลบการจองเก่าเรียบร้อยแล้ว")
  } catch (error) {
    console.error("❌ Error resetting table bookings:", error)
  }
})

// Error handling middleware
app.use((error, req, res, next) => {
  console.error("Server Error:", error)

  if (error instanceof multer.MulterError) {
    if (error.code === "LIMIT_FILE_SIZE") {
      return res.status(400).json({
        success: false,
        message: "ไฟล์มีขนาดใหญ่เกินไป (สูงสุด 5MB)",
      })
    }
  }

  res.status(500).json({
    success: false,
    message: "เกิดข้อผิดพลาดภายในเซิร์ฟเวอร์",
  })
})

// Start server
app.listen(PORT, () => {
  console.log(`🚀 Server is running on port ${PORT}`)
  console.log(`📍 Health check: http://localhost:${PORT}/api/health`)
  console.log("🚀 Server setup completed with Payment Slip Upload feature")
  console.log("📁 Payment slips will be saved to: ./uploads/Payment slip/")
})

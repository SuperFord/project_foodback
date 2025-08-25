const { Pool } = require('pg');
const bcrypt = require('bcrypt');
require('dotenv').config();

const pool = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_NAME,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT,
});

async function setupRestaurantAdmins() {
  try {
    console.log('🚀 เริ่มต้นการสร้างระบบล็อกอินสำหรับ Restaurant...');

    // สร้างตาราง restaurant_admins
    console.log('📋 สร้างตาราง restaurant_admins...');
    await pool.query(`
      CREATE TABLE IF NOT EXISTS restaurant_admins (
        id SERIAL PRIMARY KEY,
        username VARCHAR(50) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        role VARCHAR(20) DEFAULT 'admin',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);
    console.log('✅ สร้างตารางสำเร็จ');

    // สร้าง index
    console.log('🔍 สร้าง index...');
    await pool.query(`
      CREATE INDEX IF NOT EXISTS idx_restaurant_admins_username ON restaurant_admins(username);
    `);
    console.log('✅ สร้าง index สำเร็จ');

    // สร้างรหัสผ่านที่ hash แล้ว
    console.log('🔐 สร้างรหัสผ่านที่ hash แล้ว...');
    const password1 = await bcrypt.hash('admin1234', 10);
    const password2 = await bcrypt.hash('admin5678', 10);

    // เพิ่มข้อมูล admin
    console.log('👤 เพิ่มข้อมูล admin...');
    const result = await pool.query(`
      INSERT INTO restaurant_admins (username, password_hash, role) VALUES
      ($1, $2, 'admin'),
      ($3, $4, 'admin')
      ON CONFLICT (username) DO NOTHING
      RETURNING username;
    `, ['admin1', password1, 'admin2', password2]);

    if (result.rows.length > 0) {
      console.log('✅ เพิ่มข้อมูล admin สำเร็จ:');
      result.rows.forEach(row => {
        console.log(`   - ${row.username}`);
      });
    } else {
      console.log('ℹ️ ข้อมูล admin มีอยู่แล้ว');
    }

    // ตรวจสอบข้อมูล
    console.log('🔍 ตรวจสอบข้อมูลในฐานข้อมูล...');
    const checkResult = await pool.query('SELECT username, role, created_at FROM restaurant_admins');
    console.log('📊 ข้อมูล admin ทั้งหมด:');
    checkResult.rows.forEach(row => {
      console.log(`   - Username: ${row.username}, Role: ${row.role}, Created: ${row.created_at}`);
    });

    console.log('\n🎉 การตั้งค่าระบบล็อกอินสำหรับ Restaurant เสร็จสิ้น!');
    console.log('\n📝 ข้อมูลสำหรับล็อกอิน:');
    console.log('   Username: admin1, Password: admin1234');
    console.log('   Username: admin2, Password: admin5678');

  } catch (error) {
    console.error('❌ เกิดข้อผิดพลาด:', error);
  } finally {
    await pool.end();
  }
}

setupRestaurantAdmins();

// server/src/db.js
const mysql = require("mysql2/promise"); // Pakai versi promise
require("dotenv").config();

const pool = mysql.createPool({
  host: "localhost",
  user: "root", // User default XAMPP adalah 'root'
  password: "", // Password default XAMPP kosong
  database: "toko_bangunan",
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
});

module.exports = pool;

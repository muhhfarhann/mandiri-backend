// server/src/index.js
const express = require("express");
const cors = require("cors");
const pool = require("./db"); // Pastikan file db.js koneksi MySQL Anda benar
const bcrypt = require("bcryptjs");
const session = require("express-session");
const MySQLStore = require("express-mysql-session")(session);
const path = require("path");
const multer = require("multer");

const app = express();
const PORT = process.env.PORT || 5000;

const fs = require("fs"); // Tambahkan fs

// === 1. MIDDLEWARE ===
app.use(
  cors({
    origin: "https://mandiri-frontend.vercel.app",
    credentials: true,
    methods: ["GET", "POST", "PUT", "DELETE", "PATCH"],
  })
);

app.use(express.json());
// Serve folder uploads agar gambar profile/produk bisa diakses publik
const uploadDir = path.join(__dirname, "public/uploads");
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

// Serve Static Files
app.use("/uploads", express.static(uploadDir));

// === 2. SESSION SETUP ===
const dbOptions = {
  host: "localhost",
  user: "root",
  password: "",
  database: "toko_bangunan",
  clearExpired: true,
  checkExpirationInterval: 900000,
  expiration: 86400000,
};
const sessionStore = new MySQLStore(dbOptions);

app.use(
  session({
    key: "mandiri_session_id",
    secret: "secret",
    store: sessionStore,
    resave: false,
    saveUninitialized: false,
    cookie: {
      maxAge: 86400000,
      httpOnly: true,
      secure: true, // true hanya jika HTTPS
      sameSite: "none",
      maxAge: 1000 * 60 * 60 * 24,
    },
  })
);

// === 3. MULTER (UPLOAD CONFIG) ===
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    // ⬇⬇⬇ FIX UTAMA DI SINI
    cb(null, path.join(__dirname, "public/uploads"));
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + "-" + Math.round(Math.random() * 1e9);
    cb(null, uniqueSuffix + path.extname(file.originalname));
  },
});

const upload = multer({ storage });

// Middleware Cek Admin
const isAdmin = (req, res, next) => {
  if (req.session.adminId) {
    next();
  } else {
    res.status(401).json({ message: "Unauthorized: Login Admin Dulu" });
  }
};

// =========================================
// ============ 4. AUTH ROUTES =============
// =========================================

// Cek Session (Siapa yang sedang Login?)
app.post("/api/auth/check", (req, res) => {
  if (req.session.userId) {
    return res.json({
      user: {
        id: req.session.userId,
        username: req.session.username,
        role: "user",
      },
    });
  }
  if (req.session.adminId) {
    return res.json({
      user: {
        id: req.session.adminId,
        username: req.session.adminUsername,
        role: "admin",
      },
    });
  }
  res.status(401).json({ message: "Not logged in" });
});

// Register User
app.post("/api/register", async (req, res) => {
  const { username, email, password } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    await pool.execute(
      "INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
      [username, email, hashedPassword]
    );
    res.status(201).json({ message: "Registrasi sukses" });
  } catch (err) {
    console.error(err);
    res
      .status(500)
      .json({ error: "Gagal daftar, email/username mungkin sudah ada." });
  }
});

// Login User
app.post("/api/login-user", async (req, res) => {
  const { email, password } = req.body;
  try {
    const [rows] = await pool.query("SELECT * FROM users WHERE email = ?", [
      email,
    ]);
    if (rows.length === 0)
      return res.status(401).json({ message: "User tidak ditemukan" });

    const isMatch = await bcrypt.compare(password, rows[0].password);
    if (!isMatch) return res.status(401).json({ message: "Password salah" });

    req.session.userId = rows[0].id;
    req.session.username = rows[0].username;

    req.session.save((err) => {
      if (err) return res.status(500).json({ message: "Gagal login" });
      res.json({ id: rows[0].id, username: rows[0].username, role: "user" });
    });
  } catch (err) {
    res.status(500).send(err.message);
  }
});

// Login Admin
app.post("/api/admin/login", async (req, res) => {
  const { username, password } = req.body;
  try {
    const [rows] = await pool.query("SELECT * FROM admins WHERE username = ?", [
      username,
    ]);
    if (rows.length === 0)
      return res.status(401).json({ message: "Admin tidak ditemukan" });

    const admin = await Admin.findOne({ where: { username } });
    if (!admin) return res.status(401).json({ message: "Login gagal" });

    const isMatch = await bcrypt.compare(password, rows[0].password);
    if (!isMatch) return res.status(401).json({ message: "Password salah" });

    req.session.adminId = rows[0].id;
    req.session.adminUsername = rows[0].username;

    req.session.save((err) => {
      if (err) return res.status(500).json({ message: "Gagal simpan session" });
      res.json({ username: rows[0].username, role: "admin" });
    });
  } catch (err) {
    res.status(500).send(err.message);
  }
});

// Logout (Universal)
app.post("/api/admin/logout", (req, res) => {
  req.session.destroy(() => {
    res.clearCookie("mandiri_session_id");
    res.status(200).json({ message: "Logout berhasil" });
  });
});

// =========================================
// =========== 5. PROFILE ROUTES ===========
// =========================================

app.get("/api/user/profile", async (req, res) => {
  const currentId = req.session.userId || req.session.adminId;
  const isUser = !!req.session.userId;

  if (!currentId) return res.status(401).json({ message: "Belum Login" });

  try {
    let query = isUser
      ? `SELECT id, username, email, profile_pic FROM users WHERE id = ?`
      : `SELECT id, username FROM admins WHERE id = ?`;

    const [rows] = await pool.query(query, [currentId]);
    if (rows.length === 0)
      return res.status(404).json({ message: "User not found" });

    const data = rows[0];
    if (!isUser) {
      data.email = "admin@mandiristeel.com"; // Dummy email admin
      data.profile_pic = null;
    }
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put("/api/user/profile", upload.single("profile_pic"), async (req, res) => {
  const currentId = req.session.userId; // Fokus update user biasa
  if (!currentId) return res.status(401).json({ message: "Unauthorized" });

  const { username, email, remove_pic } = req.body;

  try {
    let query = `UPDATE users SET username = ?, email = ?`;
    let params = [username, email];

    if (req.file) {
      query += `, profile_pic = ?`;
      params.push(`/uploads/${req.file.filename}`);
    } else if (remove_pic === "true") {
      query += `, profile_pic = NULL`;
    }

    query += " WHERE id = ?";
    params.push(currentId);

    await pool.execute(query, params);

    // Update session agar navbar langsung berubah
    req.session.username = username;
    req.session.save();

    res.json({ message: "Profil berhasil diupdate" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Gagal update profile" });
  }
});

// =========================================
// =========== 6. PRODUCT ROUTES ===========
// =========================================

// GET All Products (Public - Dipakai di Halaman Produk & Inventory)
app.get("/api/products", async (req, res) => {
  try {
    const [rows] = await pool.query("SELECT * FROM products ORDER BY id DESC");
    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

// GET Categories (Untuk Filter)
app.get("/api/categories", async (req, res) => {
  try {
    const [rows] = await pool.query("SELECT * FROM categories");
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Admin: Add Product
app.post("/api/products", isAdmin, upload.single("image"), async (req, res) => {
  const { name, kode, category_id, price, stock, satuan, description } =
    req.body;
  const img = req.file ? `/uploads/${req.file.filename}` : null;

  try {
    await pool.execute(
      "INSERT INTO products (name, kode, category_id, price, stock, satuan, description, image_url) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
      [name, kode, category_id, price, stock, satuan, description, img]
    );
    res.status(201).json({ message: "Produk ditambahkan" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Admin: Update Product
app.put(
  "/api/products/:id",
  isAdmin,
  upload.single("image"),
  async (req, res) => {
    const { id } = req.params;
    const { name, kode, category_id, price, stock, satuan, description } =
      req.body;

    try {
      const [old] = await pool.query(
        "SELECT image_url FROM products WHERE id = ?",
        [id]
      );

      let img = old.length ? old[0].image_url : null;
      if (req.file) img = `/uploads/${req.file.filename}`;

      await pool.execute(
        `UPDATE products 
         SET name=?, kode=?, category_id=?, price=?, stock=?, satuan=?, description=?, image_url=? 
         WHERE id=?`,
        [name, kode, category_id, price, stock, satuan, description, img, id]
      );

      res.json({ message: "Produk diupdate" });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: err.message });
    }
  }
);

// Admin: Delete Product
app.delete("/api/products/:id", isAdmin, async (req, res) => {
  try {
    await pool.execute("UPDATE products SET is_active = 0 WHERE id = ?", [
      req.params.id,
    ]);
    res.json({ message: "Produk dinonaktifkan (soft delete)" });
  } catch (err) {
    res.status(500).json({ error: "Gagal hapus, mungkin ada relasi order" });
  }
});

// =========================================
// ============ 7. ORDER ROUTES ============
// =========================================

// Admin: Get All Orders
app.get("/api/orders", isAdmin, async (req, res) => {
  try {
    const [rows] = await pool.query(
      "SELECT * FROM orders ORDER BY order_date DESC"
    );
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Admin: Get Order Detail
app.get("/api/orders/:id", isAdmin, async (req, res) => {
  const { id } = req.params;
  try {
    const [order] = await pool.query("SELECT * FROM orders WHERE id = ?", [id]);
    if (order.length === 0)
      return res.status(404).json({ message: "Not Found" });

    const [items] = await pool.query(
      "SELECT p.name as product_name, oi.quantity, oi.price_per_unit FROM order_items oi JOIN products p ON oi.product_id = p.id WHERE oi.order_id = ?",
      [id]
    );
    res.json({ ...order[0], items });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Admin: Update Status Order
app.patch("/api/orders/:id/status", isAdmin, async (req, res) => {
  const { status } = req.body;
  try {
    await pool.execute("UPDATE orders SET status = ? WHERE id = ?", [
      status,
      req.params.id,
    ]);
    res.json({ message: "Status Updated" });
  } catch (err) {
    res.status(500).send("Gagal update status");
  }
});

// User: Create Order
app.post("/api/orders", async (req, res) => {
  if (!req.session.userId)
    return res.status(401).json({ message: "Harus Login" });

  const {
    customer_name,
    customer_email,
    customer_phone,
    customer_city,
    customer_address,
    company_name,
    order_notes,
    total_amount,
    items,
  } = req.body;
  const conn = await pool.getConnection();

  try {
    await conn.beginTransaction();

    // Insert Order Utama
    const [r] = await conn.execute(
      "INSERT INTO orders (user_id, customer_name, customer_email, customer_phone, customer_city, customer_address, company_name, order_notes, total_amount) VALUES (?,?,?,?,?,?,?,?,?)",
      [
        req.session.userId,
        customer_name,
        customer_email,
        customer_phone,
        customer_city,
        customer_address,
        company_name,
        order_notes,
        total_amount,
      ]
    );

    // Insert Items & Kurangi Stok
    for (const i of items) {
      await conn.execute(
        "INSERT INTO order_items (order_id, product_id, quantity, price_per_unit) VALUES (?,?,?,?)",
        [r.insertId, i.id, i.quantity, i.price]
      );
      await conn.execute("UPDATE products SET stock = stock - ? WHERE id = ?", [
        i.quantity,
        i.id,
      ]);
    }

    await conn.commit();
    res.status(201).json({ orderId: r.insertId });
  } catch (e) {
    await conn.rollback();
    console.error(e);
    res.status(500).send(e.message);
  } finally {
    conn.release();
  }
});

// =========================================
// ========= 8. DASHBOARD ROUTES ===========
// =========================================

app.get("/api/admin/dashboard-stats", isAdmin, async (req, res) => {
  try {
    const [[p]] = await pool.query(
      "SELECT SUM(total_amount) as total FROM orders WHERE status IN ('Selesai','Proses','Dikirim')"
    );

    const [[pb]] = await pool.query(
      "SELECT COUNT(*) as total FROM orders WHERE status = 'Pending'"
    );

    const [[sh]] = await pool.query(
      "SELECT COUNT(*) as total FROM products WHERE stock = 0 AND is_active = 1"
    );

    const [[tp]] = await pool.query("SELECT COUNT(*) as total FROM products");

    const [[tc]] = await pool.query(
      "SELECT COUNT(DISTINCT customer_email) as total FROM orders"
    );

    const [pt] = await pool.query(
      `SELECT 
        p.name, 
        p.image_url, 
        SUM(oi.quantity) as total_terjual 
      FROM order_items oi 
      JOIN products p ON oi.product_id = p.id 
      GROUP BY p.id 
      ORDER BY total_terjual DESC 
      LIMIT 5`
    );

    const [tx] = await pool.query(
      "SELECT id, customer_name, total_amount, order_date, status FROM orders ORDER BY order_date DESC LIMIT 5"
    );

    res.json({
      totalPendapatan: p.total || 0,
      pesananBaru: pb.total || 0,
      stokHabis: sh.total || 0,
      totalProduk: tp.total || 0,
      totalPembeli: tc.total || 0,
      produkTerjual: pt.reduce((a, b) => a + b.total_terjual, 0),
      produkTerlaris: pt,
      transaksiTerakhir: tx,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

// Dashboard: View All Top Products
app.get("/api/admin/all-top-products", isAdmin, async (req, res) => {
  const [rows] = await pool.query(
    "SELECT p.name, p.image_url, p.price, SUM(oi.quantity) as total_terjual FROM order_items oi JOIN products p ON oi.product_id = p.id GROUP BY p.id ORDER BY total_terjual DESC"
  );
  res.json(rows);
});

// Dashboard: View All Transactions
app.get("/api/admin/all-transactions", isAdmin, async (req, res) => {
  const [rows] = await pool.query(
    "SELECT id, customer_name, total_amount, order_date, status FROM orders ORDER BY order_date DESC"
  );
  res.json(rows);
});

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));

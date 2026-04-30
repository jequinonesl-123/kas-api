import express from "express";
import pkg from "pg";
import cors from "cors";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";

const { Pool } = pkg;

const app = express();

// =====================
// 🔧 MIDDLEWARES
// =====================
app.use(cors());
app.use(express.json());

// =====================
// 🔌 DB
// =====================
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false,
  },
});

// =====================
// 🔐 AUTH MIDDLEWARE
// =====================
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) return res.sendStatus(401);

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

// =====================
// 🏠 ROOT
// =====================
app.get("/", (req, res) => {
  res.send("VERSION NUEVA");
});

// =====================
// 🧪 TEST DB
// =====================
app.get("/test-db", async (req, res) => {
  try {
    const result = await pool.query("SELECT NOW()");
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// =====================
// 🔐 REGISTER
// =====================
app.post("/auth/register", async (req, res) => {
  try {
    const { email, password } = req.body;

    const hashedPassword = await bcrypt.hash(password, 10);

    const result = await pool.query(
      `INSERT INTO auth_users (email, password_hash)
       VALUES ($1, $2)
       RETURNING id, email`,
      [email, hashedPassword]
    );

    res.json(result.rows[0]);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// =====================
// 🔐 LOGIN (MEJORADO)
// =====================
app.post("/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: "Email y password requeridos" });
    }

    const result = await pool.query(
      `
      SELECT 
        au.id,
        au.email,
        au.password_hash,
        p.name,
        p.username,
        p.avatar_color
      FROM auth_users au
      LEFT JOIN profiles p ON p.auth_user_id = au.id
      WHERE au.email = $1
      `,
      [email]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ error: "Usuario no encontrado" });
    }

    const user = result.rows[0];

    const validPassword = await bcrypt.compare(
      password,
      user.password_hash
    );

    if (!validPassword) {
      return res.status(401).json({ error: "Contraseña incorrecta" });
    }

    const token = jwt.sign(
      { userId: user.id },
      process.env.JWT_SECRET,
      { expiresIn: "1d" }
    );

    res.json({
      token,
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        username: user.username,
        avatar_color: user.avatar_color,
      },
    });

  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});
// =====================
// 📋 LISTAR REQUESTS
// =====================
app.get("/requests", authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT * FROM media_requests ORDER BY created_at DESC`
    );
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// =====================
// ➕ CREAR REQUEST
// =====================
app.post("/requests", authenticateToken, async (req, res) => {
  try {
    const { title, description, type, due_date } = req.body;
    const created_by = req.user.userId;

    if (!title || !type || !due_date) {
      return res.status(400).json({
        error: "Faltan campos obligatorios",
      });
    }

    const result = await pool.query(
      `INSERT INTO media_requests 
      (title, description, type, due_date, created_by)
      VALUES ($1, $2, $3, $4, $5)
      RETURNING *`,
      [title, description, type, due_date, created_by]
    );

    res.json(result.rows[0]);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// =====================
// 👤 ASIGNAR RESPONSABLE
// =====================
app.put("/requests/:id/assign", authenticateToken, async (req, res) => {
  try {
    const { assignee_id } = req.body;
    const { id } = req.params;

    const result = await pool.query(
      `UPDATE media_requests
       SET assignee_id = $1,
           status = 'in_progress',
           updated_at = now()
       WHERE id = $2
       RETURNING *`,
      [assignee_id, id]
    );

    res.json(result.rows[0]);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// =====================
// 🔄 CAMBIAR ESTADO
// =====================
app.put("/requests/:id/status", authenticateToken, async (req, res) => {
  try {
    const { status } = req.body;
    const { id } = req.params;

    const result = await pool.query(
      `UPDATE media_requests
       SET status = $1,
           updated_at = now()
       WHERE id = $2
       RETURNING *`,
      [status, id]
    );

    res.json(result.rows[0]);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// =====================
// ✅ FINALIZAR REQUEST
// =====================
app.put("/requests/:id/finish", authenticateToken, async (req, res) => {
  try {
    const { finish_link, finish_comment } = req.body;
    const { id } = req.params;

    const result = await pool.query(
      `UPDATE media_requests
       SET status = 'finished',
           finish_link = $1,
           finish_comment = $2,
           finished_at = now(),
           updated_at = now()
       WHERE id = $3
       RETURNING *`,
      [finish_link, finish_comment, id]
    );

    res.json(result.rows[0]);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// =====================
// ❌ ERRORES GLOBALES
// =====================
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({
    error: "Error interno del servidor",
  });
});

// =====================
// 🚀 SERVER
// =====================
const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`Servidor corriendo en puerto ${PORT}`);
});
// =============================
// AUTH LOGIN
// =============================
app.post("/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    const result = await pool.query(
      `SELECT * FROM auth_users WHERE email = $1`,
      [email]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ error: "Usuario no encontrado" });
    }

    const user = result.rows[0];

    const validPassword = await bcrypt.compare(
      password,
      user.password_hash
    );

    if (!validPassword) {
      return res.status(401).json({ error: "Contraseña incorrecta" });
    }

    const token = jwt.sign(
      { userId: user.id },
      process.env.JWT_SECRET,
      { expiresIn: "1d" }
    );

    res.json({
      token,
      user: {
        id: user.id,
        email: user.email,
      },
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});


// =============================
// DEBUG
// =============================
app.get("/debug", (req, res) => {
  res.send("VERSION NUEVA DEBUG");
});


// =============================
// 🚀 SERVIDOR (SIEMPRE AL FINAL)
// =============================
const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`Servidor corriendo en puerto ${PORT}`);
});

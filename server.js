import express from "express";
import pkg from "pg";

const { Pool } = pkg;

const app = express();
app.use(express.json());

// =====================
// 🔌 CONEXIÓN DB
// =====================
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false,
  },
});

// =====================
// 🏠 ROOT
// =====================
app.get("/", (req, res) => {
  res.send("API KAS funcionando 🚀");
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
// 📋 LISTAR SOLICITUDES
// =====================
app.get("/requests", async (req, res) => {
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
// ➕ CREAR SOLICITUD
// =====================
app.post("/requests", async (req, res) => {
  try {
    const { title, description, type, due_date, created_by } = req.body;

    // Validación básica
    if (!title || !type || !due_date || !created_by) {
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
// ❌ MANEJO GLOBAL DE ERRORES
// =====================
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).send("Error interno del servidor");
});

// =====================
// 🚀 SERVIDOR
// =====================
const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`Servidor corriendo en puerto ${PORT}`);
});

import express from "express";
import pkg from "pg";

const { Pool } = pkg;

const app = express();
app.use(express.json());

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false,
  },
});

app.get("/", (req, res) => {
  res.send("API KAS funcionando 🚀");
});

app.get("/test-db", async (req, res) => {
  try {
    const result = await pool.query("SELECT NOW()");
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`Servidor corriendo en puerto ${PORT}`);
});
app.post("/requests", async (req, res) => {
  try {
    const { title, description, type, due_date, created_by } = req.body;

    const result = await pool.query(
      `INSERT INTO media_requests (title, description, type, due_date, created_by)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING *`,
      [title, description, type, due_date, created_by]
    );

    res.json(result.rows[0]);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

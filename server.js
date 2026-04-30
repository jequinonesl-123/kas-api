import cors from "cors";
import express from "express";
import pkg from "pg";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";

const { Pool } = pkg;

const app = express();
app.use(express.json());
app.use(cors());

// =====================
// 🔐 CONFIG
// =====================
const JWT_SECRET = process.env.JWT_SECRET || "super_secret_key";

// =====================
// 🔌 DB
// =====================
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

// =====================
// 🔒 MIDDLEWARE AUTH
// =====================
const authMiddleware = (req, res, next) => {
  const auth = req.headers.authorization;

  if (!auth) {
    return res.status(401).json({ error: "No autorizado" });
  }

  const token = auth.split(" ")[1];

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch {
    res.status(401).json({ error: "Token inválido" });
  }
};

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
// 🔐 REGISTER
// =====================
app.post("/auth/register", async (req, res) => {
  try {
    const { email, password, name, username } = req.body;

    if (!email || !password || !name || !username) {
      return res.status(400).json({ error: "Faltan campos" });
    }

    const hashed = await bcrypt.hash(password, 10);

    const authUser = await pool.query(
      `INSERT INTO auth_users (email, password_hash)
       VALUES ($1, $2)
       RETURNING *`,
      [email, hashed]
    );

    const profile = await pool.query(
      `INSERT INTO profiles (id, name, username)
       VALUES ($1, $2, $3)
       RETURNING *`,
      [authUser.rows[0].id, name, username]
    );

    res.json({
      user: profile.rows[0],
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// =====================
// 🔑 LOGIN
// =====================
app.post("/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await pool.query(
      `SELECT * FROM auth_users WHERE email = $1`,
      [email]
    );

    if (user.rows.length === 0) {
      return res.status(400).json({ error: "Usuario no existe" });
    }

    const valid = await bcrypt.compare(
      password,
      user.rows[0].password_hash
    );

    if (!valid) {
      return res.status(400).json({ error: "Contraseña incorrecta" });
    }

    const token = jwt.sign(
      { user_id: user.rows[0].id },
      JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.json({
      token,
      user: {
        id: user.rows[0].id,
        email: user.rows[0].email,
      },
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// =====================
// 📋 LISTAR REQUESTS
// =====================
app.get("/requests", authMiddleware, async (req, res) => {
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
app.post("/requests", authMiddleware, async (req, res) => {
  const client = await pool.connect();
  try {
    const { title, description, type, due_date } = req.body;
    const created_by = req.user.user_id;

    if (!title || !type || !due_date) {
      return res.status(400).json({ error: "Faltan campos obligatorios" });
    }

    await client.query("BEGIN");

    const result = await client.query(
      `INSERT INTO media_requests 
      (title, description, type, due_date, created_by)
      VALUES ($1, $2, $3, $4, $5)
      RETURNING *`,
      [title, description, type, due_date, created_by]
    );

    await client.query(
      `INSERT INTO request_history (request_id, user_id, action, detail)
       VALUES ($1, $2, 'created', 'Solicitud creada')`,
      [result.rows[0].id, created_by]
    );

    await client.query("COMMIT");

    res.json(result.rows[0]);
  } catch (error) {
    await client.query("ROLLBACK");
    res.status(500).json({ error: error.message });
  } finally {
    client.release();
  }
});

// =====================
// 🔁 ASIGNAR
// =====================
app.put("/requests/:id/assign", authMiddleware, async (req, res) => {
  const client = await pool.connect();
  try {
    const { assignee_id, reason } = req.body;
    const changed_by = req.user.user_id;
    const { id } = req.params;

    await client.query("BEGIN");

    const current = await client.query(
      `SELECT assignee_id FROM media_requests WHERE id = $1`,
      [id]
    );

    const previous = current.rows[0]?.assignee_id || null;

    const updated = await client.query(
      `UPDATE media_requests
       SET assignee_id = $1,
           status = 'in_progress',
           updated_at = now()
       WHERE id = $2
       RETURNING *`,
      [assignee_id, id]
    );

    await client.query(
      `INSERT INTO assignment_history
       (request_id, previous_assignee_id, new_assignee_id, changed_by, reason)
       VALUES ($1, $2, $3, $4, $5)`,
      [id, previous, assignee_id, changed_by, reason]
    );

    await client.query(
      `INSERT INTO request_history (request_id, user_id, action, reason)
       VALUES ($1, $2, 'assigned', $3)`,
      [id, changed_by, reason]
    );

    await client.query("COMMIT");

    res.json(updated.rows[0]);
  } catch (error) {
    await client.query("ROLLBACK");
    res.status(500).json({ error: error.message });
  } finally {
    client.release();
  }
});

// =====================
// 🔄 CAMBIAR ESTADO
// =====================
app.put("/requests/:id/status", authMiddleware, async (req, res) => {
  const client = await pool.connect();
  try {
    const { status } = req.body;
    const user_id = req.user.user_id;
    const { id } = req.params;

    await client.query("BEGIN");

    const result = await client.query(
      `UPDATE media_requests
       SET status = $1, updated_at = now()
       WHERE id = $2
       RETURNING *`,
      [status, id]
    );

    await client.query(
      `INSERT INTO request_history (request_id, user_id, action, detail)
       VALUES ($1, $2, 'status_changed', $3)`,
      [id, user_id, `Estado cambiado a ${status}`]
    );

    await client.query("COMMIT");

    res.json(result.rows[0]);
  } catch (error) {
    await client.query("ROLLBACK");
    res.status(500).json({ error: error.message });
  } finally {
    client.release();
  }
});

// =====================
// 📤 SUBMIT REVIEW
// =====================
app.put("/requests/:id/submit-review", authMiddleware, async (req, res) => {
  const client = await pool.connect();
  try {
    const { link, comment } = req.body;
    const submitted_by = req.user.user_id;
    const { id } = req.params;

    await client.query("BEGIN");

    const review = await client.query(
      `INSERT INTO review_rounds
       (request_id, submitted_by, comment, link, submitted_at)
       VALUES ($1, $2, $3, $4, now())
       RETURNING *`,
      [id, submitted_by, comment, link]
    );

    await client.query(
      `UPDATE media_requests
       SET status = 'in_review',
           pending_review_id = $1
       WHERE id = $2`,
      [review.rows[0].id, id]
    );

    await client.query("COMMIT");

    res.json(review.rows[0]);
  } catch (error) {
    await client.query("ROLLBACK");
    res.status(500).json({ error: error.message });
  } finally {
    client.release();
  }
});

// =====================
// ✅ DECISIÓN
// =====================
app.put("/reviews/:id/decision", authMiddleware, async (req, res) => {
  const client = await pool.connect();
  try {
    const { decision, feedback } = req.body;
    const decided_by = req.user.user_id;
    const { id } = req.params;

    await client.query("BEGIN");

    const review = await client.query(
      `UPDATE review_rounds
       SET decision = $1,
           feedback = $2,
           decided_by = $3,
           decided_at = now()
       WHERE id = $4
       RETURNING *`,
      [decision, feedback, decided_by, id]
    );

    const request_id = review.rows[0].request_id;

    if (decision === "approved") {
      await client.query(
        `UPDATE media_requests
         SET status = 'finished',
             finished_at = now()
         WHERE id = $1`,
        [request_id]
      );
    } else {
      await client.query(
        `UPDATE media_requests
         SET status = 'changes_requested',
             last_feedback = $1
         WHERE id = $2`,
        [feedback, request_id]
      );
    }

    await client.query("COMMIT");

    res.json(review.rows[0]);
  } catch (error) {
    await client.query("ROLLBACK");
    res.status(500).json({ error: error.message });
  } finally {
    client.release();
  }
});

// =====================
// ❌ ERRORES
// =====================
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).send("Error interno del servidor");
});

// =====================
// 🚀 SERVER
// =====================
const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`Servidor corriendo en puerto ${PORT}`);
});

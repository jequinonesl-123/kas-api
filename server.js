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
  ssl: { rejectUnauthorized: false },
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
  const client = await pool.connect();
  try {
    const { title, description, type, due_date, created_by } = req.body;

    if (!title || !type || !due_date || !created_by) {
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
// 🔁 ASIGNAR RESPONSABLE + HISTORIAL
// =====================
app.put("/requests/:id/assign", async (req, res) => {
  const client = await pool.connect();
  try {
    const { assignee_id, changed_by, reason } = req.body;
    const { id } = req.params;

    if (!assignee_id || !changed_by || !reason) {
      return res.status(400).json({ error: "Faltan datos obligatorios" });
    }

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
app.put("/requests/:id/status", async (req, res) => {
  const client = await pool.connect();
  try {
    const { status, user_id } = req.body;
    const { id } = req.params;

    if (!status || !user_id) {
      return res.status(400).json({ error: "Faltan datos" });
    }

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
// 📤 ENVIAR A REVISIÓN
// =====================
app.put("/requests/:id/submit-review", async (req, res) => {
  const client = await pool.connect();
  try {
    const { submitted_by, link, comment } = req.body;
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
// ✅ APROBAR / DEVOLVER
// =====================
app.put("/reviews/:id/decision", async (req, res) => {
  const client = await pool.connect();
  try {
    const { decision, feedback, decided_by } = req.body;
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
// 🚀 SERVIDOR
// =====================
const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`Servidor corriendo en puerto ${PORT}`);
});

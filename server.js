import express from "express";
import cors from "cors";
import pkg from "pg";
import dotenv from "dotenv";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";

dotenv.config();

const { Pool } = pkg;

const app = express();

app.use(cors());
app.use(express.json());

// ======================================================
// DATABASE
// ======================================================

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false,
  },
});

// ======================================================
// TEST
// ======================================================

app.get("/", (req, res) => {
  res.send("VERSION NUEVA");
});

// ======================================================
// DEBUG
// ======================================================

app.get("/debug", async (req, res) => {
  try {

    const users = await pool.query(`
      SELECT
        p.id,
        p.name,
        p.username,
        p.avatar_color,
        p.auth_user_id,
        a.email
      FROM profiles p
      LEFT JOIN auth_users a
      ON p.auth_user_id = a.id
    `);

    res.json(users.rows);

  } catch (error) {

    res.status(500).json({
      error: error.message,
    });

  }
});

// ======================================================
// AUTH MIDDLEWARE
// ======================================================

function authenticateToken(req, res, next) {

  const authHeader = req.headers["authorization"];

  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {

    return res.status(401).json({
      error: "Token requerido",
    });

  }

  jwt.verify(
    token,
    process.env.JWT_SECRET,
    (err, user) => {

      if (err) {

        return res.status(403).json({
          error: "Token inválido",
        });

      }

      req.user = user;

      next();
    }
  );
}

// ======================================================
// REGISTER
// ======================================================

app.post("/auth/register", async (req, res) => {

  try {

    const {
      email,
      password,
    } = req.body;

    if (!email || !password) {

      return res.status(400).json({
        error: "Email y contraseña requeridos",
      });

    }

    // VALIDAR DUPLICADO
    const existing = await pool.query(
      `
      SELECT * FROM auth_users
      WHERE email = $1
      `,
      [email]
    );

    if (existing.rows.length > 0) {

      return res.status(400).json({
        error: "El usuario ya existe",
      });

    }

    // HASH PASSWORD
    const password_hash = await bcrypt.hash(password, 10);

    // INSERT USER
    const result = await pool.query(
      `
      INSERT INTO auth_users (
        email,
        password_hash,
        created_at
      )
      VALUES (
        $1,
        $2,
        NOW()
      )
      RETURNING id, email
      `,
      [
        email,
        password_hash,
      ]
    );

    res.json(result.rows[0]);

  } catch (error) {

    console.error(error);

    res.status(500).json({
      error: error.message,
    });

  }

});

// ======================================================
// LOGIN
// ======================================================

app.post("/auth/login", async (req, res) => {

  try {

    const {
      email,
      password,
    } = req.body;

    const result = await pool.query(
      `
      SELECT
        a.id,
        a.email,
        a.password_hash,
        p.name,
        p.username,
        p.avatar_color,
        r.role
      FROM auth_users a
      LEFT JOIN profiles p
        ON p.auth_user_id = a.id
      LEFT JOIN user_roles r
        ON r.user_id = p.id
      WHERE a.email = $1
      `,
      [email]
    );

    if (result.rows.length === 0) {

      return res.status(401).json({
        error: "Usuario no encontrado",
      });

    }

    const user = result.rows[0];

    const validPassword = await bcrypt.compare(
      password,
      user.password_hash
    );

    if (!validPassword) {

      return res.status(401).json({
        error: "Contraseña incorrecta",
      });

    }

    const token = jwt.sign(
      {
        userId: user.id,
      },
      process.env.JWT_SECRET,
      {
        expiresIn: "1d",
      }
    );

    res.json({
      token,
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        username: user.username,
        avatar_color: user.avatar_color,
        role: user.role || "editor",
      },
    });

  } catch (error) {

    console.error(error);

    res.status(500).json({
      error: error.message,
    });

  }

});

// ======================================================
// ME
// ======================================================

app.get("/me", authenticateToken, async (req, res) => {

  try {

    const result = await pool.query(
      `
      SELECT
        a.id,
        a.email,
        p.name,
        p.username,
        p.avatar_color,
        r.role
      FROM auth_users a
      LEFT JOIN profiles p
        ON p.auth_user_id = a.id
      LEFT JOIN user_roles r
        ON r.user_id = p.id
      WHERE a.id = $1
      `,
      [req.user.userId]
    );

    if (result.rows.length === 0) {

      return res.status(404).json({
        error: "Usuario no encontrado",
      });

    }

    res.json(result.rows[0]);

  } catch (error) {

    res.status(500).json({
      error: error.message,
    });

  }

});

// ======================================================
// USERS
// ======================================================

app.get("/users", authenticateToken, async (req, res) => {

  try {

    const result = await pool.query(`
      SELECT
        p.id,
        p.name,
        p.username,
        p.avatar_color,
        p.created_at,
        a.email,
        r.role
      FROM profiles p
      LEFT JOIN auth_users a
        ON p.auth_user_id = a.id
      LEFT JOIN user_roles r
        ON r.user_id = p.id
      ORDER BY p.created_at ASC
    `);

    res.json(result.rows);

  } catch (error) {

    console.error(error);

    res.status(500).json({
      error: error.message,
    });

  }

});

// ======================================================
// CREATE USER
// ======================================================

app.post("/users", authenticateToken, async (req, res) => {

  try {

    const {
      name,
      username,
      email,
      password,
      role,
      avatar_color,
    } = req.body;

    if (!name || !username || !email || !password) {

      return res.status(400).json({
        error: "Campos obligatorios faltantes",
      });

    }

    // EMAIL EXISTE
    const existingEmail = await pool.query(
      `
      SELECT * FROM auth_users
      WHERE email = $1
      `,
      [email]
    );

    if (existingEmail.rows.length > 0) {

      return res.status(400).json({
        error: "Email ya existe",
      });

    }

    // USERNAME EXISTE
    const existingUsername = await pool.query(
      `
      SELECT * FROM profiles
      WHERE username = $1
      `,
      [username]
    );

    if (existingUsername.rows.length > 0) {

      return res.status(400).json({
        error: "Username ya existe",
      });

    }

    // HASH
    const password_hash = await bcrypt.hash(password, 10);

    // AUTH USER
    const authResult = await pool.query(
      `
      INSERT INTO auth_users (
        email,
        password_hash,
        created_at
      )
      VALUES (
        $1,
        $2,
        NOW()
      )
      RETURNING *
      `,
      [
        email,
        password_hash,
      ]
    );

    const authUser = authResult.rows[0];

    // PROFILE
    const profileResult = await pool.query(
      `
      INSERT INTO profiles (
        name,
        username,
        avatar_color,
        auth_user_id,
        created_at,
        updated_at
      )
      VALUES (
        $1,
        $2,
        $3,
        $4,
        NOW(),
        NOW()
      )
      RETURNING *
      `,
      [
        name,
        username,
        avatar_color || "#0096FA",
        authUser.id,
      ]
    );

    const profile = profileResult.rows[0];

    // ROLE
    await pool.query(
      `
      INSERT INTO user_roles (
        user_id,
        role
      )
      VALUES (
        $1,
        $2
      )
      `,
      [
        profile.id,
        role || "editor",
      ]
    );

    res.json({
      success: true,
      user: profile,
    });

  } catch (error) {

    console.error(error);

    res.status(500).json({
      error: error.message,
    });

  }

});

// ======================================================
// DELETE USER
// ======================================================

app.delete("/users/:id", authenticateToken, async (req, res) => {

  try {

    const { id } = req.params;

    // PROFILE
    const profileResult = await pool.query(
      `
      SELECT *
      FROM profiles
      WHERE id = $1
      `,
      [id]
    );

    if (profileResult.rows.length === 0) {

      return res.status(404).json({
        error: "Usuario no encontrado",
      });

    }

    const profile = profileResult.rows[0];

    // DELETE ROLE
    await pool.query(
      `
      DELETE FROM user_roles
      WHERE user_id = $1
      `,
      [id]
    );

    // DELETE PROFILE
    await pool.query(
      `
      DELETE FROM profiles
      WHERE id = $1
      `,
      [id]
    );

    // DELETE AUTH
    if (profile.auth_user_id) {

      await pool.query(
        `
        DELETE FROM auth_users
        WHERE id = $1
        `,
        [profile.auth_user_id]
      );

    }

    res.json({
      success: true,
    });

  } catch (error) {

    console.error(error);

    res.status(500).json({
      error: error.message,
    });

  }

});

// ======================================================
// UPDATE PASSWORD
// ======================================================

app.put("/users/:id/password", authenticateToken, async (req, res) => {

  try {

    const { id } = req.params;

    const { password } = req.body;

    if (!password) {

      return res.status(400).json({
        error: "Contraseña requerida",
      });

    }

    const profileResult = await pool.query(
      `
      SELECT *
      FROM profiles
      WHERE id = $1
      `,
      [id]
    );

    if (profileResult.rows.length === 0) {

      return res.status(404).json({
        error: "Usuario no encontrado",
      });

    }

    const profile = profileResult.rows[0];

    const password_hash = await bcrypt.hash(password, 10);

    await pool.query(
      `
      UPDATE auth_users
      SET password_hash = $1
      WHERE id = $2
      `,
      [
        password_hash,
        profile.auth_user_id,
      ]
    );

    res.json({
      success: true,
    });

  } catch (error) {

    console.error(error);

    res.status(500).json({
      error: error.message,
    });

  }

});

// ======================================================
// GET REQUESTS
// ======================================================

app.get("/requests", authenticateToken, async (req, res) => {

  try {

    const result = await pool.query(`
      SELECT *
      FROM media_requests
      ORDER BY created_at DESC
    `);

    res.json(result.rows);

  } catch (error) {

    console.error(error);

    res.status(500).json({
      error: error.message,
    });

  }

});

// ======================================================
// CREATE REQUEST
// ======================================================

app.post("/requests", authenticateToken, async (req, res) => {

  try {

    console.log("REQUEST BODY:", req.body);

    const {
      title,
      description,
      type,
      due_date,
      assignee_id,
    } = req.body;

    if (!title) {

      return res.status(400).json({
        error: "El título es obligatorio",
      });

    }

    if (!type) {

      return res.status(400).json({
        error: "El tipo es obligatorio",
      });

    }

    if (!due_date) {

      return res.status(400).json({
        error: "La fecha límite es obligatoria",
      });

    }

    const result = await pool.query(
      `
      INSERT INTO media_requests (
        title,
        description,
        type,
        status,
        due_date,
        created_by,
        assignee_id,
        created_at,
        updated_at
      )
      VALUES (
        $1,
        $2,
        $3,
        'pending',
        $4,
        $5,
        $6,
        NOW(),
        NOW()
      )
      RETURNING *
      `,
      [
        title,
        description || "",
        type,
        due_date,
        req.user.userId,
        assignee_id || null,
      ]
    );

    res.json(result.rows[0]);

  } catch (error) {

    console.error("ERROR CREANDO REQUEST:", error);

    res.status(500).json({
      error: error.message,
    });

  }

});

// ======================================================
// ASSIGN REQUEST
// ======================================================

app.put("/requests/:id/assign", authenticateToken, async (req, res) => {

  try {

    const { id } = req.params;

    const { assignee_id } = req.body;

    const result = await pool.query(
      `
      UPDATE media_requests
      SET assignee_id = $1,
          updated_at = NOW()
      WHERE id = $2
      RETURNING *
      `,
      [
        assignee_id,
        id,
      ]
    );

    res.json(result.rows[0]);

  } catch (error) {

    console.error(error);

    res.status(500).json({
      error: error.message,
    });

  }

});

// ======================================================
// UPDATE STATUS
// ======================================================

app.put("/requests/:id/status", authenticateToken, async (req, res) => {

  try {

    const { id } = req.params;

    const { status } = req.body;

    const result = await pool.query(
      `
      UPDATE media_requests
      SET status = $1,
          updated_at = NOW()
      WHERE id = $2
      RETURNING *
      `,
      [
        status,
        id,
      ]
    );

    res.json(result.rows[0]);

  } catch (error) {

    console.error(error);

    res.status(500).json({
      error: error.message,
    });

  }

});

// ======================================================
// FINISH REQUEST
// ======================================================

app.put("/requests/:id/finish", authenticateToken, async (req, res) => {

  try {

    const { id } = req.params;

    const {
      finish_link,
      finish_comment,
    } = req.body;

    const result = await pool.query(
      `
      UPDATE media_requests
      SET
        finish_link = $1,
        finish_comment = $2,
        finished_at = NOW(),
        status = 'review',
        updated_at = NOW()
      WHERE id = $3
      RETURNING *
      `,
      [
        finish_link,
        finish_comment,
        id,
      ]
    );

    res.json(result.rows[0]);

  } catch (error) {

    console.error(error);

    res.status(500).json({
      error: error.message,
    });

  }

});

// ======================================================
// START SERVER
// ======================================================

const PORT = process.env.PORT || 10000;

app.listen(PORT, () => {

  console.log(`Servidor corriendo en puerto ${PORT}`);

});

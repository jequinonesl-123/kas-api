import express from "express";
import cors from "cors";
import pkg from "pg";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";

dotenv.config();

const { Pool } = pkg;

const app = express();

app.use(cors());
app.use(express.json());

/* =====================================================
   DATABASE
===================================================== */

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false,
  },
});

/* =====================================================
   TEST
===================================================== */

app.get("/", (req, res) => {
  res.send("VERSION NUEVA");
});

/* =====================================================
   AUTH MIDDLEWARE
===================================================== */

function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];

  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).json({
      error: "Token requerido",
    });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({
        error: "Token inválido",
      });
    }

    req.user = user;

    next();
  });
}

/* =====================================================
   REGISTER
===================================================== */

app.post("/auth/register", async (req, res) => {
  try {
    const {
      email,
      password,
      name,
      username,
      role,
      avatar_color,
    } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        error: "Email y contraseña son requeridos",
      });
    }

    // verificar si ya existe
    const existingUser = await pool.query(
      `SELECT * FROM auth_users WHERE email = $1`,
      [email]
    );

    if (existingUser.rows.length > 0) {
      return res.status(400).json({
        error: "El usuario ya existe",
      });
    }

    // hash password
    const passwordHash = await bcrypt.hash(password, 10);

    // crear usuario auth
    const authResult = await pool.query(
      `
      INSERT INTO auth_users (
        email,
        password_hash,
        created_at
      )
      VALUES ($1, $2, NOW())
      RETURNING *
      `,
      [email, passwordHash]
    );

    const authUser = authResult.rows[0];

    // crear perfil
    const profileResult = await pool.query(
      `
      INSERT INTO profiles (
        id,
        name,
        username,
        avatar_color,
        role,
        auth_user_id,
        created_at,
        updated_at
      )
      VALUES (
        gen_random_uuid(),
        $1,
        $2,
        $3,
        $4,
        $5,
        NOW(),
        NOW()
      )
      RETURNING *
      `,
      [
        name || email,
        username || email.split("@")[0],
        avatar_color || "#0096FA",
        role || "editor",
        authUser.id,
      ]
    );

    res.status(201).json({
      message: "Usuario creado correctamente",
      auth_user: authUser,
      profile: profileResult.rows[0],
    });
  } catch (error) {
    console.error("REGISTER ERROR:", error);

    res.status(500).json({
      error: error.message,
    });
  }
});

/* =====================================================
   LOGIN
===================================================== */

app.post("/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    const result = await pool.query(
      `
      SELECT
        au.id,
        au.email,
        au.password_hash,
        p.name,
        p.username,
        p.role,
        p.avatar_color
      FROM auth_users au
      LEFT JOIN profiles p
        ON p.auth_user_id = au.id
      WHERE au.email = $1
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
        email: user.email,
        role: user.role || "editor",
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
        role: user.role,
        avatar_color: user.avatar_color,
      },
    });
  } catch (error) {
    console.error("LOGIN ERROR:", error);

    res.status(500).json({
      error: error.message,
    });
  }
});

/* =====================================================
   ME
===================================================== */

app.get("/me", authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `
      SELECT
        au.id,
        au.email,
        p.name,
        p.username,
        p.role,
        p.avatar_color
      FROM auth_users au
      LEFT JOIN profiles p
        ON p.auth_user_id = au.id
      WHERE au.id = $1
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
    console.error("ME ERROR:", error);

    res.status(500).json({
      error: error.message,
    });
  }
});

/* =====================================================
   USERS
===================================================== */

app.get("/users", authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT
        p.id,
        p.name,
        p.username,
        p.role,
        p.avatar_color,
        au.email
      FROM profiles p
      LEFT JOIN auth_users au
        ON au.id = p.auth_user_id
      ORDER BY p.created_at ASC
    `);

    res.json(result.rows);
  } catch (error) {
    console.error("USERS ERROR:", error);

    res.status(500).json({
      error: error.message,
    });
  }
});

/* =====================================================
   CREATE REQUEST
===================================================== */

app.post("/requests", authenticateToken, async (req, res) => {
  try {
    const {
      title,
      description,
      type,
      due_date,
      assignee_id,
      assigned_to,
    } = req.body;

    const finalAssignee =
      assignee_id ||
      assigned_to ||
      null;

    // validaciones
    if (!title || !description || !type) {
      return res.status(400).json({
        error: "Faltan campos requeridos",
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
        description,
        type,
        due_date || null,
        req.user.userId,
        finalAssignee,
      ]
    );

    res.status(201).json(result.rows[0]);

  } catch (error) {
    console.error("ERROR CREANDO REQUEST:", error);

    res.status(500).json({
      error: error.message,
    });
  }
});

/* =====================================================
   GET REQUESTS
===================================================== */

app.get("/requests", authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT *
      FROM media_requests
      ORDER BY created_at DESC
    `);

    res.json(result.rows);
  } catch (error) {
    console.error("GET REQUESTS ERROR:", error);

    res.status(500).json({
      error: error.message,
    });
  }
});

/* =====================================================
   ASSIGN REQUEST
===================================================== */

app.put(
  "/requests/:id/assign",
  authenticateToken,
  async (req, res) => {
    try {
      const { assignee_id } = req.body;

      const result = await pool.query(
        `
        UPDATE media_requests
        SET
          assignee_id = $1,
          updated_at = NOW()
        WHERE id = $2
        RETURNING *
        `,
        [assignee_id, req.params.id]
      );

      res.json(result.rows[0]);
    } catch (error) {
      console.error("ASSIGN ERROR:", error);

      res.status(500).json({
        error: error.message,
      });
    }
  }
);

/* =====================================================
   UPDATE STATUS
===================================================== */

app.put(
  "/requests/:id/status",
  authenticateToken,
  async (req, res) => {
    try {
      const { status } = req.body;

      const result = await pool.query(
        `
        UPDATE media_requests
        SET
          status = $1,
          updated_at = NOW()
        WHERE id = $2
        RETURNING *
        `,
        [status, req.params.id]
      );

      res.json(result.rows[0]);
    } catch (error) {
      console.error("STATUS ERROR:", error);

      res.status(500).json({
        error: error.message,
      });
    }
  }
);

/* =====================================================
   FINISH REQUEST
===================================================== */

app.put(
  "/requests/:id/finish",
  authenticateToken,
  async (req, res) => {
    try {
      const {
        finish_comment,
        finished_link,
      } = req.body;

      const result = await pool.query(
        `
        UPDATE media_requests
        SET
          status = 'finished',
          finish_comment = $1,
          finished_link = $2,
          finished_at = NOW(),
          updated_at = NOW()
        WHERE id = $3
        RETURNING *
        `,
        [
          finish_comment || null,
          finished_link || null,
          req.params.id,
        ]
      );

      res.json(result.rows[0]);
    } catch (error) {
      console.error("FINISH ERROR:", error);

      res.status(500).json({
        error: error.message,
      });
    }
  }
);

/* =====================================================
   DELETE USER
===================================================== */

app.delete(
  "/users/:id",
  authenticateToken,
  async (req, res) => {
    try {
      const profileResult = await pool.query(
        `
        SELECT *
        FROM profiles
        WHERE id = $1
        `,
        [req.params.id]
      );

      if (profileResult.rows.length === 0) {
        return res.status(404).json({
          error: "Usuario no encontrado",
        });
      }

      const profile = profileResult.rows[0];

      // eliminar profile
      await pool.query(
        `
        DELETE FROM profiles
        WHERE id = $1
        `,
        [req.params.id]
      );

      // eliminar auth user
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
      console.error("DELETE USER ERROR:", error);

      res.status(500).json({
        error: error.message,
      });
    }
  }
);

/* =====================================================
   CHANGE PASSWORD
===================================================== */

app.put(
  "/users/:id/password",
  authenticateToken,
  async (req, res) => {
    try {
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
        [req.params.id]
      );

      if (profileResult.rows.length === 0) {
        return res.status(404).json({
          error: "Usuario no encontrado",
        });
      }

      const profile = profileResult.rows[0];

      const hash = await bcrypt.hash(password, 10);

      await pool.query(
        `
        UPDATE auth_users
        SET password_hash = $1
        WHERE id = $2
        `,
        [hash, profile.auth_user_id]
      );

      res.json({
        success: true,
      });
    } catch (error) {
      console.error("CHANGE PASSWORD ERROR:", error);

      res.status(500).json({
        error: error.message,
      });
    }
  }
);

/* =====================================================
   START SERVER
===================================================== */

const PORT = process.env.PORT || 10000;

app.listen(PORT, () => {
  console.log(`Servidor corriendo en puerto ${PORT}`);
});

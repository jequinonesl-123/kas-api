import express from "express";
import pkg from "pg";
import cors from "cors";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";

dotenv.config();

const { Pool } = pkg;

const app = express();

// =====================
// 🔧 MIDDLEWARES
// =====================
app.use(cors());
app.use(express.json());

// =====================
// 🔌 DATABASE
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
  try {
    const authHeader = req.headers["authorization"];

    if (!authHeader) {
      return res.status(401).json({
        error: "Token requerido",
      });
    }

    const token = authHeader.split(" ")[1];

    if (!token) {
      return res.status(401).json({
        error: "Token inválido",
      });
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
      if (err) {
        return res.status(403).json({
          error: "Token expirado o inválido",
        });
      }

      req.user = decoded;

      next();
    });

  } catch (error) {
    return res.status(500).json({
      error: error.message,
    });
  }
};

// =====================
// 🏠 ROOT
// =====================
app.get("/", (req, res) => {
  res.send("KAS API FUNCIONANDO 🚀");
});

// =====================
// 🧪 DEBUG
// =====================
app.get("/debug", (req, res) => {
  res.json({
    message: "DEBUG OK",
    env: {
      hasDatabaseUrl: !!process.env.DATABASE_URL,
      hasJwtSecret: !!process.env.JWT_SECRET,
    },
  });
});

// =====================
// 🧪 TEST DATABASE
// =====================
app.get("/test-db", async (req, res) => {
  try {

    const result = await pool.query("SELECT NOW()");

    res.json({
      success: true,
      database_time: result.rows[0],
    });

  } catch (error) {

    res.status(500).json({
      success: false,
      error: error.message,
    });
  }
});

// =====================
// 🔐 REGISTER
// =====================
app.post("/auth/register", async (req, res) => {
  try {

    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        error: "Email y password requeridos",
      });
    }

    const existingUser = await pool.query(
      `
      SELECT id
      FROM auth_users
      WHERE email = $1
      `,
      [email]
    );

    if (existingUser.rows.length > 0) {
      return res.status(400).json({
        error: "El usuario ya existe",
      });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const authResult = await pool.query(
      `
      INSERT INTO auth_users (
        email,
        password_hash
      )
      VALUES ($1, $2)
      RETURNING id, email
      `,
      [email, hashedPassword]
    );

    const authUser = authResult.rows[0];

    const profileResult = await pool.query(
      `
      INSERT INTO profiles (
        name,
        username,
        avatar_color,
        auth_user_id
      )
      VALUES (
        $1,
        $2,
        '#0096FA',
        $3
      )
      RETURNING *
      `,
      [
        email.split("@")[0],
        email.split("@")[0],
        authUser.id,
      ]
    );

    const profile = profileResult.rows[0];

    await pool.query(
      `
      INSERT INTO user_roles (
        id,
        user_id,
        role
      )
      VALUES (
        gen_random_uuid(),
        $1,
        'designer'
      )
      `,
      [profile.id]
    );

    const token = jwt.sign(
      {
        userId: authUser.id,
      },
      process.env.JWT_SECRET,
      {
        expiresIn: "1d",
      }
    );

    res.json({
      success: true,
      token,
      user: {
        id: authUser.id,
        email: authUser.email,
      },
    });

  } catch (error) {

    console.error(error);

    res.status(500).json({
      error: error.message,
    });
  }
});

// =====================
// 🔐 LOGIN
// =====================
app.post("/auth/login", async (req, res) => {
  try {

    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        error: "Email y password requeridos",
      });
    }

    const result = await pool.query(
      `
      SELECT
        au.id,
        au.email,
        au.password_hash,
        p.id as profile_id,
        p.name,
        p.username,
        p.avatar_color,
        ur.role
      FROM auth_users au
      LEFT JOIN profiles p
        ON p.auth_user_id = au.id
      LEFT JOIN user_roles ur
        ON ur.user_id = p.id
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
      },
      process.env.JWT_SECRET,
      {
        expiresIn: "1d",
      }
    );

    res.json({
      success: true,
      token,
      user: {
        id: user.id,
        profile_id: user.profile_id,
        email: user.email,
        name: user.name,
        username: user.username,
        avatar_color: user.avatar_color,
        role: user.role,
      },
    });

  } catch (error) {

    console.error(error);

    res.status(500).json({
      error: error.message,
    });
  }
});

// =====================
// 👤 CURRENT USER
// =====================
app.get("/me", authenticateToken, async (req, res) => {
  try {

    const result = await pool.query(
      `
      SELECT
        au.id,
        au.email,
        p.id as profile_id,
        p.name,
        p.username,
        p.avatar_color,
        ur.role
      FROM auth_users au
      LEFT JOIN profiles p
        ON p.auth_user_id = au.id
      LEFT JOIN user_roles ur
        ON ur.user_id = p.id
      WHERE au.id = $1
      `,
      [req.user.userId]
    );

    res.json(result.rows[0]);

  } catch (error) {

    res.status(500).json({
      error: error.message,
    });
  }
});

// =============================
// 👥 LISTAR USUARIOS
// =============================
app.get("/users", authenticateToken, async (req, res) => {
  try {

    const result = await pool.query(`
      SELECT
        p.id,
        p.name,
        p.username,
        p.avatar_color,
        p.auth_user_id,
        p.created_at,
        p.updated_at,
        au.email,
        ur.role
      FROM profiles p
      LEFT JOIN auth_users au
        ON au.id = p.auth_user_id
      LEFT JOIN user_roles ur
        ON ur.user_id = p.id
      ORDER BY p.created_at DESC
    `);

    res.json(result.rows);

  } catch (error) {

    res.status(500).json({
      error: error.message,
    });
  }
});

// =============================
// ➕ CREAR USUARIO
// =============================
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

    if (!name || !username || !email || !password || !role) {
      return res.status(400).json({
        error: "Faltan campos obligatorios",
      });
    }

    const existingEmail = await pool.query(
      `
      SELECT id
      FROM auth_users
      WHERE email = $1
      `,
      [email]
    );

    if (existingEmail.rows.length > 0) {
      return res.status(400).json({
        error: "El email ya existe",
      });
    }

    const existingUsername = await pool.query(
      `
      SELECT id
      FROM profiles
      WHERE username = $1
      `,
      [username]
    );

    if (existingUsername.rows.length > 0) {
      return res.status(400).json({
        error: "El username ya existe",
      });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const authResult = await pool.query(
      `
      INSERT INTO auth_users (
        email,
        password_hash
      )
      VALUES ($1, $2)
      RETURNING *
      `,
      [email, hashedPassword]
    );

    const authUser = authResult.rows[0];

    const profileResult = await pool.query(
      `
      INSERT INTO profiles (
        name,
        username,
        avatar_color,
        auth_user_id
      )
      VALUES ($1, $2, $3, $4)
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

    await pool.query(
      `
      INSERT INTO user_roles (
        id,
        user_id,
        role
      )
      VALUES (
        gen_random_uuid(),
        $1,
        $2
      )
      `,
      [profile.id, role]
    );

    res.json({
      success: true,
      user: {
        id: profile.id,
        name: profile.name,
        username: profile.username,
        email,
        role,
      },
    });

  } catch (error) {

    console.error(error);

    res.status(500).json({
      error: error.message,
    });
  }
});

// =============================
// ❌ ELIMINAR USUARIO
// =============================
app.delete("/users/:id", authenticateToken, async (req, res) => {
  try {

    const { id } = req.params;

    const profileResult = await pool.query(
      `
      SELECT auth_user_id
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

    const authUserId = profileResult.rows[0].auth_user_id;

    await pool.query(`
      DELETE FROM user_roles
      WHERE user_id = '${id}'
    `);

    await pool.query(`
      DELETE FROM profiles
      WHERE id = '${id}'
    `);

    await pool.query(`
      DELETE FROM auth_users
      WHERE id = '${authUserId}'
    `);

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

// =============================
// 🔐 CAMBIAR PASSWORD
// =============================
app.put("/users/:id/password", authenticateToken, async (req, res) => {
  try {

    const { id } = req.params;
    const { password } = req.body;

    if (!password) {
      return res.status(400).json({
        error: "Password requerido",
      });
    }

    const profileResult = await pool.query(
      `
      SELECT auth_user_id
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

    const authUserId = profileResult.rows[0].auth_user_id;

    const hashedPassword = await bcrypt.hash(password, 10);

    await pool.query(
      `
      UPDATE auth_users
      SET password_hash = $1
      WHERE id = $2
      `,
      [
        hashedPassword,
        authUserId,
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

// =====================
// 📋 GET REQUESTS
// =====================
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

// =====================
// ➕ CREATE REQUEST
// =====================
app.post("/requests", authenticateToken, async (req, res) => {
  try {

    const {
      title,
      description,
      type,
      due_date,
      assignee_id,
    } = req.body;

    // =====================
    // VALIDAR CAMPOS
    // =====================
    if (!title || !type || !due_date) {
      return res.status(400).json({
        error: "Campos obligatorios faltantes",
      });
    }

    // =====================
    // VALIDAR TIPOS
    // =====================
    const allowedTypes = [
      "image",
      "video",
      "reel",
      "story",
      "banner",
      "social",
      "sermon",
      "announcement",
    ];

    if (!allowedTypes.includes(type)) {
      return res.status(400).json({
        error: `Tipo inválido: ${type}`,
      });
    }

    // =====================
    // OBTENER PROFILE ID
    // =====================
    const profileResult = await pool.query(
      `
      SELECT id
      FROM profiles
      WHERE auth_user_id = $1
      `,
      [req.user.userId]
    );

    if (profileResult.rows.length === 0) {
      return res.status(404).json({
        error: "Perfil del usuario no encontrado",
      });
    }

    // ESTE ES EL ID CORRECTO
    const profileId = profileResult.rows[0].id;

    // =====================
    // INSERT REQUEST
    // =====================
    const result = await pool.query(
      `
      INSERT INTO media_requests (
        title,
        description,
        type,
        due_date,
        created_by,
        assignee_id,
        status,
        created_at,
        updated_at
      )
      VALUES (
        $1,
        $2,
        $3,
        $4,
        $5,
        $6,
        'pending',
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
        profileId, // ✅ ESTE ERA EL ERROR
        assignee_id || null,
      ]
    );

    res.json(result.rows[0]);

  } catch (error) {

    console.error("CREATE REQUEST ERROR:");
    console.error(error);

    res.status(500).json({
      error: error.message,
    });
  }
});

// =====================
// 👤 ASSIGN REQUEST
// =====================
app.put("/requests/:id/assign", authenticateToken, async (req, res) => {
  try {

    const { assignee_id } = req.body;
    const { id } = req.params;

    const result = await pool.query(
      `
      UPDATE media_requests
      SET
        assignee_id = $1,
        status = 'in_progress',
        updated_at = NOW()
      WHERE id = $2
      RETURNING *
      `,
      [assignee_id, id]
    );

    res.json(result.rows[0]);

  } catch (error) {

    console.error(error);

    res.status(500).json({
      error: error.message,
    });
  }
});

// =====================
// 🔄 UPDATE STATUS
// =====================
app.put("/requests/:id/status", authenticateToken, async (req, res) => {
  try {

    const { status } = req.body;
    const { id } = req.params;

    const allowedStatuses = [
      "pending",
      "in_progress",
      "in_review",
      "changes_requested",
      "finished",
    ];

    if (!allowedStatuses.includes(status)) {
      return res.status(400).json({
        error: `Estado inválido: ${status}`,
      });
    }

    const result = await pool.query(
      `
      UPDATE media_requests
      SET
        status = $1,
        updated_at = NOW()
      WHERE id = $2
      RETURNING *
      `,
      [status, id]
    );

    res.json(result.rows[0]);

  } catch (error) {

    console.error(error);

    res.status(500).json({
      error: error.message,
    });
  }
});

// =====================
// ✅ FINISH REQUEST
// =====================
app.put("/requests/:id/finish", authenticateToken, async (req, res) => {
  try {

    const {
      finish_link,
      finish_comment,
    } = req.body;

    const { id } = req.params;

    const result = await pool.query(
      `
      UPDATE media_requests
      SET
        status = 'finished',
        finish_link = $1,
        finish_comment = $2,
        finished_at = NOW(),
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

// =====================
// ❌ GLOBAL ERRORS
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

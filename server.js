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

    // VALIDACIONES
    if (!email || !password) {
      return res.status(400).json({
        error: "Email y password requeridos",
      });
    }

    // VALIDAR SI YA EXISTE
    const existingUser = await pool.query(
      `SELECT id FROM auth_users WHERE email = $1`,
      [email]
    );

    if (existingUser.rows.length > 0) {
      return res.status(400).json({
        error: "El usuario ya existe",
      });
    }

    // HASH PASSWORD
    const hashedPassword = await bcrypt.hash(password, 10);

    // CREAR USUARIO AUTH
    const authResult = await pool.query(
      `
      INSERT INTO auth_users (email, password_hash)
      VALUES ($1, $2)
      RETURNING id, email
      `,
      [email, hashedPassword]
    );

    const authUser = authResult.rows[0];

    // CREAR PROFILE AUTOMÁTICO
    await pool.query(
      `
      INSERT INTO profiles (
        id,
        name,
        username,
        avatar_color,
        auth_user_id
      )
      VALUES (
        gen_random_uuid(),
        $1,
        $2,
        '#0096FA',
        $3
      )
      `,
      [
        email.split("@")[0],
        email.split("@")[0],
        authUser.id,
      ]
    );

    // TOKEN
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
      user: authUser,
    });

  } catch (error) {
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

    // VALIDACIONES
    if (!email || !password) {
      return res.status(400).json({
        error: "Email y password requeridos",
      });
    }

    // BUSCAR USUARIO
    const result = await pool.query(
      `
      SELECT 
        au.id,
        au.email,
        au.password_hash,
        p.name,
        p.username,
        p.avatar_color,
        p.id as profile_id
      FROM auth_users au
      LEFT JOIN profiles p
        ON p.auth_user_id = au.id
      WHERE au.email = $1
      `,
      [email]
    );

    // VALIDAR EXISTENCIA
    if (result.rows.length === 0) {
      return res.status(401).json({
        error: "Usuario no encontrado",
      });
    }

    const user = result.rows[0];

    // VALIDAR PASSWORD
    const validPassword = await bcrypt.compare(
      password,
      user.password_hash
    );

    if (!validPassword) {
      return res.status(401).json({
        error: "Contraseña incorrecta",
      });
    }

    // GENERAR TOKEN
    const token = jwt.sign(
      {
        userId: user.id,
      },
      process.env.JWT_SECRET,
      {
        expiresIn: "1d",
      }
    );

    // RESPUESTA
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
      },
    });

  } catch (error) {
    res.status(500).json({
      error: error.message,
    });
  }
});

// =====================
// 👤 USER PROFILE
// =====================
app.get("/me", authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `
      SELECT 
        au.id,
        au.email,
        p.name,
        p.username,
        p.avatar_color
      FROM auth_users au
      LEFT JOIN profiles p
        ON p.auth_user_id = au.id
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
    } = req.body;

    if (!title || !type || !due_date) {
      return res.status(400).json({
        error: "Campos obligatorios faltantes",
      });
    }

    const result = await pool.query(
      `
      INSERT INTO media_requests (
        title,
        description,
        type,
        due_date,
        created_by,
        status
      )
      VALUES ($1, $2, $3, $4, $5, 'pending')
      RETURNING *
      `,
      [
        title,
        description,
        type,
        due_date,
        req.user.userId,
      ]
    );

    res.json(result.rows[0]);

  } catch (error) {
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

const express = require('express');
const mysql = require('mysql2/promise');
const cors = require('cors');
const helmet = require('helmet');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const winston = require('winston');
const Joi = require('joi');
require('dotenv').config();

const app = express();
const PORT = process.env.API_PORT || 3000;

// Configurazione logger
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.File({ filename: './logs/error.log', level: 'error' }),
    new winston.transports.File({ filename: './logs/combined.log' }),
    new winston.transports.Console({
      format: winston.format.simple()
    })
  ]
});

// Configurazione database
const dbConfig = {
  host: process.env.DB_HOST || 'mariadb',
  port: process.env.DB_PORT || 3306,
  user: process.env.DB_USER || 'gameuser',
  password: process.env.DB_PASSWORD || 'secure_game_password',
  database: process.env.DB_NAME || 'gamedb',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
};

let pool;

// Inizializza pool di connessioni
async function initDatabase() {
  try {
    pool = mysql.createPool(dbConfig);
    await pool.execute('SELECT 1');
    logger.info('Database connesso con successo');
  } catch (error) {
    logger.error('Errore connessione database:', error);
    process.exit(1);
  }
}

// Middleware
app.use(helmet());
app.use(cors());
app.use(express.json({ limit: '10mb' }));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minuti
  max: 100 // max 100 richieste per IP per finestra
});
app.use(limiter);

// Middleware di autenticazione
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Token di accesso richiesto' });
  }

  jwt.verify(token, process.env.JWT_SECRET || 'your_jwt_secret_key_here', (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Token non valido' });
    }
    req.user = user;
    next();
  });
};

// Schemi di validazione
const userRegistrationSchema = Joi.object({
  username: Joi.string().alphanum().min(3).max(50).required(),
  password: Joi.string().min(6).max(100).required()
});

const userLoginSchema = Joi.object({
  username: Joi.string().alphanum().min(3).max(50).required(),
  password: Joi.string().min(6).max(100).required()
});

const scoreUpdateSchema = Joi.object({
  score: Joi.number().integer().min(0).required()
});

const mapCompletionSchema = Joi.object({
  mapId: Joi.number().integer().positive().required()
});

// =======================
// UTILITY FUNCTIONS
// =======================

// Genera JWT token con durata configurabile
function generateAuthToken(userId, username) {
  return jwt.sign(
    { userId: userId, username: username },
    process.env.JWT_SECRET || 'your_jwt_secret_key_here',
    { expiresIn: '7d' } // Durata centralizzata del token
  );
}

// =======================
// ENDPOINTS
// =======================

// Verifica token JWT
app.get('/api/auth/verify', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;

    // Ottieni informazioni utente per confermare che il token è valido
    const [users] = await pool.execute(
      'SELECT id, username, best_score, map_completed FROM users WHERE id = ?',
      [userId]
    );

    if (users.length === 0) {
      return res.status(404).json({ error: 'Utente non trovato' });
    }

    const user = users[0];

    // Trova la posizione nella leaderboard dell'utente usando RANK() per gestire i pari merito
    const [rank] = await pool.execute(
      `SELECT position, username FROM leaderboard 
      WHERE username = ?`,
      [user.username]
    );

    // Converte il rank in intero, o null se non trovato
    const userRank = rank.length > 0 ? rank[0].position : null;
    
    logger.info(`Token verificato per utente: ${user.username}, rank: ${userRank}`);
    res.json({
      valid: true,
      user: {
        id: user.id,
        username: user.username,
        bestScore: user.best_score,
        mapsCompleted: user.map_completed,
        rank: userRank
      }
    });

  } catch (error) {
    logger.error('Errore verifica token:', error);
    res.status(500).json({ error: 'Errore interno del server' });
  }
});

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'OK', timestamp: new Date().toISOString() });
});

// Registrazione utente con login automatico
app.post('/api/auth/register', async (req, res) => {
  try {
    const { error, value } = userRegistrationSchema.validate(req.body);
    if (error) {
      return res.status(400).json({ error: error.details[0].message });
    }

    const { username, password } = value;

    // Verifica se l'utente esiste già
    const [existingUsers] = await pool.execute(
      'SELECT id FROM users WHERE username = ?',
      [username]
    );

    if (existingUsers.length > 0) {
      return res.status(409).json({ error: 'Username già esistente' });
    }

    // Hash della password
    const saltRounds = 12;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Inserisci nuovo utente
    const [result] = await pool.execute(
      'INSERT INTO users (username, psw_md5) VALUES (?, ?)',
      [username, hashedPassword]
    );

    const userId = result.insertId;

    // Genera JWT token per login automatico
    const token = generateAuthToken(userId, username);

    logger.info(`Nuovo utente registrato e loggato: ${username}`);
    res.status(201).json({ 
      token: token,
      user: {
        id: userId,
        username: username,
        bestScore: 0,
        mapsCompleted: 0,
		rank: "?"
      }
    });

  } catch (error) {
    logger.error('Errore registrazione:', error);
    res.status(500).json({ error: 'Errore interno del server' });
  }
});

// Login utente
app.post('/api/auth/login', async (req, res) => {
  try {
    const { error, value } = userLoginSchema.validate(req.body);
    if (error) {
      return res.status(400).json({ error: error.details[0].message });
    }

    const { username, password } = value;

    // Trova utente
    const [users] = await pool.execute(
      'SELECT id, username, psw_md5, best_score, map_completed FROM users WHERE username = ?',
      [username]
    );

    if (users.length === 0) {
      return res.status(401).json({ error: 'Credenziali non valide' });
    }

    const user = users[0];

    // Verifica password con gestione degli errori robusta
    let isValidPassword = false;
    try {
      // Verifica che user.psw_md5 sia una stringa valida
      if (!user.psw_md5 || typeof user.psw_md5 !== 'string') {
        logger.error(`Hash password non valido per l'utente: ${username}`);
        return res.status(500).json({ error: 'Errore interno del server' });
      }
      
      isValidPassword = await bcrypt.compare(password, user.psw_md5);
    } catch (bcryptError) {
      // Log dettagliato dell'errore ma risposta generica al client
      logger.error(`Errore durante la verifica password per ${username}:`, bcryptError);
      return res.status(500).json({ error: 'Errore interno durante la verifica delle credenziali' });
    }
    
    if (!isValidPassword) {
      return res.status(401).json({ error: 'Credenziali non valide' });
    }

    // Trova la posizione nella leaderboard dell'utente usando RANK() per gestire i pari merito
    const [rank] = await pool.execute(
      `SELECT position, username FROM leaderboard 
      WHERE username = ?`,
      [user.username]
    );

    // Converte il rank in intero, o null se non trovato
    const userRank = rank.length > 0 ? rank[0].position : null;

    // Genera JWT token
    const token = generateAuthToken(user.id, user.username);

    logger.info(`Login effettuato: ${username}, rank: ${userRank}`);
    res.json({
      token,
      user: {
        id: user.id,
        username: user.username,
        bestScore: user.best_score,
        mapsCompleted: user.map_completed,
        rank: userRank
      }
    });

  } catch (error) {
    logger.error('Errore login:', error);
    res.status(500).json({ error: 'Errore interno del server' });
  }
});

// Ottieni leaderboard
app.get('/api/leaderboard', async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit) || 10, 100);
    const offset = Math.max(parseInt(req.query.offset) || 0, 0);

    const [leaderboard] = await pool.execute(
      'SELECT position, username, best_score FROM leaderboard ORDER BY best_score DESC LIMIT ? OFFSET ?',
      [limit, offset]
    );

    res.json({ leaderboard });

  } catch (error) {
    logger.error('Errore leaderboard:', error);
    res.status(500).json({ error: 'Errore interno del server' });
  }
});

// Error handler
app.use((error, req, res, next) => {
  logger.error('Errore non gestito:', error);
  res.status(500).json({ error: 'Errore interno del server' });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ error: 'Endpoint non trovato' });
});

// Avvio server
async function startServer() {
  await initDatabase();
  
  app.listen(PORT, '0.0.0.0', () => {
    logger.info(`API Server avviato sulla porta ${PORT}`);
  });
}

// Gestione segnali per graceful shutdown
process.on('SIGINT', async () => {
  logger.info('Ricevuto SIGINT, chiusura server...');
  if (pool) {
    await pool.end();
  }
  process.exit(0);
});

process.on('SIGTERM', async () => {
  logger.info('Ricevuto SIGTERM, chiusura server...');
  if (pool) {
    await pool.end();
  }
  process.exit(0);
});

startServer().catch((error) => {
  logger.error('Errore avvio server:', error);
  process.exit(1);
});
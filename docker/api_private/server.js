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
const PORT = process.env.API_PORT || 3001;

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


// Ottieni la prima mappa di difficolta x non giocata da i 2 utenti specificati

app.get('/api/maps/first-uncompleted', async (req, res) => {
	try {
		const difficulty = parseInt(req.query.difficulty);
		const userId1 = parseInt(req.query.user_id1);
		const userId2 = parseInt(req.query.user_id2);

		if (
			isNaN(difficulty) ||
			isNaN(userId1) ||
			isNaN(userId2) ||
			difficulty <= 0 ||
			userId1 <= 0 ||
			userId2 <= 0
		) {
			return res.status(400).json({ error: 'Parametri non validi' });
		}

		const [maps] = await pool.execute(
			`
			SELECT m.map_name, m.id
			FROM maps m
			WHERE m.difficulty = ?
				AND m.id NOT IN (
					SELECT map_id FROM user_completed_maps WHERE user_id = ?
				)
				AND m.id NOT IN (
					SELECT map_id FROM user_completed_maps WHERE user_id = ?
				)
			ORDER BY m.id ASC
			LIMIT 1
			`,
			[difficulty, userId1, userId2]
		);

		if (maps.length === 0) {
			return res.status(404).json({ error: 'Nessuna mappa trovata' });
		}

		res.json({ mapName: maps[0].map_name , mapId: maps[0].id });
	} catch (error) {
		logger.error('Errore ricerca prima mappa non giocata:', error);
		res.status(500).json({ error: 'Errore interno del server' });
	}
});

// Registra il completamento di una mappa da parte di un utente
app.post('/api/maps/user-completed', async (req, res) => {
  try {
    const { error, value } = Joi.object({
      user_id: Joi.number().integer().positive().required(),
      map_id: Joi.number().integer().positive().required(),
      completation_strike: Joi.number().integer().min(0).required()
    }).validate(req.body);

    if (error) {
      return res.status(400).json({ error: error.details[0].message });
    }

    const { user_id, map_id, completation_strike } = value;

    // Inizia una transazione per garantire consistenza
    const connection = await pool.getConnection();
    await connection.beginTransaction();

    try {
      // Verifica che l'utente esista
      const [users] = await connection.execute(
        'SELECT id, username, map_completed, best_score FROM users WHERE id = ?',
        [user_id]
      );

      if (users.length === 0) {
        await connection.rollback();
        connection.release();
        return res.status(404).json({ error: 'Utente non trovato' });
      }

      // Verifica che la mappa esista
      const [maps] = await connection.execute(
        'SELECT id, map_name FROM maps WHERE id = ?',
        [map_id]
      );

      if (maps.length === 0) {
        await connection.rollback();
        connection.release();
        return res.status(404).json({ error: 'Mappa non trovata' });
      }

      // Verifica se l'utente ha già completato questa mappa
      const [existingCompletions] = await connection.execute(
        'SELECT id FROM user_completed_maps WHERE user_id = ? AND map_id = ?',
        [user_id, map_id]
      );

      if (existingCompletions.length > 0) {
        await connection.rollback();
        connection.release();
        return res.status(409).json({ error: 'Mappa già completata da questo utente' });
      }

      // Inserisci il completamento nella tabella user_completed_maps
      const [completionResult] = await connection.execute(
        'INSERT INTO user_completed_maps (user_id, map_id) VALUES (?, ?)',
        [user_id, map_id]
      );

      const completionId = completionResult.insertId;

      // Aggiorna il conteggio mappe completate dell'utente
      await connection.execute(
        'UPDATE users SET map_completed = map_completed + 1 WHERE id = ?',
        [user_id]
      );

	  if (completation_strike > users[0].best_score) {
		// Aggiorna il miglior punteggio dell'utente se il completamento ha un punteggio migliore
		await connection.execute(
		  'UPDATE users SET best_score = ? WHERE id = ?',
		  [completation_strike, user_id]
		);
	  }

      // Commit della transazione
      await connection.commit();
      connection.release();

      logger.info(`Completamento mappa registrato: User ${users[0].username} (ID: ${user_id}), Map ${maps[0].map_name} (ID: ${map_id})`);
      
      res.status(201).json({
        message: 'Completamento mappa registrato con successo',
        completionId: completionId,
        userId: user_id,
        mapId: map_id,
        userName: users[0].username,
        mapName: maps[0].map_name,
        newCompletedCount: users[0].map_completed + 1
      });

    } catch (transactionError) {
      await connection.rollback();
      connection.release();
      throw transactionError;
    }

  } catch (error) {
    logger.error('Errore registrazione completamento mappa:', error);
    res.status(500).json({ error: 'Errore interno del server' });
  }
});

// Registra il completamento di una mappa in modalità ranked
app.post('/api/ranked/user-completed', async (req, res) => {
  try {
    const { error, value } = Joi.object({
      user_id: Joi.number().integer().positive().required(),
      map_id: Joi.number().integer().positive().required(),
      completation_strike: Joi.number().integer().min(0).required()
    }).validate(req.body);

    if (error) {
      return res.status(400).json({ error: error.details[0].message });
    }

    const { user_id, map_id, completation_strike } = value;

    // Inizia una transazione per garantire consistenza
    const connection = await pool.getConnection();
    await connection.beginTransaction();

    try {
      // Verifica che l'utente esista
      const [users] = await connection.execute(
        'SELECT id, username, map_completed, best_score FROM users WHERE id = ?',
        [user_id]
      );

      if (users.length === 0) {
        await connection.rollback();
        connection.release();
        return res.status(404).json({ error: 'Utente non trovato' });
      }

      // Verifica che la mappa esista
      const [maps] = await connection.execute(
        'SELECT id, map_name FROM maps WHERE id = ?',
        [map_id]
      );

      if (maps.length === 0) {
        await connection.rollback();
        connection.release();
        return res.status(404).json({ error: 'Mappa non trovata' });
      }

      // Verifica se l'utente ha già completato questa mappa (per evitare duplicati nel tracking)
      const [existingCompletions] = await connection.execute(
        'SELECT id FROM user_completed_maps WHERE user_id = ? AND map_id = ?',
        [user_id, map_id]
      );

      // Inserisci il completamento nella tabella user_completed_maps solo se non esiste già
      if (existingCompletions.length === 0) {
        await connection.execute(
          'INSERT INTO user_completed_maps (user_id, map_id) VALUES (?, ?)',
          [user_id, map_id]
        );
      }

      // NOTA: In modalità ranked NON incrementiamo map_completed dell'utente
      // Aggiorniamo solo il best_score se il punteggio è migliore
      if (completation_strike > users[0].best_score) {
        await connection.execute(
          'UPDATE users SET best_score = ? WHERE id = ?',
          [completation_strike, user_id]
        );
      }

      // Commit della transazione
      await connection.commit();
      connection.release();

      logger.info(`Completamento ranked registrato: User ${users[0].username} (ID: ${user_id}), Map ${maps[0].map_name} (ID: ${map_id}), Score: ${completation_strike}`);
      
      res.status(201).json({
        message: 'Completamento ranked registrato con successo',
        userId: user_id,
        mapId: map_id,
        userName: users[0].username,
        mapName: maps[0].map_name,
        currentScore: completation_strike,
        bestScore: Math.max(users[0].best_score, completation_strike)
      });

    } catch (transactionError) {
      await connection.rollback();
      connection.release();
      throw transactionError;
    }

  } catch (error) {
    logger.error('Errore registrazione completamento ranked:', error);
    res.status(500).json({ error: 'Errore interno del server' });
  }
});

// Inserisci una nuova mappa nel database
app.post('/api/maps/new', async (req, res) => {
  try {
    const { error, value } = Joi.object({
      map_name: Joi.string().min(3).max(100).required(),
      difficulty: Joi.number().integer().min(1).max(5).required()
    }).validate(req.body);

    if (error) {
      return res.status(400).json({ error: error.details[0].message });
    }

    const { map_name, difficulty } = value;

    // Verifica se esiste già una mappa con lo stesso nome
    const [existingMaps] = await pool.execute(
      'SELECT id FROM maps WHERE map_name = ?',
      [map_name]
    );

    if (existingMaps.length > 0) {
      return res.status(409).json({ error: 'Mappa con questo nome già esistente' });
    }

    // Inserisci la nuova mappa
    const [result] = await pool.execute(
      'INSERT INTO maps (map_name, difficulty, completed_times, played_times) VALUES (?, ?, 0, 0)',
      [map_name, difficulty]
    );

    const mapId = result.insertId;

    logger.info(`Nuova mappa creata: ${map_name} (ID: ${mapId}) dal server`);
    
    res.status(201).json({
      message: 'Mappa creata con successo',
      mapId: mapId,
      mapName: map_name,
      difficulty: difficulty
    });

  } catch (error) {
    logger.error('Errore creazione mappa:', error);
    res.status(500).json({ error: 'Errore interno del server' });
  }
});

// Aggiorna le statistiche di una mappa (solo rete interna)
app.post('/api/maps/update-stats', async (req, res) => {
  try {
    const { error, value } = Joi.object({
      map_name: Joi.string().min(1).max(100).required(),
      incr_played: Joi.boolean().required(),
      incr_completed: Joi.boolean().required()
    }).validate(req.body);

    if (error) {
      return res.status(400).json({ error: error.details[0].message });
    }

    const { map_name, incr_played, incr_completed } = value;

    // Costruisci la query dinamicamente
    let updateQuery = 'UPDATE maps SET ';
    let updateFields = [];
    let queryParams = [];

    if (incr_played) {
      updateFields.push('played_times = played_times + 1');
    }

    if (incr_completed) {
      updateFields.push('completed_times = completed_times + 1');
    }

    if (updateFields.length === 0) {
      return res.status(400).json({ error: 'Almeno un parametro di incremento deve essere true' });
    }

    updateQuery += updateFields.join(', ') + ' WHERE map_name = ?';
    queryParams.push(map_name);

    const [result] = await pool.execute(updateQuery, queryParams);

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Mappa non trovata' });
    }

    logger.info(`Statistiche aggiornate per mappa: ${map_name} (played: ${incr_played}, completed: ${incr_completed})`);
    
    res.json({
      message: 'Statistiche mappa aggiornate con successo',
      mapName: map_name,
      updatedFields: {
        played: incr_played,
        completed: incr_completed
      }
    });

  } catch (error) {
    logger.error('Errore aggiornamento statistiche mappa:', error);
    res.status(500).json({ error: 'Errore interno del server' });
  }
});

// Ottieni il valore massimo di maps_completed tra gli utenti specificati
app.post('/api/users/max-maps-completed', async (req, res) => {
  try {
    const { error, value } = Joi.object({
      user_ids: Joi.array().items(Joi.number().integer().positive()).min(1).required()
    }).validate(req.body);

    if (error) {
      return res.status(400).json({ error: error.details[0].message });
    }

    const { user_ids } = value;

    // Costruisci i placeholder per la query (?, ?, ?, ...)
    const placeholders = user_ids.map(() => '?').join(', ');
    
    // Query per ottenere il valore massimo di maps_completed
    const [results] = await pool.execute(
      `SELECT MAX(map_completed) as max_maps_completed FROM users WHERE id IN (${placeholders})`,
      user_ids
    );

    const maxMapsCompleted = results.length > 0 ? (results[0].max_maps_completed || 0) : 0;

    logger.info(`Max maps completed retrieved for users [${user_ids.join(', ')}]: ${maxMapsCompleted}`);
    
    res.json({
      max_maps_completed: maxMapsCompleted,
      user_ids: user_ids,
      count: user_ids.length
    });

  } catch (error) {
    logger.error('Errore recupero max maps completed:', error);
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
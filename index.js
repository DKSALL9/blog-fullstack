import express from 'express';
import pg from 'pg';
import bcrypt from 'bcryptjs';
import session from 'express-session';
import multer from 'multer';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import 'dotenv/config';


const __dirname = dirname(fileURLToPath(import.meta.url));
const app = express();
const port = 3000;

const pool = new pg.Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false,
  },
});

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));
app.use(session({
  secret: 'your-secret-key',
  resave: false,
  saveUninitialized: false
}));

// File upload configuration
const storage = multer.diskStorage({
  destination: './public/uploads/',
  filename: (req, file, cb) => {
    cb(null, Date.now() + '-' + file.originalname);
  }
});
const upload = multer({ storage });

// Database initialization
async function initDB() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username VARCHAR(50) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL
      );
      
      CREATE TABLE IF NOT EXISTS posts (
        id SERIAL PRIMARY KEY,
        title VARCHAR(255) NOT NULL,
        content TEXT NOT NULL,
        image_url VARCHAR(255),
        user_id INTEGER REFERENCES users(id),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);
    console.log('Database initialized');
  } catch (err) {
    console.error('Database initialization error:', err);
  }
}

initDB();

// Routes
app.get('/', (req, res) => {
  res.sendFile(join(__dirname, 'public', 'index.html'));
});

app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    await pool.query(
      'INSERT INTO users (username, password) VALUES ($1, $2)',
      [username, hashedPassword]
    );
    res.redirect('/login.html');
  } catch (err) {
    res.status(500).json({ error: 'Error registering user' });
  }
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    if (result.rows.length > 0) {
      const valid = await bcrypt.compare(password, result.rows[0].password);
      if (valid) {
        req.session.userId = result.rows[0].id;
        res.redirect('/dashboard.html');
      } else {
        res.status(401).json({ error: 'Invalid credentials' });
      }
    } else {
      res.status(401).json({ error: 'User not found' });
    }
  } catch (err) {
    res.status(500).json({ error: 'Error logging in' });
  }
});

app.post('/posts', upload.single('image'), async (req, res) => {
  if (!req.session.userId) {
    return res.status(401).json({ error: 'Not authenticated' });
  }
  
  const { title, content } = req.body;
  const imageUrl = req.file ? `/uploads/${req.file.filename}` : null;
  
  try {
    await pool.query(
      'INSERT INTO posts (title, content, image_url, user_id) VALUES ($1, $2, $3, $4)',
      [title, content, imageUrl, req.session.userId]
    );
    res.redirect('/dashboard.html');
  } catch (err) {
    res.status(500).json({ error: 'Error creating post' });
  }
});

app.get('/posts', async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT posts.*, users.username FROM posts JOIN users ON posts.user_id = users.id ORDER BY created_at DESC'
    );
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: 'Error fetching posts' });
  }
});

app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});
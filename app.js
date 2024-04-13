const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const session = require('express-session');

const app = express();
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(session({
  secret: 'your-secret-key',
  resave: false,
  saveUninitialized: true,
  cookie: { secure: 'auto' }
}));

const db = new sqlite3.Database('./userdata.db', sqlite3.OPEN_READWRITE | sqlite3.OPEN_CREATE, (err) => {
  if (err) console.error('Error when connecting to the database', err.message);
  else {
    console.log('Database connection established');
    db.run(`CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL
    )`, [], (err) => {
      if (err) console.error('Error creating table', err.message);
      else console.log('Users table created');
    });
  }
});

app.post('/register', async (req, res) => {
  const { email, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  db.run('INSERT INTO users (email, password) VALUES (?, ?)', [email, hashedPassword], function(err) {
    if (err) {
      console.error('Error registering new user', err.message);
      res.send("Error registering user.");
    } else {
      console.log(`A new user has been added with ID ${this.lastID}`);
      res.redirect('/login.html');
    }
  });
});

app.post('/login', (req, res) => {
  const { email, password } = req.body;
  db.get('SELECT * FROM users WHERE email = ?', [email], async (err, user) => {
    if (err || !user) {
      console.error('User not found or error fetching user', err);
      res.send("Error logging in.");
    } else if (await bcrypt.compare(password, user.password)) {
      req.session.userId = user.id;
      res.redirect('/dashboard.html');
    } else {
      res.send("Incorrect password.");
    }
  });
});

app.use(express.static('public'));

app.listen(3000, () => {
  console.log('Server is running on http://localhost:3000');
});

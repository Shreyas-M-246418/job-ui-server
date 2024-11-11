const express = require('express');
const cors = require('cors');
const fs = require('fs').promises;
const path = require('path');
const jwt = require('jsonwebtoken');
const passport = require('passport');
const GitHubStrategy = require('passport-github2').Strategy;
const session = require('express-session');
require('dotenv').config();

const app = express();
const port = process.env.PORT || 3001;

// Middleware for token authentication
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.sendStatus(401);

  jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key', (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

// Helper functions for reading/writing jobs
const readJobsFile = async () => {
  try {
    const data = await fs.readFile(path.join(__dirname, 'data', 'jobs.json'), 'utf8');
    return JSON.parse(data);
  } catch (error) {
    return [];
  }
};

const writeJobsFile = async (jobs) => {
  await fs.writeFile(
    path.join(__dirname, 'data', 'jobs.json'),
    JSON.stringify(jobs, null, 2),
    'utf8'
  );
};

// Session storage using file system
const FileStore = require('session-file-store')(session);

// Middleware
app.use(cors({
  origin: process.env.CLIENT_URL || 'https://job-ui-six.vercel.app',
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true
}));

app.use(express.json());

// Session configuration with FileStore
app.use(session({
  store: new FileStore({
    path: './sessions'
  }),
  secret: process.env.SESSION_SECRET || 'your-secret-key',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
    maxAge: 24 * 60 * 60 * 1000 // 1 day
  }
}));

// Passport initialization
app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser((user, done) => {
  done(null, user);
});

passport.deserializeUser((user, done) => {
  done(null, user);
});

// GitHub Strategy
passport.use(new GitHubStrategy({
    clientID: process.env.GITHUB_CLIENT_ID,
    clientSecret: process.env.GITHUB_CLIENT_SECRET,
    callbackURL: "/auth/github/callback"
  },
  async (accessToken, refreshToken, profile, done) => {
    try {
      const user = {
        id: profile.id,
        username: profile.username,
        name: profile.displayName
      };
      return done(null, user);
    } catch (error) {
      return done(error, null);
    }
  }
));

// Auth routes
app.post('/auth/google', async (req, res) => {
  try {
    const { token } = req.body;
    // For demo purposes, we're creating a simple JWT
    // In production, you should verify the Google token
    const jwtToken = jwt.sign(
      { userId: 'google-user' }, 
      process.env.JWT_SECRET || 'your-secret-key'
    );
    res.json({ 
      token: jwtToken, 
      user: { 
        id: 'google-user',
        email: 'user@example.com',
        name: 'Google User'
      } 
    });
  } catch (error) {
    console.error('Google auth error:', error);
    res.status(401).json({ error: 'Authentication failed' });
  }
});

app.get('/auth/github/callback',
    passport.authenticate('github', { failureRedirect: '/login' }),
    (req, res) => {
      const token = jwt.sign(
        { userId: req.user.id }, 
        process.env.JWT_SECRET || 'your-secret-key'
      );
      // Redirect to display-jobs page with token
      res.redirect(`${process.env.CLIENT_URL}/display-jobs?token=${token}`);
    }
  );

// Token verification endpoint
app.get('/auth/verify', authenticateToken, (req, res) => {
  res.json({ user: req.user });
});

// API routes
app.get('/api/jobs', async (req, res) => {
  try {
    const jobs = await readJobsFile();
    res.json(jobs);
  } catch (error) {
    console.error('Error reading jobs:', error);
    res.status(500).json({ error: 'Failed to fetch jobs' });
  }
});

app.post('/api/jobs', async (req, res) => {
  try {
    const { title, description, location, salary, userId, createdBy } = req.body;
    
    if (!title || !description) {
      return res.status(400).json({ error: 'Title and description are required' });
    }

    const jobs = await readJobsFile();
    const newJob = {
      id: jobs.length > 0 ? Math.max(...jobs.map(job => job.id)) + 1 : 1,
      title,
      description,
      location,
      salary,
      userId,
      createdBy,
      createdAt: new Date().toISOString()
    };

    jobs.push(newJob);
    await writeJobsFile(jobs);
    res.status(201).json(newJob);
  } catch (error) {
    console.error('Error creating job:', error);
    res.status(500).json({ error: 'Failed to create job' });
  }
});

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ status: 'OK' });
});

// Create data directory if it doesn't exist
const ensureDataDirectory = async () => {
  const dataDir = path.join(__dirname, 'data');
  try {
    await fs.access(dataDir);
  } catch {
    await fs.mkdir(dataDir);
    await writeJobsFile([]);
  }
};

// Initialize server
ensureDataDirectory().then(() => {
  app.listen(port, () => {
    console.log(`Server running on port ${port}`);
  });
}).catch(console.error);
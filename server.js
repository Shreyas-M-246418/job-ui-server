const express = require('express');
const cors = require('cors');
const fs = require('fs').promises;
const path = require('path');
const jwt = require('jsonwebtoken');
const axios = require('axios');
const session = require('express-session');
require('dotenv').config();

const app = express();
const port = process.env.PORT || 3001;

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

// Auth routes
app.get('/auth/github', (req, res) => {
  const githubAuthUrl = `https://github.com/login/oauth/authorize?client_id=${process.env.GITHUB_CLIENT_ID}&redirect_uri=${encodeURIComponent(process.env.GITHUB_CALLBACK_URL)}`;
  res.json({ url: githubAuthUrl });
});

app.post('/auth/github/callback', async (req, res) => {
  try {
    const { code } = req.body;
    
    // Exchange code for access token
    const tokenResponse = await axios.post('https://github.com/login/oauth/access_token', {
      client_id: process.env.GITHUB_CLIENT_ID,
      client_secret: process.env.GITHUB_CLIENT_SECRET,
      code: code,
      redirect_uri: process.env.GITHUB_CALLBACK_URL
    }, {
      headers: {
        Accept: 'application/json'
      }
    });

    const accessToken = tokenResponse.data.access_token;

    // Get user data from GitHub
    const userResponse = await axios.get('https://api.github.com/user', {
      headers: {
        Authorization: `Bearer ${accessToken}`
      }
    });

    const user = {
      id: userResponse.data.id,
      username: userResponse.data.login,
      name: userResponse.data.name || userResponse.data.login,
      email: userResponse.data.email
    };

    // Create JWT token
    const token = jwt.sign(
      { userId: user.id, username: user.username },
      process.env.JWT_SECRET || 'your-secret-key',
      { expiresIn: '24h' }
    );

    // Send user data and token back to client
    res.json({ user, token });
  } catch (error) {
    console.error('GitHub callback error:', error);
    res.status(500).json({ error: 'Authentication failed' });
  }
});

// API routes
app.get('/api/jobs', async (req, res) => {
  try {
    const jobs = await readJobsFile();
    const userId = req.query.userId;

    if (userId) {
      const userJobs = jobs.filter(job => job.userId === userId);
      res.json(userJobs);
    } else {
      res.json(jobs);
    }
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
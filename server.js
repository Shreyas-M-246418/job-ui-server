const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const axios = require('axios');
const session = require('express-session');
const FileStore = require('session-file-store')(session);
const { GoogleGenerativeAI } = require('@google/generative-ai');
const puppeteer = require('puppeteer');
const cheerio = require('cheerio');
require('dotenv').config();

const app = express();
const port = process.env.PORT || 3001;

// Initialize Google AI
const genAI = new GoogleGenerativeAI(process.env.GOOGLE_API_KEY);



// Function to scrape and summarize career page
async function scrapeAndSummarizeCareerPage(url) {
  try {
    if (!url || !url.startsWith('http')) {
      console.error('Invalid URL provided');
      return null;
    }

    const browser = await puppeteer.launch({ 
      headless: true,
      args: [
        '--no-sandbox',
        '--disable-setuid-sandbox',
        '--disable-dev-shm-usage',
        '--single-process'
      ],
      executablePath: process.env.PUPPETEER_EXECUTABLE_PATH || '/usr/bin/google-chrome'
    });
    
    console.log('Browser launched successfully');
    
    const page = await browser.newPage();
    console.log('Navigating to URL:', url);
    
    await page.goto(url, { waitUntil: 'networkidle0', timeout: 60000 });
    console.log('Page loaded successfully');
    
    const content = await page.evaluate(() => {
      const mainContent = document.body.innerText;
      return mainContent.replace(/\s+/g, ' ').trim();
    });
    
    await browser.close();
    console.log('Browser closed successfully');

    if (!content) {
      console.error('No content extracted from page');
      return null;
    }

    console.log('Content length:', content.length);
    
    const model = genAI.getGenerativeModel({ model: "gemini-pro" });
    const prompt = `Summarize this company's career page content in 200 words, focusing on:
    1. Company culture and values
    2. Growth opportunities
    3. Work environment and benefits
    
    Content: ${content.substring(0, 4000)}`; // Limit content length
    
    const result = await model.generateContent(prompt);
    const summary = result.response.text();
    
    console.log('Summary generated successfully:', summary.substring(0, 100) + '...');
    return summary;

  } catch (error) {
    console.error('Error in scrapeAndSummarizeCareerPage:', error);
    return null;
  }
}

// Function to detect spam job posting
async function detectSpamJob(jobDetails) {
  try {
    const model = genAI.getGenerativeModel({ model: "gemini-pro" });
    const prompt = `Analyze this job posting for potential spam indicators. Consider:
    1. Unrealistic salary promises
    2. Vague job descriptions
    3. Suspicious requirements
    4. Poor grammar or unprofessional language
    5. Requests for personal/financial information
    
    Job details: ${JSON.stringify(jobDetails)}
    
    Return only "true" if likely spam or "false" if likely legitimate.`;
    
    const result = await model.generateContent(prompt);
    return result.response.text().trim().toLowerCase() === 'true';
  } catch (error) {
    console.error('Error detecting spam:', error);
    return false;
  }
}

// Helper function to read jobs from GitHub
const readJobsFromGithub = async () => {
  try {
    const response = await axios.get(
      `https://api.github.com/repos/${process.env.GITHUB_REPO_OWNER}/${process.env.GITHUB_REPO_NAME}/contents/data/jobs.json`,
      {
        headers: {
          Authorization: `token ${process.env.GITHUB_ACCESS_TOKEN}`,
          Accept: 'application/vnd.github.v3+json'
        }
      }
    );
    
    const content = Buffer.from(response.data.content, 'base64').toString();
    return JSON.parse(content);
  } catch (error) {
    console.error('Error reading from GitHub:', error); 
    return [];
  }
};

// Helper function to update jobs in GitHub
const updateGithubJobs = async (jobs) => {
  try {
    const currentFile = await axios.get(
      `https://api.github.com/repos/${process.env.GITHUB_REPO_OWNER}/${process.env.GITHUB_REPO_NAME}/contents/data/jobs.json`,
      {
        headers: {
          Authorization: `token ${process.env.GITHUB_ACCESS_TOKEN}`,
          Accept: 'application/vnd.github.v3+json'
        }
      }
    );

    const updatedContent = Buffer.from(JSON.stringify(jobs, null, 2)).toString('base64');
    
    console.log('Updating GitHub with new jobs data');
    
    const response = await axios.put(
      `https://api.github.com/repos/${process.env.GITHUB_REPO_OWNER}/${process.env.GITHUB_REPO_NAME}/contents/data/jobs.json`,
      {
        message: 'Update jobs.json via API',
        content: updatedContent,
        sha: currentFile.data.sha
      },
      {
        headers: {
          Authorization: `token ${process.env.GITHUB_ACCESS_TOKEN}`,
          Accept: 'application/vnd.github.v3+json'
        },
        maxContentLength: Infinity,
        maxBodyLength: Infinity
      }
    );

    console.log('GitHub update successful');
    return true;
  } catch (error) {
    console.error('Error updating GitHub repository:', error);
    throw error;
  }
};
 
// Middleware setup
app.use(cors({
  origin: process.env.CLIENT_URL || 'https://job-ui-six.vercel.app',
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true,
  exposedHeaders: ['Set-Cookie']
}));

app.use(express.json());
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
    maxAge: 24 * 60 * 60 * 1000
  }
}));

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

// Auth routes
app.get('/auth/github', (req, res) => {
  const githubAuthUrl = `https://github.com/login/oauth/authorize?client_id=${process.env.GITHUB_CLIENT_ID}&redirect_uri=${encodeURIComponent(process.env.GITHUB_CALLBACK_URL)}`;
  res.json({ url: githubAuthUrl });
});

app.post('/auth/github/callback', async (req, res) => {
  try {
    const { code } = req.body;
    
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

    const token = jwt.sign(
      { userId: user.id, username: user.username },
      process.env.JWT_SECRET || 'your-secret-key',
      { expiresIn: '24h' }
    );

    res.json({ user, token });
  } catch (error) {
    console.error('GitHub callback error:', error);
    res.status(500).json({ error: 'Authentication failed' });
  }
});

app.get('/auth/verify', authenticateToken, (req, res) => {
  res.json({ user: req.user });
});

// Updated job creation endpoint
app.post('/api/jobs', authenticateToken, async (req, res) => {
  try {
    const {
      title,
      description,
      companyName,
      location,
      domain,
      workType,
      employmentType,
      userType,
      salaryRange,
      applyLink,
      careerLink,
      userId,
      createdBy
    } = req.body;
    
    if (!title || !description || !companyName) {
      return res.status(400).json({ 
        error: 'Required fields missing. Title, description, and company name are required.' 
      });
    }

    // Scrape and summarize career page if URL is provided
    let companySummary = null;
    if (careerLink) {
      console.log('Attempting to scrape career page:', careerLink);
      companySummary = await scrapeAndSummarizeCareerPage(careerLink);
      if (!companySummary) {
        console.log('Failed to generate company summary');
      } else {
        console.log('Company summary generated successfully');
      }
    }

    // Check for spam
    const isSpam = await detectSpamJob({
      title,
      description,
      companyName,
      salaryRange
    });

    const jobs = await readJobsFromGithub();

    const newJob = {
      id: jobs.length > 0 ? Math.max(...jobs.map(job => job.id)) + 1 : 1,
      title,
      description,
      companyName,
      location,
      domain,
      workType,
      employmentType,
      userType,
      salaryRange,
      applyLink,
      careerLink,
      companySummary: companySummary || null,
      isSpam,
      userId: userId || req.user.userId,
      createdBy: createdBy || req.user.username,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    };

    jobs.push(newJob);
    await updateGithubJobs(jobs);
    
    res.status(201).json({
      message: 'Job created successfully',
      job: newJob
    });
  } catch (error) {
    console.error('Error creating job:', error);
    res.status(500).json({ 
      error: 'Failed to create job',
      details: error.message 
    });
  }
});

// Public jobs endpoint (no auth required)
app.get('/api/public/jobs', async (req, res) => {
  try {
    const jobs = await readJobsFromGithub();
    res.json(jobs);
  } catch (error) {
    console.error('Error reading jobs:', error);
    res.status(500).json({ error: 'Failed to fetch jobs' });
  }
});


// Get all jobs endpoint
app.get('/api/jobs', authenticateToken, async (req, res) => {
  try {
    const jobs = await readJobsFromGithub();
    const userId = req.query.userId;

    if (userId) {
      // Convert both IDs to strings for comparison
      const userJobs = jobs.filter(job => String(job.userId) === String(userId));
      res.json(userJobs);
    } else {
      res.json(jobs);
    }
  } catch (error) {
    console.error('Error reading jobs:', error);
    res.status(500).json({ error: 'Failed to fetch jobs' });
  }
});

// Get single job endpoint
app.get('/api/jobs/:id', async (req, res) => {
  try {
    const jobs = await readJobsFromGithub();
    const job = jobs.find(job => job.id === parseInt(req.params.id));
    
    if (!job) {
      return res.status(404).json({ error: 'Job not found' });
    }
    
    res.json(job);
  } catch (error) {
    console.error('Error fetching job:', error);
    res.status(500).json({ error: 'Failed to fetch job' });
  }
});

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ status: 'OK' });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({
    error: 'Internal server error',
    details: process.env.NODE_ENV === 'development' ? err.message : undefined
  });
});
 
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});

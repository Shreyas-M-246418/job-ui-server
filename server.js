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
    // Validate URL
    if (!url || !url.startsWith('http')) {
      console.error('Invalid URL provided');
      return null;
    }

    // Launch browser with proper error handling
    let browser;
    try {
      browser = await puppeteer.launch({ 
        headless: true,
        args: [
          '--no-sandbox',
          '--disable-setuid-sandbox',
          '--disable-dev-shm-usage',
          '--single-process',
          '--disable-gpu',
          '--disable-software-rasterizer'
        ],
        executablePath: process.env.PUPPETEER_EXECUTABLE_PATH || '/usr/bin/google-chrome',
        timeout: 60000
      });
    } catch (error) {
      console.error('Browser launch failed:', error);
      return null;
    }

    try {
      // Create new page with proper timeout and settings
      const page = await browser.newPage();
      await page.setDefaultNavigationTimeout(30000);
      await page.setRequestInterception(true);
      
      // Optimize performance by blocking unnecessary resources
      page.on('request', (request) => {
        if (['image', 'stylesheet', 'font', 'media'].includes(request.resourceType())) {
          request.abort();
        } else {
          request.continue();
        }
      });

      // Navigate to page with proper error handling
      await page.goto(url, { 
        waitUntil: 'networkidle0', 
        timeout: 30000 
      });

      // Extract text content using multiple methods
      const content = await page.evaluate(() => {
        // Remove unnecessary elements
        const elementsToRemove = document.querySelectorAll('header, footer, nav, script, style, iframe');
        elementsToRemove.forEach(el => el.remove());

        // Get main content
        const mainContent = document.querySelector('main') || document.querySelector('article') || document.body;
        return mainContent.innerText;
      });

      await browser.close();

      // Clean up the text
      const cleanedText = content
        .replace(/\s+/g, ' ')
        .replace(/\n+/g, ' ')
        .trim();

      if (!cleanedText || cleanedText.length < 50) {
        console.error('Insufficient content extracted from page');
        return null;
      }

      // Use Google Gemini to summarize with improved prompt
      const model = genAI.getGenerativeModel({ model: "gemini-pro" });
      const prompt = `Analyze and summarize the following company career/about page content. Focus on these key aspects:

1. Company Overview: What does the company do and what is their mission?
2. Company Culture and Values: What are their core values and workplace culture?
3. Growth and Development: What opportunities exist for career growth?
4. Benefits and Perks: What do they offer employees?

Please provide a professional, concise summary in 3-4 paragraphs. If any information is missing, focus on what is available.

Content to analyze: ${cleanedText.substring(0, 5000)}`; // Limit text length to avoid token limits
      
      const result = await model.generateContent(prompt);
      const summary = result.response.text();
      
      if (!summary) {
        console.error('Failed to generate summary');
        return null;
      }

      return summary;

    } catch (error) {
      console.error('Error during page processing:', error);
      await browser.close();
      return null;
    }
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

    await axios.put(
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
        }
      }
    );

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
      console.log('Career page summary:', companySummary);
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
      companySummary,
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

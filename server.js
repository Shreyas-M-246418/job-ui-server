const express = require('express');
const cors = require('cors');
const fs = require('fs').promises;
const path = require('path');
require('dotenv').config();

const app = express();
const port = process.env.PORT || 3001;

// Middleware
app.use(cors({
  origin: 'https://job-ui-six.vercel.app',
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type']
}));
app.use(express.json());

// GitHub credentials
const GITHUB_OWNER = 'Shreyas-M-246418';
const GITHUB_REPO = 'job-ui-server';
const GITHUB_ACCESS_TOKEN = process.env.GITHUB_ACCESS_TOKEN;

// Helper function to read/write jobs data
const JOBS_FILE = path.join(__dirname, 'data', 'jobs.json');

async function readJobsFile() {
  try {
    const data = await fs.readFile(JOBS_FILE, 'utf8');
    return JSON.parse(data);
  } catch (error) {
    if (error.code === 'ENOENT') {
      // If file doesn't exist, create it with empty array
      await fs.writeFile(JOBS_FILE, '[]');
      return [];
    }
    throw error;
  }
}

async function writeJobsFile(jobs) {
  try {
    // Write the jobs data to the local jobs.json file
    await fs.writeFile(JOBS_FILE, JSON.stringify(jobs, null, 2));
    console.log('Jobs data written to local file.');

    // Update the jobs.json file on the GitHub repository
    await updateGitHubFile('data/jobs.json', JSON.stringify(jobs, null, 2));
    console.log('Jobs data updated in GitHub repository.');
  } catch (error) {
    console.error('Error writing jobs file:', error);
    throw error;
  }
}

async function updateGitHubFile(filePath, content) {
  try {
    const { Octokit } = await import('@octokit/rest');
    const octokit = new Octokit({
      auth: GITHUB_ACCESS_TOKEN
    });

    // Get the current contents of the file
    const response = await octokit.repos.getContent({
      owner: GITHUB_OWNER,
      repo: GITHUB_REPO,
      path: filePath
    });

    // Update the file content
    await octokit.repos.createOrUpdateFileContents({
      owner: GITHUB_OWNER,
      repo: GITHUB_REPO,
      path: filePath,
      message: 'Update jobs.json',
      content: Buffer.from(content).toString('base64'),
      sha: response.data.sha
    });

    console.log('GitHub file updated:', filePath);
  } catch (error) {
    console.error('Error updating GitHub file:', error);
    throw error;
  }
}

// Routes
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
    const { title, description, location, salary } = req.body;
    console.log('Incoming job data:', { title, description, location, salary });

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
      createdAt: new Date().toISOString()
    };

    jobs.push(newJob);

    try {
      await writeJobsFile(jobs);
      console.log('New job created:', newJob);
      res.status(201).json(newJob);
    } catch (error) {
      console.error('Error writing jobs file:', error);
      console.error('Error stack:', error.stack);
      res.status(500).json({ error: 'Failed to create job' });
    }
  } catch (error) {
    console.error('Error creating job:', error);
    console.error('Error stack:', error.stack);
    res.status(500).json({ error: 'Failed to create job' });
  }
});

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ status: 'OK' });
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const axios = require('axios');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = 'your_jwt_secret_key';

app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
const client_id = 'c12ce70ba45ed298d9a2e440fbd2d00b8eb5279178007085144614592ea551ea';
const client_secret  = 'gloas-8ccbd561b23d3b737043f0e98ff2824cdf3a29dce1bf394811fedfe5271c4cb6';

// Mock database
const users = [];

// Register endpoint
app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  users.push({ username, password: hashedPassword });
  res.status(201).send({ message: 'User registered successfully' });
});

app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// Login endpoin
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const user = users.find(u => u.username === username);
  console.log(users);

  if (!user) {
    return res.status(400).send({ message: 'Invalid username or password' });
  }

  const isPasswordValid = await bcrypt.compare(password, user.password);
  if (!isPasswordValid) {
    return res.status(400).send({ message: 'Invalid username or password' });
  }

  const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: '1h' });
  res.send({ token });
});

// Protected route
app.get('/protected', (req, res) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.sendStatus(401);
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.sendStatus(403);
    }
    res.send({ message: 'This is a protected route', user });
  });
});

// Integrate with GitLab Enterprise
app.post('/gitlab-login', async (req, res) => {
  const { code } = req.body;

  try {
    const response = await axios.post(`${GITLAB_URL}/oauth/token`, {
      client_id: client_id,
      client_secret: client_secret,
      code,
      grant_type: 'authorization_code',
      redirect_uri: 'http://localhost:3000/gitlab-callback'
    });

    const { access_token } = response.data;

    const userResponse = await axios.get( `${GITLAB_URL}/api/v4/user`, {
      headers: {
        'Authorization': `Bearer ${access_token}`
      }
    });

    const { username } = userResponse.data;

    const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: '1h' });
    res.send({ token });

  } catch (error) {
    console.log(error);
    res.status(400).send({ message: 'GitLab authentication failed' });
  }
});

// GitLab OAuth callback
app.get('/gitlab-callback', async (req, res) => {
    const { code } = req.query;
  
    try {
      const tokenResponse = await axios.post(`${GITLAB_URL}/oauth/token`, qs.stringify({
        client_id: GITLAB_CLIENT_ID,
        client_secret: GITLAB_CLIENT_SECRET,
        code,
        grant_type: 'authorization_code',
        redirect_uri: GITLAB_REDIRECT_URI
      }), {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded'
        }
      });
  
      const { access_token } = tokenResponse.data;
  
      const userResponse = await axios.get(`${GITLAB_URL}/api/v4/user`, {
        headers: {
          'Authorization': `Bearer ${access_token}`
        }
      });
  
      const { username } = userResponse.data;
  
      const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: '1h' });
      res.send({ token });
  
    } catch (error) {
      res.status(400).send({ message: 'GitLab authentication failed' });
    }
  });

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

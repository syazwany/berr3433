const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { MongoClient } = require('mongodb');


const app = express();
const port = 3000;


// MongoDB connection URL
const url = 'mongodb+srv://wany:wany123@wany.ccwpslo.mongodb.net/?retryWrites=true&w=majority';
const dbName = 'VisitorManagementSystem'; // database name


// Middleware for parsing JSON data
app.use(express.json());


// Middleware to verify JWT
function verifyToken(req, res, next) {
  const authHeader = req.headers.authorization;
  const token = authHeader && authHeader.split(' ')[1]; // Extract the token from the header

  if (!token) {
    res.status(401).json({ message: 'Unauthorized' });
    return;
  }

  jwt.verify(token, 'secretKey', (err, decoded) => {
    if (err) {
      res.status(403).json({ message: 'Invalid token' });
      return;
    }

    req.userId = decoded.userId;
    next();
  });
}


// Connect to MongoDB
MongoClient.connect(url, { useUnifiedTopology: true })
  .then((client) => {
    console.log('Connected to MongoDB');
    const db = client.db(dbName);


    // Logout for user (requires a valid JWT)
    app.post('/logout', verifyToken, async (req, res) => {
      try {
        // Perform any necessary logout operations
        await db.collection('users').insertOne({ action: 'Logout', userId: req.userId });
        res.status(200).json({ message: 'Logout successful' });
      } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'An error occurred' });
      }
    });


    // Login for user
    app.post('/login', async (req, res) => {
      try {
        const { username, password } = req.body;

        // Find the user in the "users" collection
        const user = await db.collection('users').findOne({ username });

        if (!user) {
          res.status(404).json({ message: 'User not found' });
          return;
        }

        // Compare the password
        const isPasswordMatch = await bcrypt.compare(password, user.password);

        if (!isPasswordMatch) {
          res.status(401).json({ message: 'Invalid password' });
          return;
        }

        // Insert into "visitors" collection
        await db.collection('visitors').insertOne({ name: 'Login Visitor', email: 'login@visitor.com' });

        // Generate a JSON Web Token (JWT)
        const token = jwt.sign({ userId: user._id }, 'secretKey');

        res.status(200).json({ message: 'Login successful', token });
      } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'An error occurred' });
      }
    });


// Create a new visitor (requires a valid JWT)
app.post('/visitors', verifyToken, async (req, res) => {
    try {
      const { name, email, purpose } = req.body;
  
      // Insert into "visitors" collection
      await db.collection('visitors').insertMany([{ name, email, purpose }]);
  
      res.status(201).json({ message: 'Visitor created successfully' });
    } catch (error) {
      console.error(error);
      res.status(500).json({ message: 'An error occurred' });
    }
  });
  

// Register a new user
app.post('/register', async (req, res) => {
    try {
      const { username, password, email, address } = req.body;
  
      // Check if the user already exists
      const existingUser = await db.collection('users').findOne({ username });
      if (existingUser) {
        res.status(409).json({ message: 'User already exists' });
        return;
      }
  
      // Hash the password
      const hashedPassword = await bcrypt.hash(password, 10);
  
      // Insert the user into the "users" collection
      const result = await db
        .collection('users')
        .insertOne({ username, password: hashedPassword, email, address });
  
      res.status(201).json({ message: 'User registered successfully' });
    } catch (error) {
      console.error(error);
      res.status(500).json({ message: 'An error occurred' });
    }
  });
  


// Register a new security
app.post('/register-security', async (req, res) => {
  try {
    const { name, username, password, email } = req.body;

    // Check if the security already exists
    const existingSecurity = await db.collection('security').findOne({ username });
    if (existingSecurity) {
      res.status(409).json({ message: 'Security already exists' });
      return;
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Insert the security into the "security" collection
    const result = await db
      .collection('security')
      .insertOne({ name, username, password: hashedPassword, email });

    res.status(201).json({ message: 'Security registered successfully' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'An error occurred' });
  }
});


  
    

        // View access info for a visitor
        app.get('/visitors/:name/:email/access', async (req, res) => {
          try {
            const { name, email } = req.params;

            // Retrieve the access info for the visitor from the "visitors" collection
            const visitors = await db.collection('visitors').findOne({ name, email });

            if (!visitors) {
              return res.status(404).json({ message: 'Access information not found' });
            }

            res.status(200).json(visitors);
          } catch (error) {
            console.error(error);
            res.status(500).json({ message: 'An error occurred' });
          }
        });



 
        // Retrieve all visitors
        app.get('/visitors', async (req, res) => {
          try {
            // Retrieve all visitors from the "visitors" collection
            const visitors = await db.collection('visitors').find().toArray();
    
            res.status(200).json(visitors);
          } catch (error) {
            console.error(error);
            res.status(500).json({ message: 'An error occurred' });
          }
        });
    

        // Update a visitor (requires a valid JWT)
app.patch('/visitors/:id', verifyToken, async (req, res) => {
    try {
      const { id } = req.params;
      const { name, email, purpose } = req.body;
  
      // Update the visitor in the "visitors" collection
      await db.collection('visitors').updateOne({ _id: id }, { $set: { name, email, purpose } });
  
      res.status(200).json({ message: 'Visitor updated successfully' });
    } catch (error) {
      console.error(error);
      res.status(500).json({ message: 'An error occurred' });
    }
  });
  
  // Delete a visitor (requires a valid JWT)
  app.delete('/visitors/:id', verifyToken, async (req, res) => {
    try {
      const { id } = req.params;
  
      // Delete the visitor from the "visitors" collection
      const result = await db.collection('visitors').deleteOne({ _id: id });
  
      res.status(200).json({ message: 'Visitor deleted successfully' });
    } catch (error) {
      console.error(error);
      res.status(500).json({ message: 'An error occurred' });
    }
  });
  


    // Start the server
    app.listen(port, () => {
      console.log(`Server running on port ${port}`);
    });
  })
  .catch((error) => {
    console.error('Error connecting to MongoDB:', error);
  });

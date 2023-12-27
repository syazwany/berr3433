const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { MongoClient } = require('mongodb');
const swaggerUi = require('swagger-ui-express');
const swaggerJsdoc = require(' swagger-jsdoc');

const app = express();
const port = 3000;


// MongoDB connection URL
const url = 'mongodb+srv://wany:wany123@wany.ccwpslo.mongodb.net/?retryWrites=true&w=majority';
const dbName = 'VisitorManagementSystem'; // database name


// Middleware for parsing JSON data
app.use(express.json());

const option = {
  definition: {
    openapi: '3.0.0',
    info: {
      title: 'Visitorr',
      version: '1.0.0',
    },
  },
};
const swaggerSpec = swaggerJsdoc(option);
app.use('/api-docs', swaggerUi.server, swaggerUi.setup(swaggerSpec));

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
    /**
     * @swagger
     * /logout:
    post:
      summary: Logout endpoint
      description: Endpoint to perform user logout
      tags:
        - Authentication
      parameters:
        - name: Authorization
          in: header
          description: Bearer token for user authentication
          required: true
          schema:
            type: string
      responses:
        '200':
          description: Successful logout
          content:
            application/json:
              example:
                message: Logout successful
        '500':
          description: Internal server error
          content:
            application/json:
              example:
                message: An error occurred
security:
  - BearerAuth: []
components:
  securitySchemes:
    BearerAuth:
      type: apiKey
      in: header
      name: Authorization
     */
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
    /**
     * @swagger
     * /login:
    post:
      summary: User Login
      description: Endpoint for user authentication and login
      tags:
        - Authentication
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              properties:
                username:
                  type: string
                  description: The username of the user
                password:
                  type: string
                  description: The password of the user
              required:
                - username
                - password
      responses:
        '200':
          description: Successful login
          content:
            application/json:
              example:
                message: Login successful
                token: "your_generated_jwt_token"
        '401':
          description: Invalid credentials
          content:
            application/json:
              example:
                message: Invalid password
        '404':
          description: User not found
          content:
            application/json:
              example:
                message: User not found
        '500':
          description: Internal server error
          content:
            application/json:
              example:
                message: An error occurred
components:
  securitySchemes:
    BearerAuth:
      type: apiKey
      in: header
      name: Authorization
     */
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
/**
 * @swagger
 *  /visitors:
    post:
      summary: Create a new visitor
      description: Endpoint to create a new visitor
      tags:
        - Visitors
      security:
        - BearerAuth: []
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              properties:
                name:
                  type: string
                  description: The name of the visitor
                email:
                  type: string
                  format: email
                  description: The email address of the visitor
                purpose:
                  type: string
                  description: The purpose of the visit
              required:
                - name
                - email
                - purpose
      responses:
        '201':
          description: Visitor created successfully
          content:
            application/json:
              example:
                message: Visitor created successfully
        '500':
          description: Internal server error
          content:
            application/json:
              example:
                message: An error occurred
components:
  securitySchemes:
    BearerAuth:
      type: apiKey
      in: header
      name: Authorization
 */
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
/**
 * @swagger
 * /register:
    post:
      summary: Register a new user
      description: Endpoint to register a new user
      tags:
        - Authentication
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              properties:
                username:
                  type: string
                  description: The username of the user
                password:
                  type: string
                  description: The password of the user
                email:
                  type: string
                  format: email
                  description: The email address of the user
                address:
                  type: string
                  description: The address of the user
              required:
                - username
                - password
                - email
                - address
      responses:
        '201':
          description: User registered successfully
          content:
            application/json:
              example:
                message: User registered successfully
        '409':
          description: User already exists
          content:
            application/json:
              example:
                message: User already exists
        '500':
          description: Internal server error
          content:
            application/json:
              example:
                message: An error occurred
components:
  securitySchemes:
    BearerAuth:
      type: apiKey
      in: header
      name: Authorization
 */
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
/**
 * @swagger
 * /register-security:
    post:
      summary: Register a new security personnel
      description: Endpoint to register a new security personnel
      tags:
        - Security
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              properties:
                name:
                  type: string
                  description: The name of the security personnel
                username:
                  type: string
                  description: The username of the security personnel
                password:
                  type: string
                  description: The password of the security personnel
                email:
                  type: string
                  format: email
                  description: The email address of the security personnel
              required:
                - name
                - username
                - password
                - email
      responses:
        '201':
          description: Security personnel registered successfully
          content:
            application/json:
              example:
                message: Security personnel registered successfully
        '409':
          description: Security personnel already exists
          content:
            application/json:
              example:
                message: Security personnel already exists
        '500':
          description: Internal server error
          content:
            application/json:
              example:
                message: An error occurred
components:
  securitySchemes:
    BearerAuth:
      type: apiKey
      in: header
      name: Authorization
 */
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
        /**
         * @swagger
         *  '/visitors/{name}/{email}/access':
    get:
      summary: Retrieve access information for a visitor
      description: Endpoint to retrieve access information for a visitor based on name and email
      tags:
        - Visitors
      parameters:
        - name: name
          in: path
          description: The name of the visitor
          required: true
          schema:
            type: string
        - name: email
          in: path
          description: The email address of the visitor
          required: true
          schema:
            type: string
      responses:
        '200':
          description: Access information retrieved successfully
          content:
            application/json:
              example:
                name: "Visitor Name"
                email: "visitor@example.com"
                accessInfo: "Access details"
        '404':
          description: Access information not found
          content:
            application/json:
              example:
                message: Access information not found
        '500':
          description: Internal server error
          content:
            application/json:
              example:
                message: An error occurred
components:
  securitySchemes:
    BearerAuth:
      type: apiKey
      in: header
      name: Authorization
         */
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
        /**
         * @swagger
         * /visitors:
    get:
      summary: Retrieve all visitors
      description: Endpoint to retrieve all visitors from the "visitors" collection
      tags:
        - Visitors
      responses:
        '200':
          description: Visitors retrieved successfully
          content:
            application/json:
              example:
                - name: "Visitor1"
                  email: "visitor1@example.com"
                  purpose: "Meeting"
                - name: "Visitor2"
                  email: "visitor2@example.com"
                  purpose: "Delivery"
                # ... more visitor entries
        '500':
          description: Internal server error
          content:
            application/json:
              example:
                message: An error occurred
components:
  securitySchemes:
    BearerAuth:
      type: apiKey
      in: header
      name: Authorization
         */
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
        /**
         * @swagger
         *  '/visitors/{id}':
    patch:
      summary: Update a visitor by ID
      description: Endpoint to update a visitor's information by ID
      tags:
        - Visitors
      parameters:
        - name: id
          in: path
          description: The ID of the visitor to update
          required: true
          schema:
            type: string
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              properties:
                name:
                  type: string
                  description: The updated name of the visitor
                email:
                  type: string
                  format: email
                  description: The updated email address of the visitor
                purpose:
                  type: string
                  description: The updated purpose of the visit
              required:
                - name
                - email
                - purpose
      responses:
        '200':
          description: Visitor updated successfully
          content:
            application/json:
              example:
                message: Visitor updated successfully
        '500':
          description: Internal server error
          content:
            application/json:
              example:
                message: An error occurred
components:
  securitySchemes:
    BearerAuth:
      type: apiKey
      in: header
      name: Authorization
         */
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
  /**
   * @swagger
   * '/visitors/{id}':
    delete:
      summary: Delete a visitor by ID
      description: Endpoint to delete a visitor by ID
      tags:
        - Visitors
      parameters:
        - name: id
          in: path
          description: The ID of the visitor to delete
          required: true
          schema:
            type: string
      responses:
        '200':
          description: Visitor deleted successfully
          content:
            application/json:
              example:
                message: Visitor deleted successfully
        '500':
          description: Internal server error
          content:
            application/json:
              example:
                message: An error occurred
components:
  securitySchemes:
    BearerAuth:
      type: apiKey
      in: header
      name: Authorization
   */
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

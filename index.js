const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const {MongoClient} = require('mongodb');
const swaggerUi = require('swagger-ui-express');
const swaggerJsdoc = require('swagger-jsdoc');

const app = express();
const port = process.env.PORT || 3000;


// MongoDB connection URL
const url = 'mongodb+srv://wany:wany123@wany.ccwpslo.mongodb.net/?retryWrites=true&w=majority';
const dbName = 'VisitorManagementSystem'; // database name

// Connect to MongoDB
let db;
MongoClient.connect(url)
    .then(client => {
        console.log('Connected to MongoDB');
        db = client.db(dbName);
    })
    .catch(error => console.error(error));
    
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
    apis: ["./index.js"],
};
const swaggerSpec = swaggerJsdoc(option);
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec));

// Middleware to verify JWT
function verifyToken(req, res, next) {
    const authHeader = req.headers.authorization;
    const token = authHeader && authHeader.split(' ')[1]; // Extract the token from the header

    if (!token) {
        res.status(401).json({
            message: 'Unauthorized'
        });
        return;
    }

    jwt.verify(token, 'secretKey', (err, decoded) => {
        if (err) {
            res.status(403).json({
                message: 'Invalid token'
            });
            return;
        }

        req.userId = decoded.userId;
        next();
    });
}


// Start defining your routes here
app.get('/', (req, res) => {
    res.send('Hello World');
});

// Logout for user (requires a valid JWT)
  /**
    *@swagger
    *  /logout:
    post:
    summary: Logout User
    description: Logs out the user and performs necessary operations.
    tags:
      - Authentication
    security:
      - bearerAuth: []
    requestBody:
      required: true
      content:
        application/json:
          schema:
            type: object
            properties:
              token:
                type: string
                description: The user's authentication token.
                example: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
    responses:
      '200':
        description: Logout successful
        content:
          application/json:
            schema:
              type: object
              properties:
                message:
                  type: string
                  description: Logout successful message.
                  example: Logout successful
      '500':
        description: An error occurred
        content:
          application/json:
            schema:
              type: object
              properties:
                message:
                  type: string
                  description: Error message.
                  example: An error occurred
components:
securitySchemes:
  bearerAuth:
    type: http
    scheme: bearer
*/
app.post('/logout', verifyToken, async (req, res) => {
    try {
        // Perform any necessary logout operations
        await db.collection('users').insertOne({
            action: 'Logout',
            userId: req.userId
        });
        res.status(200).json({
            message: 'Logout successful'
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({
            message: 'An error occurred'
        });
    }
});

// Login for user

  /**
    *@swagger
    * /login:
    post:
    summary: 'User login'
    description: 'Authenticate a user and generate a JWT token'
    consumes:
      - application/json
    produces:
      - application/json
    parameters:
      - in: body
        name: body
        description: 'User credentials for login'
        required: true
        schema:
          type: object
          properties:
            username:
              type: string
            password:
              type: string
    responses:
      '200':
        description: 'Login successful'
        schema:
          type: object
          properties:
            message:
              type: string
              description: 'Login successful'
            token:
              type: string
              description: 'Generated JWT token'
      '401':
        description: 'Invalid password'
        schema:
          type: object
          properties:
            message:
              type: string
              description: 'Invalid password'
      '404':
        description: 'User not found'
        schema:
          type: object
          properties:
            message:
              type: string
              description: 'User not found'
      '500':
        description: 'An error occurred'
        schema:
          type: object
          properties:
            message:
              type: string
              description: 'An error occurred'
*/
app.post('/login', async (req, res) => {
    try {
        const {
            username,
            password
        } = req.body;

        // Find the user in the "users" collection
        const user = await db.collection('users').findOne({
            username
        });

        if (!user) {
            res.status(404).json({
                message: 'User not found'
            });
            return;
        }

        // Compare the password
        const isPasswordMatch = await bcrypt.compare(password, user.password);

        if (!isPasswordMatch) {
            res.status(401).json({
                message: 'Invalid password'
            });
            return;
        }

        // Insert into "visitors" collection
        await db.collection('visitors').insertOne({
            name: 'Login Visitor',
            email: 'login@visitor.com'
        });

        // Generate a JSON Web Token (JWT)
        const token = jwt.sign({
            userId: user._id
        }, 'secretKey');

        res.status(200).json({
            message: 'Login successful',
            token
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({
            message: 'An error occurred'
        });
    }
});

// Create a new visitor (requires a valid JWT)
/**
  *@swagger
  * /visitors:
  post:
  summary: Create a new visitor
  security:
    - BearerAuth: []
  requestBody:
    content:
      application/json:
        schema:
          type: object
          properties:
            name:
              type: string
              description: The name of the visitor
              example: John Doe
            email:
              type: string
              format: email
              description: The email address of the visitor
              example: john@example.com
            purpose:
              type: string
              description: The purpose of the visit
              example: Meeting
          required:
            - name
            - email
            - purpose
  responses:
    '201':
      description: Visitor created successfully
      content:
        application/json:
          schema:
            type: object
            properties:
              message:
                type: string
                example: Visitor created successfully
    '500':
      description: An error occurred
      content:
        application/json:
          schema:
            type: object
            properties:
              message:
                type: string
                example: An error occurred
components:
securitySchemes:
BearerAuth:
  type: http
  scheme: bearer
*/

app.post('/visitors', verifyToken, async (req, res) => {
    try {
        const {
            name,
            email,
            purpose
        } = req.body;

        // Insert into "visitors" collection
        await db.collection('visitors').insertMany([{
            name,
            email,
            purpose
        }]);

        res.status(201).json({
            message: 'Visitor created successfully'
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({
            message: 'An error occurred'
        });
    }
});

// Register a new user
/**
*@swagger
* /register:
post:
summary: Register a new user
description: Endpoint to register a new user.
consumes:
- application/json
produces:
- application/json
parameters:
- in: body
  name: user
  description: User information for registration
  required: true
  schema:
    type: object
    properties:
      username:
        type: string
      password:
        type: string
      email:
        type: string
      address:
        type: string
responses:
201:
  description: User registered successfully
  schema:
    type: object
    properties:
      message:
        type: string
409:
  description: User already exists
  schema:
    type: object
    properties:
      message:
        type: string
500:
  description: An error occurred
  schema:
    type: object
    properties:
      message:
        type: string
*/
app.post('/register', async (req, res) => {
    try {
        const {
            username,
            password,
            email,
            address
        } = req.body;

        // Check if the user already exists
        const existingUser = await db.collection('users').findOne({
            username
        });
        if (existingUser) {
            res.status(409).json({
                message: 'User already exists'
            });
            return;
        }

        // Hash the password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Insert the user into the "users" collection
        const result = await db
            .collection('users')
            .insertOne({
                username,
                password: hashedPassword,
                email,
                address
            });

        res.status(201).json({
            message: 'User registered successfully'
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({
            message: 'An error occurred'
        });
    }
});


// Register a new security
/**
  *@swagger
  * /register-security:
  post:
  summary: Register a new security entity
  requestBody:
    required: true
    content:
      application/json:
        schema:
          type: object
          properties:
            name:
              type: string
              description: Name of the security
            username:
              type: string
              description: Unique username for the security
            password:
              type: string
              description: Password for the security
            email:
              type: string
              format: email
              description: Email address of the security
          required:
            - name
            - username
            - password
            - email
  responses:
    '201':
      description: Security registered successfully
      content:
        application/json:
          example:
            message: Security registered successfully
    '409':
      description: Security already exists
      content:
        application/json:
          example:
            message: Security already exists
    '500':
      description: An error occurred
      content:
        application/json:
          example:
            message: An error occurred
*/
app.post('/register-security', async (req, res) => {
    try {
        const {
            name,
            username,
            password,
            email
        } = req.body;

        // Check if the security already exists
        const existingSecurity = await db.collection('security').findOne({
            username
        });
        if (existingSecurity) {
            res.status(409).json({
                message: 'Security already exists'
            });
            return;
        }

        // Hash the password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Insert the security into the "security" collection
        const result = await db
            .collection('security')
            .insertOne({
                name,
                username,
                password: hashedPassword,
                email
            });

        res.status(201).json({
            message: 'Security registered successfully'
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({
            message: 'An error occurred'
        });
    }
});


// View access info for a visitor
   /**
     *@swagger
     * /visitors/{name}/{email}/access:
     get:
     summary: 'Get Access Information for a Visitor'
     parameters:
       - name: name
         in: path
         description: 'Name of the visitor'
         required: true
         type: string
       - name: email
         in: path
         description: 'Email of the visitor'
         required: true
         type: string
     responses:
       '200':
         description: 'Success'
         schema:
           type: object
           properties:
             // Define the properties of the response object here based on your actual data structure
       '404':
         description: 'Access information not found'
         schema:
           type: object
           properties:
             message:
               type: string
       '500':
         description: 'Internal Server Error'
         schema:
           type: object
           properties:
             message:
               type: string
 */
app.get('/visitors/:name/:email/access', async (req, res) => {
    try {
        const {
            name,
            email
        } = req.params;

        // Retrieve the access info for the visitor from the "visitors" collection
        const visitors = await db.collection('visitors').findOne({
            name,
            email
        });

        if (!visitors) {
            return res.status(404).json({
                message: 'Access information not found'
            });
        }

        res.status(200).json(visitors);
    } catch (error) {
        console.error(error);
        res.status(500).json({
            message: 'An error occurred'
        });
    }
});


// Retrieve all visitors
    /**
      *@swagger
      * /visitors:
      get:
      summary: Get all visitors
      responses:
        '200':
          description: Successful response
          content:
            application/json:
              example:
                - visitor1
                - visitor2
                - visitor3
        '500':
          description: Internal Server Error
          content:
            application/json:
              example:
                message: An error occurred
  */
app.get('/visitors', async (req, res) => {
    try {
        // Retrieve all visitors from the "visitors" collection
        const visitors = await db.collection('visitors').find().toArray();

        res.status(200).json(visitors);
    } catch (error) {
        console.error(error);
        res.status(500).json({
            message: 'An error occurred'
        });
    }
});
 
// update visitor        
 /**
   *@swagger
   * /visitors/{id}:
   patch:
   summary: Update a visitor's information
   parameters:
     - name: id
       in: path
       description: ID of the visitor
       required: true
       type: string
     - name: Authorization
       in: header
       description: Bearer token for authentication
       required: true
       type: string
   responses:
     200:
       description: Successful operation
       schema:
         type: object
         properties:
           message:
             type: string
             description: Visitor updated successfully
     500:
       description: Internal server error
       schema:
         type: object
         properties:
           message:
             type: string
             description: An error occurred
   consumes:
     - application/json
   produces:
     - application/json
   security:
     - BearerAuth: []
   requestBody:
     description: Visitor data to be updated
     content:
       application/json:
         schema:
           type: object
           properties:
             name:
               type: string
             email:
               type: string
             purpose:
               type: string
           required:
             - name
             - email
             - purpose
 */      
app.patch('/visitors/:id', verifyToken, async (req, res) => {
    try {
        const {
            id
        } = req.params;
        const {
            name,
            email,
            purpose
        } = req.body;

        // Update the visitor in the "visitors" collection
        await db.collection('visitors').updateOne({
            _id: id
        }, {
            $set: {
                name,
                email,
                purpose
            }
        });

        res.status(200).json({
            message: 'Visitor updated successfully'
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({
            message: 'An error occurred'
        });
    }
});

// Delete a visitor (requires a valid JWT)
  /**
    *@swagger
    * /visitors/{id}:
    delete:
    summary: 'Delete a visitor by ID'
    parameters:
      - name: id
        in: path
        description: 'ID of the visitor to be deleted'
        required: true
        type: string
    responses:
      '200':
        description: 'Successful operation'
        schema:
          type: object
          properties:
            message:
              type: string
              description: 'Visitor deleted successfully'
      '500':
        description: 'Internal Server Error'
        schema:
          type: object
          properties:
            message:
              type: string
              description: 'An error occurred'
    security:
      - jwt: []
securityDefinitions:
jwt:
  type: apiKey
  name: Authorization
  in: header
*/
app.delete('/visitors/:id', verifyToken, async (req, res) => {
    try {
        const {
            id
        } = req.params;

        // Delete the visitor from the "visitors" collection
        const result = await db.collection('visitors').deleteOne({
            _id: id
        });

        res.status(200).json({
            message: 'Visitor deleted successfully'
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({
            message: 'An error occurred'
        });
    }
});



// Start the server
try {
    app.listen(port, () => {
       console.log('Server running on port ${port}');
    });
} catch (error) {
    console.error('Error connecting to MongoDB:', error);
    // Handle any errors related to MongoDB connection here
}
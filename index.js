const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const {MongoClient} = require('mongodb');
const swaggerUi = require('swagger-ui-express');
const swaggerJsdoc = require('swagger-jsdoc');

const app = express();
const port = process.env.PORT || 3000;
const { ObjectID } = require('mongodb');

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
            title: 'Visitor',
            version: '1.0.0',
        },
        components: {  // Add 'components' section
            securitySchemes: {  // Define 'securitySchemes'
                bearerAuth: {  // Define 'bearerAuth'
                    type: 'http',
                    scheme: 'bearer',
                    bearerFormat: 'JWT'
                }
            }
        }
    },
    apis: ["./index.js"],
};
const swaggerSpec = swaggerJsdoc(option);
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec));

// Middleware to verify JWT
function verifyToken(req, res, next) {
    const authHeader = req.headers.authorization;
    const token = authHeader && authHeader.split(' ')[1]; // Extract the token from the header
    console.log('Received Token:', token);
    if (!token || blacklistedTokens.has(token)) {
        res.status(401).json({ message: 'Unauthorized' });
        return;
    }
    
    jwt.verify(token, 'secretKey', (err, decoded) => {
        if (err) {
            console.error('Token verification error:', err);
            res.status(403).json({message: 'Invalid token'});
            return;
        }

        console.log('Decoded token:', decoded);
        req.decoded = decoded; // Set decoded token in request object
        next(); // Proceed to the next middleware
    });
}

// Connect to MongoDB
MongoClient.connect(url)
    .then((client) => {
        console.log('Connected to MongoDB');
        const db = client.db(dbName);
    })

// Start defining your routes here
app.get('/', (req, res) => {
    res.send('WELCOME TO VISITOR MANAGEMENT SYSTEM!');
});

// Logout for user (requires a valid JWT)
/**
 * @swagger
 * /logout:
 *   post:
 *     summary: Logout and invalidate token
 *     tags:
 *       - Authentication
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       '200':
 *         description: Logout successful
 *         schema:
 *           type: object
 *           properties:
 *             message:
 *               type: string
 *       '401':
 *         description: Unauthorized - invalid token or not provided
 *         schema:
 *           $ref: '#/definitions/Error'
 *       '500':
 *         description: An error occurred
 *         schema:
 *           $ref: '#/definitions/Error'
 */

const blacklistedTokens = new Set(); // Assuming this set keeps track of blacklisted tokens

app.post('/logout', verifyToken, async (req, res) => {
    try {
        const token = req.headers.authorization.split(' ')[1]; // Extract token from header
        blacklistedTokens.add(token); // Add the token to the blacklist/set
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
 *   post:
 *     summary: Login a user
 *     tags:
 *       - Admin
 *     requestBody:
 *       description: User login details
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               username:
 *                 type: string
 *               password:
 *                 type: string
 *             required:
 *               - username
 *               - password
 *     responses:
 *       '200':
 *         description: Login successful
 *         content:
 *           application/json:
 *             example:
 *               message: Login successful
 *               token: <JWT_TOKEN>
 *       '401':
 *         description: Invalid password
 *         content:
 *           application/json:
 *             example:
 *               message: Invalid password
 *       '404':
 *         description: User not found
 *         content:
 *           application/json:
 *             example:
 *               message: User not found
 *       '500':
 *         description: An error occurred during login
 *         content:
 *           application/json:
 *             example:
 *               message: An error occurred during login
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

        // // Insert into "visitors" collection
        // await db.collection('visitors').insertOne({
        //     name: 'Login Visitor',
        //     email: 'login@visitor.com'
        // });

        // Generate a JSON Web Token (JWT)
        const token = jwt.sign({ role: user.role }, 'secretKey');
        console.log('Generated Token:', token);
        res.status(200).json({ message: 'Login successful', token });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ message: 'An error occurred during login' });
    }
});

// Create a new visitor (requires a valid JWT)
/**
 * @swagger
 * /visitors:
 *   post:
 *     summary: Create a new visitor
 *     description: Create a new visitor with the provided information.
 *     tags:
 *       - Visitors
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               userId:
 *                 type: string
 *                 description: Visitor's ID number
 *               name:
 *                 type: string
 *                 description: Name of the visitor
 *               email:
 *                 type: string
 *                 format: email
 *                 description: Email of the visitor
 *               purpose:
 *                 type: string
 *                 description: Purpose of the visit
 *             required:
 *               - name
 *               - email
 *               - purpose
 *     responses:
 *       '201':
 *         description: Visitor created successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *             example:
 *               message: Visitor created successfully
 *       '500':
 *         description: An error occurred
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *             example:
 *               message: An error occurred
 */
app.post('/visitors', verifyToken, async (req, res) => {
    try {
        const {
            userId,
            name,
            email,
            purpose
        } = req.body;

        const decodedToken = req.decoded;
        if(decodedToken.role == "admin"){
            // Insert into "visitors" collection
            await db.collection('visitors').insertOne({
                userId,
                name,
                email,
                purpose
            });
            res.status(201).json({
                message: 'Visitor created successfully'
            });
        } else {
            res.status(401).json({ message: 'Unauthorized' });
        }
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'An error occurred' });
    }
});

// Register a new user
/**
 * @swagger
 *  /register:
 *   post:
 *     summary: Register a new user
 *     tags:
 *        - Admin 
 *     requestBody:
 *       description: User registration details
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               username:
 *                 type: string
 *               password:
 *                 type: string
 *               email:
 *                 type: string
 *               address:
 *                 type: string
 *             required:
 *               - username
 *               - password
 *               - email
 *               - address
 *     responses:
 *       '201':
 *         description: User registered successfully
 *         content:
 *           application/json:
 *             example:
 *               message: User registered successfully
 *       '409':
 *         description: User with this email already exists
 *         content:
 *           application/json:
 *             example:
 *               message: User with this email already exists
 *       '500':
 *         description: An error occurred
 *         content:
 *           application/json:
 *             example:
 *               message: An error occurred
 */ 
app.post('/register', async (req, res) => {
    try {
        const {
            username,
            password,
            email,
            address
        } = req.body;

        // Check if the user already exists based on email
        const existingUser = await db.collection('users').findOne({
            email
        });

        if (existingUser) {
            res.status(409).json({
                message: 'User with this email already exists'
            });
            return;
        }

        // Hash the password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Insert the user into the "users" collection
        await db.collection('users').insertOne({
                username: username,
                password: hashedPassword,
                email: email,
                address: address,
                role: 'admin'
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
 * @swagger
 *  /register-security:
 *   post:
 *     summary: Register a new security
 *     tags:
 *       - Security
 *     description: Register a new security entity with the provided information.
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               name:
 *                 type: string
 *               username:
 *                 type: string
 *               password:
 *                 type: string
 *               email:
 *                 type: string
 *     responses:
 *       '201':
 *         description: Security registered successfully
 *         content:
 *           application/json:
 *             example:
 *               message: Security registered successfully
 *       '409':
 *         description: Security already exists
 *         content:
 *           application/json:
 *             example:
 *               message: Security already exists
 *       '500':
 *         description: An error occurred
 *         content:
 *           application/json:
 *             example:
 *               message: An error occurred
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
 * @swagger
 * /visitors/{name}/{email}/access:
 *   get:
 *     summary: Get access info for a visitor
 *     tags:
 *       - Visitors
 *     parameters:
 *       - name: name
 *         in: path
 *         required: true
 *         type: string
 *         description: The name of the visitor
 *       - name: email
 *         in: path
 *         required: true
 *         type: string
 *         format: email
 *         description: The email of the visitor
 *     responses:
 *       '200':
 *         description: Successful response
 *         schema:
 *           $ref: '#/definitions/Visitor'
 *       '404':
 *         description: Access information not found
 *         schema:
 *           $ref: '#/definitions/Error'
 *       '500':
 *         description: An error occurred
 *         schema:
 *           $ref: '#/definitions/Error'
 * Visitor:
 *   type: object
 *   properties:
 *     name:
 *       type: string
 *     email:
 *       type: string    
 * Error:
 *   type: object
 *   properties:
 *     message:
 *       type: string
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

//retrieve all visitors
/**
 * @swagger
 * /visitors:
 *   get:
 *     summary: "View visitors"
 *     description: "Retrieve visitors based on user role"
 *     tags:
 *       - Staff & Visitors
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       '200':
 *         description: "Visitors retrieved successfully"
 *         schema:
 *           type: array
 *           items:
 *             $ref: '#/definitions/Visitor'
 *       '400':
 *         description: "Invalid token or error in retrieving visitors"
 *         schema:
 *           $ref: '#/definitions/Error'
 *       '401':
 *         description: "Unauthorized - Invalid token or insufficient permissions"
 *         schema:
 *           $ref: '#/definitions/Error'
 *     consumes:
 *       - "application/json"
 *     produces:
 *       - "application/json"
 * definitions:
 *   Visitor:
 *     type: object
 *     properties:
 *       name:
 *         type: string
 *       email:
 *         type: string
 *   Error:
 *     type: object
 *     properties:
 *       message:
 *         type: string
 */
app.get('/visitors', verifyToken, async (req, res) => {
    try {
        const decodedToken = req.decoded;
        if (decodedToken.role === 'admin') {
            // If the user is an admin, retrieve all visitors from the "visitors" collection
            const visitors = await db.collection('visitors').find().toArray();
            res.status(200).json(visitors);
        } else {
            // If the user is not an admin, send an unauthorized message
            res.status(401).json({ message: 'Unauthorized' });
        }
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'An error occurred' });
    }
});

 
// update visitor  
/**
 * @swagger
 * /visitors/{userId}:
 *   patch:
 *     summary: Update Visitor
 *     tags:
 *       - Visitors
 *     security:
 *       - bearerAuth: []  # Requires a bearer token for authorization
 *     description: Endpoint to update a visitor by user ID
 *     parameters:
 *       - in: path
 *         name: userId
 *         required: true
 *         description: ID of the visitor to be updated
 *         schema:
 *           type: string
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               name:
 *                 type: string
 *                 description: Name of the visitor
 *               email:
 *                 type: string
 *                 description: Email of the visitor
 *               purpose:
 *                 type: string
 *                 description: Purpose of the visit
 *     responses:
 *       '200':
 *         description: Visitor updated successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   description: Visitor updated successfully
 *       '401':
 *         description: Unauthorized - Requires admin role
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   description: Insufficient permissions
 *       '404':
 *         description: Visitor not found
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   description: Visitor not found
 *       '500':
 *         description: Internal Server Error
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   description: An error occurred
 */

app.patch('/visitors/:userId', verifyToken, async (req, res) => {
    try {
        const { userId } = req.params;
        const { name, email, purpose } = req.body;

        // Check if the user has admin role
        if (req.decoded.role !== 'admin') {
            res.status(401).json({ message: 'Unauthorized - Requires admin role' });
            return;
        }

        // Update the visitor in the "visitors" collection
        const result = await db.collection('visitors').updateOne(
            { userId }, // Match based on userId
            { $set: { name, email, purpose } } // Update fields
        );

        if (result.matchedCount === 1) {
            res.status(200).json({ message: 'Visitor updated successfully' });
        } else {
            res.status(404).json({ message: 'Visitor not found' });
        }
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'An error occurred' });
    }
});

//delete a visitor
/**
 * @swagger
 * /visitors/{id}:
 *   delete:
 *     summary: Delete a visitor
 *     description: Delete a visitor from the "visitors" collection by ID. Requires admin role.
 *     tags:
 *       - Visitors
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - name: id
 *         in: path
 *         required: true
 *         description: ID of the visitor to be deleted
 *         schema:
 *           type: string
 *     responses:
 *       '200':
 *         description: Visitor deleted successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *             example:
 *               message: Visitor deleted successfully
 *       '401':
 *         description: Unauthorized - Requires admin role
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *             example:
 *               message: Unauthorized - Requires admin role
 *       '500':
 *         description: An error occurred
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *             example:
 *               message: An error occurred
 */

app.delete('/visitors/:userId', verifyToken, async (req, res) => {
    try {
        const { userId } = req.params; // Extract the 'id' from req.params

        // Check if the user has admin role
        if (req.decoded.role !== 'admin') {
            res.status(401).json({ message: 'Unauthorized - Requires admin role' });
            return;
        }

        // Delete the visitor from the "visitors" collection using the ObjectId
        const result = await db.collection('visitors').deleteOne({ userId });

        if (result.deletedCount === 1) {
            res.status(200).json({ message: 'Visitor deleted successfully' });
        } else {
            res.status(404).json({ message: 'Visitor not found' });
        }
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'An error occurred' });
    }
});

// Public API for security to create a new host account with security approval
/**
 * @swagger
 * /create/host:
 *   post:
 *     summary: Create a new host account with security approval
 *     tags:
 *       - Host
 *     security:
 *       - bearerAuth: []  # Use the 'bearerAuth' security scheme for authentication
 *     requestBody:
 *       description: Host details for account creation
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               name:
 *                 type: string
 *               username:
 *                 type: string
 *               password:
 *                 type: string
 *               email:
 *                 type: string
 *             required:
 *               - name
 *               - username
 *               - password
 *               - email
 *     responses:
 *       '201':
 *         description: Host account created successfully
 *         content:
 *           application/json:
 *             example:
 *               message: Host account created successfully
 *       '401':
 *         description: Unauthorized - Requires security role
 *         content:
 *           application/json:
 *             example:
 *               message: Unauthorized - Requires security role
 *       '409':
 *         description: Host already exists
 *         content:
 *           application/json:
 *             example:
 *               message: Host already exists
 *       '500':
 *         description: An error occurred during account creation
 *         content:
 *           application/json:
 *             example:
 *               message: An error occurred
 */
app.post('/create/host', verifyToken, async (req, res) => {
    try {
        // Check if the user has security role
        if (req.decoded.role !== 'security') {
            res.status(401).json({ message: 'Unauthorized - Requires security role' });
            return;
        }

        const { name, username, password, email } = req.body;

        // Check if the host already exists
        const existingHost = await db.collection('hosts').findOne({ username });

        if (existingHost) {
            res.status(409).json({ message: 'Host already exists' });
            return;
        }

        // Hash the password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Insert the host into the "hosts" collection
        await db.collection('hosts').insertOne({
            name,
            username,
            password: hashedPassword,
            email
        });

        res.status(201).json({ message: 'Host account created successfully' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'An error occurred' });
    }
});

// Public API for host login and token generation
/**
 * @swagger
 * /host/login:
 *   post:
 *     summary: Host Login
 *     tags:
 *       - Host
 *     requestBody:
 *       description: Host login details
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               username:
 *                 type: string
 *               password:
 *                 type: string
 *             required:
 *               - username
 *               - password
 *     responses:
 *       '200':
 *         description: Login successful, returns token
 *         content:
 *           application/json:
 *             example:
 *               message: Login successful
 *               token: <JWT_TOKEN>
 *       '401':
 *         description: Invalid password or host user not found
 *         content:
 *           application/json:
 *             example:
 *               message: Invalid password or host user not found
 *       '500':
 *         description: An error occurred during login
 *         content:
 *           application/json:
 *             example:
 *               message: An error occurred during login
 */
app.post('/host/login', async (req, res) => {
    try {
        const { username, password } = req.body;

        // Find the host user in the "hosts" collection
        const hostUser = await db.collection('hosts').findOne({ username });

        if (!hostUser) {
            res.status(401).json({ message: 'Invalid password or host user not found' });
            return;
        }

        // Compare the password
        const isPasswordMatch = await bcrypt.compare(password, hostUser.password);

        if (!isPasswordMatch) {
            res.status(401).json({ message: 'Invalid password or host user not found' });
            return;
        }

        // Generate a JSON Web Token (JWT) for the host
        const token = jwt.sign({ role: hostUser.role, username: hostUser.username }, 'secretKey');
        console.log('Generated Token:', token);
        
        res.status(200).json({ message: 'Login successful', token });
    } catch (error) {
        console.error('Host Login error:', error);
        res.status(500).json({ message: 'An error occurred during login' });
    }
});

// Public API for testing without security approval (e.g., /create/test/host)
/**
 * @swagger
 * /create/test/host:
 *   post:
 *     summary: Create a test host account without security approval
 *     tags:
 *       - Testing
 *     requestBody:
 *       description: Host details for test account creation
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               name:
 *                 type: string
 *               username:
 *                 type: string
 *               password:
 *                 type: string
 *               email:
 *                 type: string
 *             required:
 *               - name
 *               - username
 *               - password
 *               - email
 *     responses:
 *       '201':
 *         description: Test Host account created successfully
 *         content:
 *           application/json:
 *             example:
 *               message: Test Host account created successfully
 *       '409':
 *         description: Host already exists
 *         content:
 *           application/json:
 *             example:
 *               message: Host already exists
 *       '500':
 *         description: An error occurred during test account creation
 *         content:
 *           application/json:
 *             example:
 *               message: An error occurred
 */
app.post('/create/test/host', async (req, res) => {
    try {
        const { name, username, password, email } = req.body;

        // Check if the host already exists
        const existingHost = await db.collection('hosts').findOne({ username });

        if (existingHost) {
            res.status(409).json({ message: 'Host already exists' });
            return;
        }

        // Hash the password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Insert the host into the "hosts" collection
        await db.collection('hosts').insertOne({
            name,
            HostUsername,
            password: hashedPassword,
            email
        });

        res.status(201).json({ message: 'Test Host account created successfully' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'An error occurred' });
    }
});

// Public API for authenticated host to see all created visitors
/**
 * @swagger
 * /host/visitors:
 *   get:
 *     summary: Retrieve all created visitors for an authenticated host
 *     tags:
 *       - Visitor
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       '200':
 *         description: List of visitors retrieved successfully
 *         content:
 *           application/json:
 *             example:
 *               - userId: 1
 *                 name: Visitor 1
 *                 email: visitor1@example.com
 *                 purpose: Meeting
 *               - userId: 2
 *                 name: Visitor 2
 *                 email: visitor2@example.com
 *                 purpose: Delivery
 *       '401':
 *         description: Unauthorized - Requires host role
 *         content:
 *           application/json:
 *             example:
 *               message: Unauthorized - Requires host role. Ensure the provided token has the 'host' role.
 *       '500':
 *         description: An error occurred
 *         content:
 *           application/json:
 *             example:
 *               message: An error occurred
 */
app.get('/host/visitors', verifyToken, async (req, res) => {
    try {
        // Check if the user has host role
        const decodedToken = req.decoded;
        if (req.decoded.role !== 'host') {
            res.status(401).json({ message: 'Unauthorized - Requires host role' });
            return;
        }

        // Retrieve all visitors for the authenticated host from the "visitors" collection
       const visitors = await db.collection('visitors').find({ username: req.decoded.username }).toArray();
        res.status(200).json(visitors);
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'An error occurred' });
    }   
    
});

// Public API for authenticated host to issue visitor pass
/**
 * @swagger
 * /host/issue-pass:
 *   post:
 *     summary: Issue a visitor pass.
 *     description: Allows an authenticated host to issue a visitor pass.
 *     tags:
 *       - Host
 *     security:
 *       - bearerAuth: []  # Use the same security scheme as defined in the swagger definition
 *     requestBody:
 *       description: Visitor pass details
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               name:
 *                 type: string
 *                 description: Name of the visitor.
 *               email:
 *                 type: string
 *                 description: Email of the visitor.
 *               purpose:
 *                 type: string
 *                 description: Purpose of the visit.
 *             required:
 *               - name
 *               - email
 *               - purpose
 *     responses:
 *       201:
 *         description: Visitor pass issued successfully.
 *       401:
 *         description: Unauthorized - Requires host role.
 *       500:
 *         description: An error occurred.
 */
app.post('/host/issue-pass', verifyToken, async (req, res) => {
    try {
        // Check if the user has host role
        const decodedToken = req.decoded;
        if (req.decoded.role !== 'host') {
            res.status(401).json({ message: 'Unauthorized - Requires host role' });
            return;
        }

        const { name, email, purpose } = req.body;

        // Issue the visitor pass (store only in the "visitors" collection, no separate visitor account)
        await db.collection('visitors').insertOne({
            HostUsername: req.decoded.username,
            name,
            email,
            purpose,
        });

        res.status(201).json({ message: 'Visitor pass issued successfully' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'An error occurred' });
    }
});

     
  // Public API for visitor to retrieve the pass
/**
 * @swagger
 * /visitor/pass:
 *   get:
 *     summary: Retrieve the pass for the authenticated visitor
 *     description: Allows an authenticated visitor to retrieve their pass.
 *     tags:
 *       - Visitor
 *     security:
 *       - bearerAuth: []  # Use the same security scheme as defined in the swagger definition
 *     responses:
 *       200:
 *         description: Pass retrieved successfully
 *       401:
 *         description: Unauthorized - Requires visitor role
 *       404:
 *         description: Pass not found
 *       500:
 *         description: An error occurred
 */
app.get('/visitor/pass', async (req, res) => {
    try {
      // Check if the user has visitor role
      if (req.decoded.role !== 'visitor') {
        res.status(401).json({ message: 'Unauthorized - Requires visitor role' });
        return;
      }
  
      // Retrieve the pass for the authenticated visitor from the "visitors" collection
      const pass = await db.collection('visitors').findOne({ email: req.decoded.email });
  
      if (!pass) {
        res.status(404).json({ message: 'Pass not found' });
        return;
      }
  
      res.status(200).json(pass);
    } catch (error) {
      console.error(error);
      res.status(500).json({ message: 'An error occurred' });
    }
  });

// Public API for authenticated security to retrieve the contact number of the host
/**
 * @swagger
 * /security/retrieve-contact/{passIdentifier}:
 *   get:
 *     summary: Retrieve the contact information of the host.
 *     description: Allows an authenticated security personnel to retrieve the contact information of the host from a visitor pass.
 *     tags:
 *       - Security
 *     security:
 *       - bearerAuth: []  # Use the same security scheme as defined in the swagger definition
 *     parameters:
 *       - in: path
 *         name: passIdentifier
 *         required: true
 *         description: The identifier of the visitor pass.
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Host contact information retrieved successfully
 *       401:
 *         description: Unauthorized - Requires security role
 *       404:
 *         description: Visitor pass not found
 *       500:
 *         description: An error occurred
 */
app.get('/security/retrieve-contact/:passIdentifier', verifyToken, async (req, res) => {
    try {
        // Check if the user has security role
        if (req.decoded.role !== 'security') {
            res.status(401).json({ message: 'Unauthorized - Requires security role' });
            return;
        }

        const passIdentifier = req.params.passIdentifier;

        // Query the database using passIdentifier to retrieve host contact info from the visitor pass
        const visitorPass = await db.collection('visitors').findOne({ passIdentifier });

        if (!visitorPass) {
            res.status(404).json({ message: 'Visitor pass not found' });
            return;
        }

        // Return only the host's contact information to the public
        const hostContact = {
            name: visitorPass.hostUsername,
            // Add more host contact information fields as needed
        };

        res.status(200).json(hostContact);
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'An error occurred' });
    }
});


// Additional API to manage account roles by an authenticated administrator
/**
 * @swagger
 * /admin/manage-roles:
 *   patch:
 *     summary: Manage account roles by an authenticated administrator
 *     tags:
 *       - Admin
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       description: Account role details
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               username:
 *                 type: string
 *               role:
 *                 type: string
 *             required:
 *               - username
 *               - role
 *     responses:
 *       '200':
 *         description: Account role updated successfully
 *         content:
 *           application/json:
 *             example:
 *               message: Account role updated successfully
 *       '401':
 *         description: Unauthorized - Requires admin role
 *         content:
 *           application/json:
 *             example:
 *               message: Unauthorized - Requires admin role
 *       '400':
 *         description: Invalid role specified
 *         content:
 *           application/json:
 *             example:
 *               message: Invalid role specified
 *       '404':
 *         description: Account not found
 *         content:
 *           application/json:
 *             example:
 *               message: Account not found
 *       '500':
 *         description: An error occurred
 *         content:
 *           application/json:
 *             example:
 *               message: An error occurred
 */
app.patch('/admin/manage-roles', verifyToken, async (req, res) => {
    try {
        const { username, role } = req.body;

        // Check if the user has admin role
        if (req.decoded.role !== 'admin') {
            res.status(401).json({ message: 'Unauthorized - Requires admin role' });
            return;
        }

        // Validate that the role is either 'security' or 'host'
        if (role !== 'security' && role !== 'host') {
            res.status(400).json({ message: 'Invalid role specified' });
            return;
        }

        // Update the account role in the respective collection (security/host)
        const collectionName = role === 'security' ? 'security' : 'hosts';
        const result = await db.collection(collectionName).updateOne(
            { username },
            { $set: { role } }
        );

        if (result.matchedCount === 1) {
            res.status(200).json({ message: 'Account role updated successfully' });
        } else {
            res.status(404).json({ message: 'Account not found' });
        }
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'An error occurred' });
    }
});

// Additional API to manage account roles by an authenticated administrator
/**
 * @swagger
 * /admin/manage-roles:
 *   patch:
 *     summary: Manage account roles by an authenticated administrator
 *     tags:
 *       - Admin
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       description: Account role details
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               username:
 *                 type: string
 *               role:
 *                 type: string
 *             required:
 *               - username
 *               - role
 *     responses:
 *       '200':
 *         description: Account role updated successfully
 *         content:
 *           application/json:
 *             example:
 *               message: Account role updated successfully
 *       '401':
 *         description: Unauthorized - Requires admin role
 *         content:
 *           application/json:
 *             example:
 *               message: Unauthorized - Requires admin role
 *       '400':
 *         description: Invalid role specified
 *         content:
 *           application/json:
 *             example:
 *               message: Invalid role specified
 *       '404':
 *         description: Account not found
 *         content:
 *           application/json:
 *             example:
 *               message: Account not found
 *       '500':
 *         description: An error occurred
 *         content:
 *           application/json:
 *             example:
 *               message: An error occurred
 */
app.patch('/admin/manage-roles', verifyToken, async (req, res) => {
    try {
        const { username, role } = req.body;

        // Check if the user has admin role
        if (req.decoded.role !== 'admin') {
            res.status(401).json({ message: 'Unauthorized - Requires admin role' });
            return;
        }

        // Validate that the role is either 'security' or 'host'
        if (role !== 'security' && role !== 'host') {
            res.status(400).json({ message: 'Invalid role specified' });
            return;
        }

        // Update the account role in the respective collection (security/host)
        const collectionName = role === 'security' ? 'security' : 'hosts';
        const result = await db.collection(collectionName).updateOne(
            { username },
            { $set: { role } }
        );

        if (result.matchedCount === 1) {
            res.status(200).json({ message: 'Account role updated successfully' });
        } else {
            res.status(404).json({ message: 'Account not found' });
        }
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'An error occurred' });
    }
});

// Administrator login page (dump all host data upon successful login)
/**
 * @swagger
 * /admin/login:
 *   post:
 *     summary: Dump all host data upon successful login
 *     tags:
 *       - Admin
 *     requestBody:
 *       description: Administrator login details
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               username:
 *                 type: string
 *               password:
 *                 type: string
 *             required:
 *               - username
 *               - password
 *     responses:
 *       '200':
 *         description: Login successful
 *         content:
 *           application/json:
 *             example:
 *               message: Login successful
 *               token: <JWT_TOKEN>
 *               hosts:
 *                 - host1
 *                 - host2
 *                 - host3
 *       '401':
 *         description: Invalid password or admin user not found
 *         content:
 *           application/json:
 *             example:
 *               message: Invalid password or admin user not found
 *       '500':
 *         description: An error occurred during login
 *         content:
 *           application/json:
 *             example:
 *               message: An error occurred during login
 */
app.post('/admin/login', async (req, res) => {
    try {
        const { username, password } = req.body;

        // Find the admin user in the "admins" collection
        const adminUser = await db.collection('admins').findOne({ username });

        if (!adminUser) {
            res.status(401).json({ message: 'Invalid password or admin user not found' });
            return;
        }

        // Compare the password
        const isPasswordMatch = await bcrypt.compare(password, adminUser.password);

        if (!isPasswordMatch) {
            res.status(401).json({ message: 'Invalid password or admin user not found' });
            return;
        }

        // Generate a JSON Web Token (JWT)
        const token = jwt.sign({ role: adminUser.role, username: adminUser.username }, 'secretKey');

        // Retrieve all host data from the "hosts" collection
        const hosts = await db.collection('hosts').find().toArray();

        console.log('Generated Token:', token);
        res.status(200).json({ message: 'Login successful', token, hosts });
    } catch (error) {
        console.error('Admin Login error:', error);
        res.status(500).json({ message: 'An error occurred during login' });
    }
});


//Start the server
try {
    app.listen(port, () => {
       console.log(`Server running on port ${port}`);
    });
} catch (error) {
    console.error('Error connecting to MongoDB:', error);
    // Handle any errors related to MongoDB connection here
}

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
    res.send('Hello World!');
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


// Login for host
/**
 * @swagger
 * /login:
 *   post:
 *     summary: Log in as a host
 *     tags:
 *       - Hosts
 *     requestBody:
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
 *       '401':
 *         description: Invalid password or host not found
 *         content:
 *           application/json:
 *             example:
 *               message: Invalid password or host not found
 *       '500':
 *         description: An error occurred
 *         content:
 *           application/json:
 *             example:
 *               message: An error occurred
 */
app.post('/login', async (req, res) => {
    try {
        const { username, password } = req.body;

        // Find the host in the "hosts" collection
        const host = await db.collection('hosts').findOne({ username });

        if (!host) {
            res.status(404).json({ message: 'Host not found' });
            return;
        }

        // Compare the password
        const isPasswordMatch = await bcrypt.compare(password, host.password);

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
        const token = jwt.sign({ role: host.role }, 'secretKey');
        console.log('Generated Token:', token);
        res.status(200).json({ message: 'Login successful', token });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ message: 'An error occurred during login' });
    }
        res.status(200).json({ message: 'Login successful' });
    
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

// Register a new host
/**
 * @swagger
 * /register/host:
 *   post:
 *     summary: Register a new host
 *     tags:
 *       - Hosts
 *     requestBody:
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
 *         description: Host is registered successfully
 *         content:
 *           application/json:
 *             example:
 *               message: Host is registered successfully
 *       '409':
 *         description: Host with this email already exists
 *         content:
 *           application/json:
 *             example:
 *               message: Host with this email already exists
 *       '500':
 *         description: An error occurred
 *         content:
 *           application/json:
 *             example:
 *               message: An error occurred
 */
app.post('/register/host', async (req, res) => {
    try {
        const {
            username,
            password,
            email,
            address
        } = req.body;

        // Check if the host already exists based on email
        const existingHost = await db.collection('hosts').findOne({
            email
        });

        if (existingHost) {
            res.status(409).json({
                message: 'Host with this email already exists'
            });
            return;
        }

        // Hash the password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Insert the host into the "hosts" collection
        await db.collection('hosts').insertOne({
            username,
            password: hashedPassword,
            email,
            address,
            role: 'admin'
        });

        res.status(201).json({
            message: 'Host is registered successfully'
        });
    } catch (error) {
        console.error('Error registering host:', error);
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

/**
 * @swagger
 * /create/test/host:
 *   post:
 *     summary: Create a new test host account without security approval
 *     tags:
 *       - Hosts
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
 *         description: Test host account created successfully
 *         content:
 *           application/json:
 *             example:
 *               message: Test host account created successfully
 *       '500':
 *         description: An error occurred
 *         content:
 *           application/json:
 *             example:
 *               message: An error occurred
 */
app.post('/create/test/host', async (req, res) => {
    try {
        // Extract host information from the request body
        const { name, username, password, email } = req.body;

        // TODO: Add logic to create a new test host account (insert into the database)

        res.status(201).json({ message: 'Test host account created successfully' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'An error occurred' });
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


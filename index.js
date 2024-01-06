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

/**
 * @swagger
 * /create/host:
 *   post:
 *     summary: Create a new host account
 *     tags:
 *       - Security
 *     security:
 *       - bearerAuth: []
 *     description: Create a new host account with the provided information.
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
 *       '500':
 *         description: An error occurred
 *         content:
 *           application/json:
 *             example:
 *               message: An error occurred
 */
app.post('/create/host', verifyToken, async (req, res) => {
    try {
        const { name, username, password, email } = req.body;

        // Check if the user has security role
        if (req.decoded.role !== 'security') {
            res.status(401).json({ message: 'Unauthorized - Requires security role' });
            return;
        }

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

/**
 * @swagger
 * /create/test/host:
 *   post:
 *     summary: Testing API without security approval
 *     tags:
 *       - Security
 *     description: Testing API to create a new host account without security approval.
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
 *         description: Host account created successfully
 *         content:
 *           application/json:
 *             example:
 *               message: Host account created successfully (without security approval)
 *       '500':
 *         description: An error occurred
 *         content:
 *           application/json:
 *             example:
 *               message: An error occurred
 */
app.post('/create/test/host', async (req, res) => {
    try {
        const { name, username, password, email } = req.body;

        // For testing purposes, no security role check

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

        res.status(201).json({ message: 'Host account created successfully (without security approval)' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'An error occurred' });
    }
});

/**
 * @swagger
 * /host/visitors:
 *   get:
 *     summary: View all visitors created by the authenticated host
 *     tags:
 *       - Host
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       '200':
 *         description: Visitors retrieved successfully
 *         schema:
 *           type: array
 *           items:
 *             $ref: '#/definitions/Visitor'
 *       '401':
 *         description: Unauthorized - Requires host role
 *         schema:
 *           $ref: '#/definitions/Error'
 *       '500':
 *         description: An error occurred
 *         schema:
 *           $ref: '#/definitions/Error'
 */
app.get('/host/visitors', verifyToken, async (req, res) => {
    try {
        // Check if the user has host role
        if (req.decoded.role !== 'host') {
            res.status(401).json({ message: 'Unauthorized - Requires host role' });
            return;
        }

        // Retrieve visitors created by the authenticated host from the "visitors" collection
        const visitors = await db.collection('visitors').find({ hostUsername: req.decoded.username }).toArray();
        res.status(200).json(visitors);
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'An error occurred' });
    }
});

/**
 * @swagger
 * /host/issue-pass:
 *   post:
 *     summary: Issue visitor pass
 *     tags:
 *       - Host
 *     security:
 *       - bearerAuth: []
 *     description: Issue a visitor pass with the provided information.
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               name:
 *                 type: string
 *               email:
 *                 type: string
 *               purpose:
 *                 type: string
 *     responses:
 *       '201':
 *         description: Visitor pass issued successfully
 *         content:
 *           application/json:
 *             example:
 *               message: Visitor pass issued successfully
 *       '401':
 *         description: Unauthorized - Requires host role
 *         content:
 *           application/json:
 *             example:
 *               message: Unauthorized - Requires host role
 *       '500':
 *         description: An error occurred
 *         content:
 *           application/json:
 *             example:
 *               message: An error occurred
 */
app.post('/host/issue-pass', verifyToken, async (req, res) => {
    try {
        const { name, email, purpose } = req.body;

        // Check if the user has host role
        if (req.decoded.role !== 'host') {
            res.status(401).json({ message: 'Unauthorized - Requires host role' });
            return;
        }

        // Insert the visitor pass into the "visitors" collection
        await db.collection('visitors').insertOne({
            name,
            email,
            purpose,
            hostUsername: req.decoded.username
        });

        res.status(201).json({ message: 'Visitor pass issued successfully' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'An error occurred' });
    }
});

/**
 * @swagger
 * /visitor/pass:
 *   get:
 *     summary: Retrieve visitor pass
 *     tags:
 *       - Visitor
 *     parameters:
 *       - name: name
 *         in: query
 *         required: true
 *         type: string
 *         description: Name of the visitor
 *       - name: email
 *         in: query
 *         required: true
 *         type: string
 *         format: email
 *         description: Email of the visitor
 *     responses:
 *       '200':
 *         description: Visitor pass retrieved successfully
 *         schema:
 *           $ref: '#/definitions/VisitorPass'
 *       '404':
 *         description: Visitor pass not found
 *         schema:
 *           $ref: '#/definitions/Error'
 *       '500':
 *         description: An error occurred
 *         schema:
 *           $ref: '#/definitions/Error'
 * definitions:
 *   VisitorPass:
 *     type: object
 *     properties:
 *       name:
 *         type: string
 *       email:
 *         type: string
 *       purpose:
 *         type: string
 *       hostUsername:
 *         type: string
 */
app.get('/visitor/pass', async (req, res) => {
    try {
        const { name, email } = req.query;

        // Retrieve the visitor pass from the "visitors" collection
        const visitorPass = await db.collection('visitors').findOne({ name, email });

        if (!visitorPass) {
            return res.status(404).json({
                message: 'Visitor pass not found'
            });
        }

        res.status(200).json(visitorPass);
    } catch (error) {
        console.error(error);
        res.status(500).json({
            message: 'An error occurred'
        });
    }
});

// Admin Login
app.post('/admin/login', async (req, res) => {
    try {
        const { username, password } = req.body;

        // Find the admin user in the "admins" collection
        const adminUser = await db.collection('admins').findOne({ username });

        if (!adminUser) {
            res.status(404).json({ message: 'Admin user not found' });
            return;
        }

        // Compare the password
        const isPasswordMatch = await bcrypt.compare(password, adminUser.password);

        if (!isPasswordMatch) {
            res.status(401).json({ message: 'Invalid password' });
            return;
        }

        // Generate a JSON Web Token (JWT)
        const token = jwt.sign({ role: adminUser.role, username: adminUser.username }, 'secretKey');
        console.log('Generated Token:', token);
        res.status(200).json({ message: 'Login successful', token });
    } catch (error) {
        console.error('Admin Login error:', error);
        res.status(500).json({ message: 'An error occurred during login' });
    }
});

// Dump all host data upon successful login
app.get('/admin/dashboard', verifyToken, async (req, res) => {
    try {
        // Check if the user has admin role
        if (req.decoded.role !== 'admin') {
            res.status(401).json({ message: 'Unauthorized - Requires admin role' });
            return;
        }

        // Retrieve all host data from the "hosts" collection
        const hosts = await db.collection('hosts').find().toArray();
        res.status(200).json(hosts);
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'An error occurred' });
    }
});

/**
 * @swagger
 * /admin/manage-roles:
 *   patch:
 *     summary: Manage account roles
 *     tags:
 *       - Admin
 *     security:
 *       - bearerAuth: []
 *     description: Update the account role for a user (security/host) by an authenticated admin
 *     requestBody:
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
 *                 enum: [security, host]
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
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   description: Insufficient permissions
 *       '404':
 *         description: User not found
 *         content:
 *           application/json:
 *             example:
 *               message: User not found
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

        // Update the account role in the respective collection (security/host)
        const collectionName = role === 'security' ? 'security' : 'hosts';

        // Check if the user exists in the specified collection
        const user = await db.collection(collectionName).findOne({ username });
        if (!user) {
            res.status(404).json({ message: 'User not found' });
            return;
        }

        // Update the user's role
        await db.collection(collectionName).updateOne(
            { username },
            { $set: { role } }
        );

        res.status(200).json({ message: 'Account role updated successfully' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'An error occurred' });
    }
});

/**
 * @swagger
 * /visitor/check-in:
 *   post:
 *     summary: Visitor check-in
 *     tags:
 *       - Visitor
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               name:
 *                 type: string
 *               email:
 *                 type: string
 *     responses:
 *       '200':
 *         description: Visitor checked in successfully
 *         content:
 *           application/json:
 *             example:
 *               message: Visitor checked in successfully
 *       '404':
 *         description: Visitor not found
 *         content:
 *           application/json:
 *             example:
 *               message: Visitor not found
 *       '500':
 *         description: An error occurred
 *         content:
 *           application/json:
 *             example:
 *               message: An error occurred
 */
app.post('/visitor/check-in', async (req, res) => {
    try {
        const {
            name,
            email
        } = req.body;

        // Find the visitor in the "visitors" collection
        const visitor = await db.collection('visitors').findOne({
            name,
            email
        });

        if (!visitor) {
            return res.status(404).json({
                message: 'Visitor not found'
            });
        }

        // Perform check-in actions (e.g., update the visitor status in the database)

        res.status(200).json({
            message: 'Visitor checked in successfully'
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({
            message: 'An error occurred'
        });
    }
});

/**
 * @swagger
 * /visitor/check-out:
 *   post:
 *     summary: Visitor check-out
 *     tags:
 *       - Visitor
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               name:
 *                 type: string
 *               email:
 *                 type: string
 *     responses:
 *       '200':
 *         description: Visitor checked out successfully
 *         content:
 *           application/json:
 *             example:
 *               message: Visitor checked out successfully
 *       '404':
 *         description: Visitor not found
 *         content:
 *           application/json:
 *             example:
 *               message: Visitor not found
 *       '500':
 *         description: An error occurred
 *         content:
 *           application/json:
 *             example:
 *               message: An error occurred
 */
app.post('/visitor/check-out', async (req, res) => {
    try {
        const {
            name,
            email
        } = req.body;

        // Find the visitor in the "visitors" collection
        const visitor = await db.collection('visitors').findOne({
            name,
            email
        });

        if (!visitor) {
            return res.status(404).json({
                message: 'Visitor not found'
            });
        }

        // Perform check-out actions (e.g., update the visitor status in the database)

        res.status(200).json({
            message: 'Visitor checked out successfully'
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({
            message: 'An error occurred'
        });
    }
});

/**
 * @swagger
 * /host/revoke-pass:
 *   post:
 *     summary: Revoke visitor pass
 *     tags:
 *       - Host
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               name:
 *                 type: string
 *               email:
 *                 type: string
 *     responses:
 *       '200':
 *         description: Visitor pass revoked successfully
 *         content:
 *           application/json:
 *             example:
 *               message: Visitor pass revoked successfully
 *       '401':
 *         description: Unauthorized - Requires host role
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
 *             example:
 *               message: Visitor not found
 *       '500':
 *         description: An error occurred
 *         content:
 *           application/json:
 *             example:
 *               message: An error occurred
 */
app.post('/host/revoke-pass', verifyToken, async (req, res) => {
    try {
        const decodedToken = req.decoded;
        if (decodedToken.role === 'host') {
            const {
                name,
                email
            } = req.body;

            // Find the visitor in the "visitors" collection
            const visitor = await db.collection('visitors').findOne({
                name,
                email
            });

            if (!visitor) {
                return res.status(404).json({
                    message: 'Visitor not found'
                });
            }

            // Perform pass revocation actions (e.g., remove the visitor from the database)

            res.status(200).json({
                message: 'Visitor pass revoked successfully'
            });
        } else {
            // If the user is not a host, send an unauthorized message
            res.status(401).json({ message: 'Unauthorized - Requires host role' });
        }
    } catch (error) {
        console.error(error);
        res.status(500).json({
            message: 'An error occurred'
        });
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

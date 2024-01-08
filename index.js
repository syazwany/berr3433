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

// Login for Admin
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

// Register a new Admin
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
 *     security:
 *       - bearerAuth: []
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
app.post('/admin/login', verifyToken, async (req, res) => {
    try {
        const { username, password } = req.body;

        // Find the admin user in the "admins" collection
        const adminUser = await db.collection('admins').findOne({ username });
        // Check if the user has admin role
       if (req.decoded.role !== 'admin') {
           res.status(401).json({ message: 'Unauthorized - Requires admin role' });
            return;
        }
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

/**
 * @swagger
 *  /security/login:
 *   post:
 *     summary: Security login
 *     tags:
 *       - Security
 *     description: Log in as a security entity and generate a JWT token.
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
 *     responses:
 *       '200':
 *         description: Login successful, token generated
 *         content:
 *           application/json:
 *             example:
 *               message: Login successful
 *               token: <generated_token>
 *       '401':
 *         description: Invalid username or password
 *         content:
 *           application/json:
 *             example:
 *               message: Invalid username or password
 *       '500':
 *         description: An error occurred
 *         content:
 *           application/json:
 *             example:
 *               message: An error occurred
 */
app.post('/security/login', async (req, res) => {
    try {
        const { username, password } = req.body;

        // Find the security user in the "security" collection
        const securityUser = await db.collection('security').findOne({ username });

        if (!securityUser) {
            res.status(401).json({ message: 'Invalid username or password' });
            return;
        }

        // Compare the password
        const isPasswordMatch = await bcrypt.compare(password, securityUser.password);

        if (!isPasswordMatch) {
            res.status(401).json({ message: 'Invalid username or password' });
            return;
        }

        // Generate a JSON Web Token (JWT) for the security
        const token = jwt.sign({ role: 'security', username: securityUser.username }, 'secretKey');
        console.log('Generated Token:', token);
        res.status(200).json({ message: 'Login successful', token });
    } catch (error) {
        console.error('Security Login error:', error);
        res.status(500).json({ message: 'An error occurred during login' });
    }
});

// Public API for authenticated security to retrieve host contact number from visitor pass
/**
 * @swagger
 * /security/host-contact/{passId}:
 *   get:
 *     summary: Retrieve host contact number
 *     tags:
 *       - security
 *     parameters:
 *       - name: passId
 *         in: path
 *         required: true
 *         description: ID of the visitor pass
 *         schema:
 *           type: string
 *     security:
 *       - bearerAuth: []  # Assuming you are using JWT authentication
 *     responses:
 *       '200':
 *         description: Successful retrieval of host contact number
 *         content:
 *           application/json:
 *             example:
 *               hostContact: "123-456-7890"
 *       '401':
 *         description: Unauthorized - Requires security role
 *         content:
 *           application/json:
 *             example:
 *               message: Unauthorized - Requires security role
 *       '403':
 *         description: Unauthorized - You are not the host who issued the pass
 *         content:
 *           application/json:
 *             example:
 *               message: Unauthorized - You are not the host who issued the pass
 *       '404':
 *         description: Pass not found
 *         content:
 *           application/json:
 *             example:
 *               message: Pass not found
 *       '500':
 *         description: An error occurred
 *         content:
 *           application/json:
 *             example:
 *               message: An error occurred
 * components:
 *  securitySchemes:
 *    bearerAuth:
 *      type: http
 *      scheme: bearer
 */
app.get('/security/host-contact/:passId', verifyToken, async (req, res) => {
    try {
        // Check if the user has a security role
        if (req.decoded.role !== 'security') {
            res.status(401).json({ message: 'Unauthorized - Requires security role' });
            return;
        }

        const passId = req.params.passId;

        // Retrieve the pass from the "visitors" collection
        const pass = await db.collection('visitors').findOne({ Id: passId });

        if (!pass) {
            res.status(404).json({ message: 'Pass not found' });
            return;
        }

        // Ensure that the request is made by the host who issued the pass
        if (pass.HostUsername !== req.decoded.username) {
            res.status(403).json({ message: 'Unauthorized - You are not the host who issued the pass' });
            return;
        }

        // Return host contact number or any other host information
        const hostContact = await getHostContactNumber(pass.HostUsername);
        
        res.status(200).json({ hostContact });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'An error occurred' });
    }
});

// Function to retrieve host contact number (replace with your actual implementation)
async function getHostContactNumber(HostUsername) {
    // Add your logic to retrieve host contact information from the database
    const host = await db.collection('hosts').findOne({ HostUsername: phoneNumber });
    return host.phoneNumber;
    //return "123-456-7890"; // Replace with actual implementation
}

// Public API for security to create a new host account with security approval
/**
 * @swagger
 *  /create/host:
 *   post:
 *     summary: Create a new host
 *     tags:
 *       - Host
 *     description: Create a new host account with security approval.
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
 *               username:
 *                 type: string
 *               password:
 *                 type: string
 *               email:
 *                 type: string
 *               phoneNumber:
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
 *       '409':
 *         description: Host already exists
 *         content:
 *           application/json:
 *             example:
 *               message: Host already exists
 *       '500':
 *         description: An error occurred
 *         content:
 *           application/json:
 *             example:
 *               message: An error occurred
 */
app.post('/create/host', verifyToken, async (req, res) => {
    try {
        // Check if the user has security role
        const decodedToken = req.decoded;
        if (req.decoded.role !== 'security') {
            res.status(401).json({ message: 'Unauthorized - Requires security role' });
            return;
        }

        const { name, username, password, email, phoneNumber } = req.body;

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
            email,
            phoneNumber
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
 *       - Host
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
 *               phoneNumber:
 *                 type: string
 *             required:
 *               - name
 *               - username
 *               - password
 *               - email
 *               - phoneNumber
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
        const { name, username, password, email, phoneNumber } = req.body;

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
            email,
            phoneNumber
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
       const visitors = await db.collection('visitors').find({ HostUsername: req.decoded.username }).toArray();
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
 *     summary: Issue a visitor pass
 *     tags:
 *       - Host
 *     security:
 *       - bearerAuth: [] # Assuming you are using JWT authentication
 *     requestBody:
 *       description: Visitor Pass Information
 *       required: true
 *       content:
 *        application/json:
 *           schema:
 *             type: object
 *             properties:
 *               Id:
 *                 type: string
 *                 description: ID of the visitor
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
 *               - Id
 *               - name
 *               - email
 *               - purpose
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
 * components:
 *  securitySchemes:
 *    bearerAuth:
 *      type: http
 *      scheme: bearer
 */
app.post('/host/issue-pass', verifyToken, async (req, res) => {
    try {
        // Check if the user has host role
        const decodedToken = req.decoded;
        if (req.decoded.role !== 'host') {
            res.status(401).json({ message: 'Unauthorized - Requires host role' });
            return;
        }

        const {Id, name, email, purpose } = req.body;

        // Issue the visitor pass (store only in the "visitors" collection, no separate visitor account)
        await db.collection('visitors').insertOne({
            HostUsername: req.decoded.username,
            Id,
            name,
            email,
            purpose,
        });
        
        // Generate a JSON Web Token (JWT)
        const token = jwt.sign({ role: 'visitor', username: req.decoded.username }, 'secretKey');
        console.log('Generated Token:', token);
        res.status(201).json({ message: 'Visitor pass issued successfully' , token });
       
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'An error occurred' });
    }
});

     
// Public API for visitor to retrieve their pass
/**
 * @swagger
 * /visitor/pass:
 *   get:
 *     summary: Retrieve visitor pass
 *     tags:
 *       - Visitor
 *     security:
 *       - bearerAuth: []  # Assuming you are using JWT authentication
 *     responses:
 *       '200':
 *         description: Successful retrieval of visitor pass
 *         content:
 *           application/json:
 *             example:
 *               Id: "12345"
 *               name: "John Doe"
 *               email: "john@example.com"
 *               purpose: "Meeting"
 *               HostUsername: "host123"
 *       '401':
 *         description: Unauthorized - Requires visitor role
 *         content:
 *           application/json:
 *             example:
 *               message: Unauthorized - Requires visitor role
 *       '403':
 *         description: Unauthorized - You are not the owner of this pass
 *         content:
 *           application/json:
 *             example:
 *               message: Unauthorized - You are not the owner of this pass
 *       '404':
 *         description: Pass not found
 *         content:
 *           application/json:
 *             example:
 *               message: Pass not found
 *       '500':
 *         description: An error occurred
 *         content:
 *           application/json:
 *             example:
 *               message: An error occurred
 * components:
 *  securitySchemes:
 *   bearerAuth:
 *     type: http
 *     scheme: bearer
 */
app.get('/visitor/pass', verifyToken, async (req, res) => {
    try {
        // Check if the user has a visitor role
        if (req.decoded.role !== 'visitor') {
            res.status(401).json({ message: 'Unauthorized - Requires visitor role' });
            return;
        }

        // Retrieve the pass for the authenticated visitor from the "visitors" collection
        const pass = await db.collection('visitors').findOne({ username: req.decoded.username });

        if (!pass) {
            res.status(404).json({ message: 'Pass not found' });
            return;
        }

        // Ensure that the request is made by the visitor to whom the pass belongs
        if (pass.HostUsername !== req.decoded.username) {
            res.status(403).json({ message: 'Unauthorized - You are not the owner of this pass' });
            return;
        }

        res.status(200).json(pass);
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

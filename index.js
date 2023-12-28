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
 * @swagger
 * /logout:
 *  post:
 *     summary: User Logout
 *     description: Endpoint to perform user logout operations.
 *     consumes:
 *       - application/json
 *     produces:
 *       - application/json
 *     parameters:
 *       - name: Authorization
 *         in: header
 *         description: Bearer token for authentication
 *         required: true
 *         type: string
 *     responses:
 *       200:
 *         description: Successful logout
 *         schema:
 *           type: object
 *           properties:
 *             message:
 *               type: string
 *               description: Logout successful
 *       401:
 *         description: Unauthorized
 *         schema:
 *           type: object
 *           properties:
 *             message:
 *               type: string
 *               description: Unauthorized access
 *       500:
 *         description: Internal server error
 *         schema:
 *           type: object
 *           properties:
 *             message:
 *               type: string
 *               description: An error occurred
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
 * @swagger
 * /login:
 *   post:
 *     summary: 'User Login'
 *     description: 'Endpoint for user login'
 *     consumes:
 *       - 'application/json'
 *     produces:
 *       - 'application/json'
 *     parameters:
 *       - in: body
 *         name: body
 *         description: 'User credentials for login'
 *         required: true
 *         schema:
 *           type: object
 *           properties:
 *             username:
 *               type: string
 *               description: 'User username'
 *             password:
 *               type: string
 *               description: 'User password'
 *     responses:
 *       200:
 *         description: 'Login successful'
 *         schema:
 *           type: object
 *           properties:
 *             message:
 *               type: string
 *               description: 'Login successful'
 *             token:
 *               type: string
 *               description: 'JSON Web Token (JWT) for authentication'
 *       401:
 *         description: 'Invalid password'
 *         schema:
 *           type: object
 *           properties:
 *             message:
 *               type: string
 *               description: 'Invalid password'
 *       404:
 *         description: 'User not found'
 *         schema:
 *           type: object
 *           properties:
 *             message:
 *               type: string
 *               description: 'User not found'
 *       500:
 *         description: 'Internal Server Error'
 *         schema:
 *           type: object
 *           properties:
 *             message:
 *               type: string
 *               description: 'An error occurred'
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
 * @swagger
 *  /visitors:
 *  post:
 *     summary: Create a new visitor
 *     description: Requires a valid JWT.
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               name:
 *                 type: string
 *                 description: Visitor's name
 *                 example: John Doe
 *               email:
 *                 type: string
 *                 format: email
 *                 description: Visitor's email address
 *                 example: john@example.com
 *               purpose:
 *                 type: string
 *                 description: Purpose of the visit
 *                 example: Meeting
 *             required:
 *               - name
 *               - email
 *               - purpose
 *     security:
 *       - BearerAuth: []
 *     responses:
 *       '201':
 *         description: Visitor created successfully
 *         content:
 *           application/json:
 *             example:
 *               message: Visitor created successfully
 *       '500':
 *         description: An error occurred
 *         content:
 *           application/json:
 *             example:
 *               message: An error occurred
 *components:
 *  securitySchemes:
 *   BearerAuth:
 *     type: http
 *     scheme: bearer
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
 * @swagger
 * /register:
 *   post:
 *     summary: Register a new user
 *     description: Endpoint to register a new user.
 *     produces:
 *       - application/json
 *     parameters:
 *       - name: user
 *         description: User object
 *         in: body
 *         required: true
 *         schema:
 *           type: object
 *           properties:
 *             username:
 *               type: string
 *             password:
 *               type: string
 *             email:
 *               type: string
 *             address:
 *               type: string
 *     responses:
 *       201:
 *         description: User registered successfully
 *       409:
 *         description: User already exists
 *       500:
 *         description: An error occurred
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
 * @swagger
 * /register-security:
 *   post:
 *     summary: Register a new security
 *     consumes:
 *       - application/json
 *     produces:
 *       - application/json
 *     parameters:
 *       - name: body
 *         in: body
 *         required: true
 *         schema:
 *           type: object
 *           properties:
 *             name:
 *               type: string
 *             username:
 *               type: string
 *             password:
 *               type: string
 *             email:
 *               type: string
 *           example:
 *             name: John Doe
 *             username: johndoe
 *             password: mysecretpassword
 *             email: johndoe@example.com
 *     responses:
 *       201:
 *         description: Security registered successfully
 *         schema:
 *           type: object
 *           properties:
 *             message:
 *               type: string
 *             example:
 *               message: Security registered successfully
 *       409:
 *         description: Security already exists
 *         schema:
 *           type: object
 *           properties:
 *             message:
 *               type: string
 *             example:
 *               message: Security already exists
 *       500:
 *         description: An error occurred
 *         schema:
 *           type: object
 *           properties:
 *             message:
 *               type: string
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


// Retrieve all visitors
/**
 * @swagger
 * /visitors:
 *  get:
 *    summary: Retrieve all visitors
 *     responses:
 *       '200':
 *         description: Successful response
 *         schema:
 *           type: array
 *           items:
 *             $ref: '#/definitions/Visitor'
 *       '500':
 *         description: An error occurred
 *         schema:
 *           $ref: '#/definitions/Error'
 * Visitor:
 *  type: object
 *  properties:
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
 * @swagger
 * /visitors/{id}:
 *   patch:
 *     summary: 'Update Visitor'
 *     description: 'Endpoint to update a visitor by ID'
 *     consumes:
 *       - 'application/json'
 *     produces:
 *       - 'application/json'
 *     parameters:
 *       - in: path
 *         name: id
 *         type: string
 *         required: true
 *         description: 'Visitor ID'
 *       - in: body
 *         name: body
 *         description: 'Visitor data to update'
 *         required: true
 *         schema:
 *           type: object
 *           properties:
 *             name:
 *               type: string
 *               description: 'Visitor name'
 *             email:
 *               type: string
 *               description: 'Visitor email'
 *             purpose:
 *               type: string
 *               description: 'Purpose of the visit'
 *     security:
 *       - BearerAuth: []
 *     responses:
 *       200:
 *         description: 'Visitor updated successfully'
 *         schema:
 *           type: object
 *           properties:
 *             message:
 *               type: string
 *               description: 'Visitor updated successfully'
 *       500:
 *         description: 'Internal Server Error'
 *         schema:
 *           type: object
 *           properties:
 *             message:
 *               type: string
 *               description: 'An error occurred'
 *     securityDefinitions:
 *       BearerAuth:
 *         type: apiKey
 *         name: Authorization
 8         in: header
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
 * @swagger
 * /visitors/{id}:
 *  delete:
 *     summary: 'Delete Visitor'
 *     description: 'Endpoint to delete a visitor by ID'
 *     produces:
 *       - 'application/json'
 *     parameters:
 *       - in: path
 *         name: id
 *         type: string
 *         required: true
 *         description: 'Visitor ID'
 *     security:
 *       - BearerAuth: []
 *     responses:
 *       200:
 *         description: 'Visitor deleted successfully'
 *         schema:
 *           type: object
 *           properties:
 *             message:
 *               type: string
 *               description: 'Visitor deleted successfully'
 *       500:
 *         description: 'Internal Server Error'
 *         schema:
 *           type: object
 *           properties:
 *             message:
 *               type: string
 *               description: 'An error occurred'
 *     securityDefinitions:
 *       BearerAuth:
 *         type: apiKey
 *         name: Authorization
 *         in: header
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
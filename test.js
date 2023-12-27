/*const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { MongoClient } = require('mongodb');
const swaggerUi = require('swagger-ui-express');
const swaggerJsdoc = require('swagger-jsdoc');

const app = express();
const port = process.env.PORT || 3000;


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
  apis:["./index.js"],
};
const swaggerSpec = swaggerJsdoc(option);
app.use('/api-docs', swaggerUi.server, swaggerUi.setup(swaggerSpec)); */
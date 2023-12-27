/*
// Logout for user (requires a valid JWT)
  /**
    *@swagger
    * /logout:
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
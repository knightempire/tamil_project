const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const bodyParser = require('body-parser');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const { google } = require("googleapis");
const stream = require("stream");



const app = express();
const upload = multer();

const port = 3000 || null;


app.use(cors());
app.use(express.json());
app.use(cookieParser());
app.use(express.static('public'));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

require('dotenv').config();
const {
    DB_HOST,
    DB_USER,
    DB_PASSWORD,
    DB_DATABASE,
    DB_WAIT_FOR_CONNECTIONS,
    DB_CONNECTION_LIMIT,
    DB_QUEUE_LIMIT,
    DB_PORT,
    SESSION_SECRET,
    JWT_SECRET,
    JWT_EXPIRY,
} = process.env;

const dbConfig = {
    host: DB_HOST,
    port: DB_PORT,
    user: DB_USER,
    password: DB_PASSWORD,
    database: DB_DATABASE,
    waitForConnections: DB_WAIT_FOR_CONNECTIONS === 'true', // Convert string to boolean
    connectionLimit: parseInt(DB_CONNECTION_LIMIT, 10),
    queueLimit: parseInt(DB_QUEUE_LIMIT, 10),
};



// Create a MySQL pool
const pool = mysql.createPool(dbConfig);




const KEYFILEPATH = path.join(__dirname, "cred.json");
const SCOPES = ["https://www.googleapis.com/auth/drive"];


const auth = new google.auth.GoogleAuth({
    keyFile: KEYFILEPATH,
    scopes: SCOPES,
});


const uploadFile = async(fileObject, name) => {
    const bufferStream = new stream.PassThrough();
    bufferStream.end(fileObject.buffer);

    const fileExtension = path.extname(fileObject.originalname);
    const fileName = `${name}${fileExtension}`;

    const { data } = await google.drive({ version: "v3", auth }).files.create({
        media: {
            mimeType: fileObject.mimetype,
            body: bufferStream,
        },
        requestBody: {
            name: fileName,
            parents: ["1NOS8Xy8QZq7YPPRzNLSgEhJH4NmV9vwd"], // Replace with your folder ID
        },
        fields: "id,name",
    });

    const url = `https://drive.google.com/file/d/${data.id}/view`;
    console.log(`Uploaded file ${data.name} ${data.id}`);
    console.log(`URL: ${url}`);

    return url;
};


// Session middleware configuration
app.use(session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
}));

(async() => {
    try {
        // Attempt to get a connection from the pool
        const connection = await pool.getConnection();

        // If connection successful, log a success message
        console.log('Database connected successfully');

        // Release the connection back to the pool
        connection.release();
    } catch (error) {
        // Log an error message if connection fails
        console.error('Error connecting to the database:', error);
        process.exit(1); // Terminate the application process
    }
})();








app.get('/test', (req, res) => {
    res.status(200).json({ message: "Welcome Tamil students" });
});



//port
app.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`);
}).on('error', (err) => {
    console.error('Server start error:', err);
});
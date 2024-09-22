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




// Route for user registration
app.post('/api/register', async(req, res) => {
    // Get and convert username to lowercase
    const { username, password } = req.body;
    const normalizedUsername = username.toLowerCase(); // Convert username to lowercase

    try {
        console.log('API registration requested');

        // Check if the username already exists (case-insensitive check)
        const [existingUser] = await pool.execute('SELECT * FROM login WHERE username = ?', [normalizedUsername]);
        if (existingUser.length > 0) {
            console.log('User with the same username already exists');
            return res.status(400).json({ error: 'User with the same username already exists' });
        }

        // Hash the password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Insert new user into the login table
        const loginResult = await pool.execute('INSERT INTO login (username, password, is_active) VALUES (?, ?, ?)', [normalizedUsername, hashedPassword, 1]);

        // Send response
        res.json({ success: true, message: 'User registered successfully' });
    } catch (error) {
        console.error('Error during registration:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});



// Route for creating Level 1 entry
app.post('/api/level1', async(req, res) => {
    const { name, description, img } = req.body;

    try {
        console.log('API Level 1 creation requested');

        // Validate the request body
        if (!name) {
            return res.status(400).json({ error: 'Name is required' });
        }

        // Insert new entry into the level1 table
        const result = await pool.execute(
            'INSERT INTO level1 (name, description, img) VALUES (?, ?, ?)', [name, description || null, img || null] // Use null if description or img is not provided
        );

        // Send response
        res.json({ success: true, message: 'Level 1 entry created successfully', id: result.insertId });
    } catch (error) {
        console.error('Error during Level 1 creation:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});


// Route for creating Level 2 entry
app.post('/api/level2', async(req, res) => {
    const { p_id, name, description, img } = req.body;

    try {
        console.log('API Level 2 creation requested');

        // Validate the request body
        if (!p_id || !name) {
            return res.status(400).json({ error: 'p_id and name are required' });
        }

        // Insert new entry into the level2 table
        const result = await pool.execute(
            'INSERT INTO level2 (p_id, name, description, img) VALUES (?, ?, ?, ?)', [p_id, name, description || null, img || null] // Use null if description or img is not provided
        );

        // Send response
        res.json({ success: true, message: 'Level 2 entry created successfully', id: result.insertId });
    } catch (error) {
        console.error('Error during Level 2 creation:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});



// Route for creating Level 3 entry
app.post('/api/level3', async(req, res) => {
    const { p_id, name, description, img } = req.body;

    try {
        console.log('API Level 3 creation requested');

        if (!p_id || !name) {
            return res.status(400).json({ error: 'p_id and name are required' });
        }

        const result = await pool.execute(
            'INSERT INTO level3 (p_id, name, description, img) VALUES (?, ?, ?, ?)', [p_id, name, description || null, img || null]
        );

        res.json({ success: true, message: 'Level 3 entry created successfully', id: result.insertId });
    } catch (error) {
        console.error('Error during Level 3 creation:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});



// Route for creating Level 4 entry
app.post('/api/level4', async(req, res) => {
    const { p_id, name, description, img } = req.body;

    try {
        console.log('API Level 4 creation requested');

        if (!p_id || !name) {
            return res.status(400).json({ error: 'p_id and name are required' });
        }

        const result = await pool.execute(
            'INSERT INTO level4 (p_id, name, description, img) VALUES (?, ?, ?, ?)', [p_id, name, description || null, img || null]
        );

        res.json({ success: true, message: 'Level 4 entry created successfully', id: result.insertId });
    } catch (error) {
        console.error('Error during Level 4 creation:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});


// Route for creating Level 5 entry
app.post('/api/level5', async(req, res) => {
    const { p_id, name, description, img } = req.body;

    try {
        console.log('API Level 5 creation requested');

        if (!p_id || !name) {
            return res.status(400).json({ error: 'p_id and name are required' });
        }

        const result = await pool.execute(
            'INSERT INTO level5 (p_id, name, description, img) VALUES (?, ?, ?, ?)', [p_id, name, description || null, img || null]
        );

        res.json({ success: true, message: 'Level 5 entry created successfully', id: result.insertId });
    } catch (error) {
        console.error('Error during Level 5 creation:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});


// Route for creating Level 6 entry
app.post('/api/level6', async(req, res) => {
    const { p_id, name, description, img } = req.body;

    try {
        console.log('API Level 6 creation requested');

        if (!p_id || !name) {
            return res.status(400).json({ error: 'p_id and name are required' });
        }

        const result = await pool.execute(
            'INSERT INTO level6 (p_id, name, description, img) VALUES (?, ?, ?, ?)', [p_id, name, description || null, img || null]
        );

        res.json({ success: true, message: 'Level 6 entry created successfully', id: result.insertId });
    } catch (error) {
        console.error('Error during Level 6 creation:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});


// Route for creating Level 7 entry
app.post('/api/level7', async(req, res) => {
    const { p_id, name, description, img } = req.body;

    try {
        console.log('API Level 7 creation requested');

        if (!p_id || !name) {
            return res.status(400).json({ error: 'p_id and name are required' });
        }

        const result = await pool.execute(
            'INSERT INTO level7 (p_id, name, description, img) VALUES (?, ?, ?, ?)', [p_id, name, description || null, img || null]
        );

        res.json({ success: true, message: 'Level 7 entry created successfully', id: result.insertId });
    } catch (error) {
        console.error('Error during Level 7 creation:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});


// Route for creating Level 8 entry
app.post('/api/level8', async(req, res) => {
    const { p_id, name, description, img } = req.body;

    try {
        console.log('API Level 8 creation requested');

        if (!p_id || !name) {
            return res.status(400).json({ error: 'p_id and name are required' });
        }

        const result = await pool.execute(
            'INSERT INTO level8 (p_id, name, description, img) VALUES (?, ?, ?, ?)', [p_id, name, description || null, img || null]
        );

        res.json({ success: true, message: 'Level 8 entry created successfully', id: result.insertId });
    } catch (error) {
        console.error('Error during Level 8 creation:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});



// Route for creating Level 9 entry
app.post('/api/level9', async(req, res) => {
    const { p_id, name, description, img } = req.body;

    try {
        console.log('API Level 9 creation requested');

        if (!p_id || !name) {
            return res.status(400).json({ error: 'p_id and name are required' });
        }

        const result = await pool.execute(
            'INSERT INTO level9 (p_id, name, description, img) VALUES (?, ?, ?, ?)', [p_id, name, description || null, img || null]
        );

        res.json({ success: true, message: 'Level 9 entry created successfully', id: result.insertId });
    } catch (error) {
        console.error('Error during Level 9 creation:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});


// Route for creating Level 10 entry
app.post('/api/level10', async(req, res) => {
    const { p_id, name, description, img } = req.body;

    try {
        console.log('API Level 10 creation requested');

        if (!p_id || !name) {
            return res.status(400).json({ error: 'p_id and name are required' });
        }

        const result = await pool.execute(
            'INSERT INTO level10 (p_id, name, description, img) VALUES (?, ?, ?, ?)', [p_id, name, description || null, img || null]
        );

        res.json({ success: true, message: 'Level 10 entry created successfully', id: result.insertId });
    } catch (error) {
        console.error('Error during Level 10 creation:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});




app.get('/test', (req, res) => {
    res.status(200).json({ message: "Welcome Tamil students" });
});



//port
app.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`);
}).on('error', (err) => {
    console.error('Server start error:', err);
});
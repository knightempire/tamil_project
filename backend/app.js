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

const port = 3002 || null;


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


const createtoken = (req, res, rows) => {
    const username = rows[0].username; // Get username from the returned rows
    const token = jwt.sign({ username: username }, JWT_SECRET, {
        expiresIn: JWT_EXPIRY,
    });
    req.session.jwtToken = token;

    // Return the token
    return token;
};


const authenticateToken = (req, res, next) => {
    try {

        if (!req.headers.authorization) {
            return res.redirect('#');
        }

        const token = req.headers.authorization.split(' ')[1];

        jwt.verify(token, JWT_SECRET, (err, decoded) => {
            if (err) {
                console.error('Authentication error:', err.message);

                return res.status(401).json({ error: 'Unauthorized' });
            } else {
                req.user = decoded;
                next();
            }
        });
    } catch (err) {
        console.error('Error in authentication middleware:', err.message);
        res.status(500).send('Internal Server Error');
    }
};


app.post('/api/decodeToken', [authenticateToken, async(req, res) => {
    console.log('API decode requested');
    try {
        const { token } = req.body;

        const decodedToken = jwt.verify(token, JWT_SECRET);

        const { username } = decodedToken; // Get username from the decoded token

        if (!username) {
            return res.status(400).json({ error: 'username not found in token' });
        }

        const connection = await pool.getConnection();

        try {
            // Use the specified query to retrieve username and u_id
            const [rows] = await connection.execute(
                'SELECT username, u_id FROM login WHERE username = ?', [username]
            );

            if (rows.length === 0) {
                return res.status(404).json({ error: 'User not found' });
            }

            const userData = rows[0];

            // Send response with username and u_id
            res.status(200).json(userData);
        } catch (error) {
            console.error('Error querying database:', error.message);
            res.status(500).json({ error: 'Internal server error' });
        } finally {
            connection.release();
        }
    } catch (error) {
        console.error('Error decoding token:', error.message);
        res.status(400).json({ error: 'Failed to decode token' });
    }
}]);



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



// Route for login
app.post('/api/login', async(req, res) => {
    const { username, password } = req.body;

    try {
        console.log('API login requested');

        // Query the database to check if the provided username exists in the login table
        const [existingUser] = await pool.execute('SELECT * FROM login WHERE username = ?', [username]);

        if (existingUser.length === 0) {
            // If the username doesn't exist in the login table, return an error
            console.log("No user found");
            return res.status(400).json({ error: 'Invalid username' });
        }

        // Verify the password
        const isPasswordValid = await bcrypt.compare(password, existingUser[0].password);

        if (!isPasswordValid) {
            // If the password is incorrect, return an error
            console.log("Invalid password");
            return res.status(400).json({ error: 'Invalid password' });
        }

        // Call function to create token
        const token = createtoken(req, res, existingUser);
        console.log("Token:", token);

        // Send response
        res.json({ isValid: true, token });
    } catch (error) {
        console.error('Error during login:', error);
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



// Route for retrieving all Level 1 entries
app.get('/api/dislevel1', async(req, res) => {
    try {
        console.log('API Level 1 retrieval requested');

        // Query to get all Level 1 entries
        const [rows] = await pool.execute('SELECT * FROM level1');

        // Send response with Level 1 entries
        res.json({ success: true, data: rows });
    } catch (error) {
        console.error('Error during Level 1 retrieval:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});


// Route for retrieving Level 2 entries based on a provided ID
app.post('/api/dislevel2', async(req, res) => {
    await retrieveLevel(req, res, 'level2');
});

// Route for retrieving Level 3 entries based on a provided ID
app.post('/api/dislevel3', async(req, res) => {
    await retrieveLevel(req, res, 'level3');
});

// Route for retrieving Level 4 entries based on a provided ID
app.post('/api/dislevel4', async(req, res) => {
    await retrieveLevel(req, res, 'level4');
});

// Route for retrieving Level 5 entries based on a provided ID
app.post('/api/dislevel5', async(req, res) => {
    await retrieveLevel(req, res, 'level5');
});

// Route for retrieving Level 6 entries based on a provided ID
app.post('/api/dislevel6', async(req, res) => {
    await retrieveLevel(req, res, 'level6');
});

// Route for retrieving Level 7 entries based on a provided ID
app.post('/api/dislevel7', async(req, res) => {
    await retrieveLevel(req, res, 'level7');
});

// Route for retrieving Level 8 entries based on a provided ID
app.post('/api/dislevel8', async(req, res) => {
    await retrieveLevel(req, res, 'level8');
});

// Route for retrieving Level 9 entries based on a provided ID
app.post('/api/dislevel9', async(req, res) => {
    await retrieveLevel(req, res, 'level9');
});

// Route for retrieving Level 10 entries based on a provided ID
app.post('/api/dislevel10', async(req, res) => {
    await retrieveLevel(req, res, 'level10');
});

// Helper function to retrieve entries from specified level
async function retrieveLevel(req, res, level) {
    try {
        console.log(`API ${level.charAt(0).toUpperCase() + level.slice(1)} retrieval requested`);

        // Get the id from the request body
        const { id } = req.body;

        // Check if id is provided
        if (!id) {
            return res.status(400).json({ error: 'ID is required' });
        }

        // Query to get entries from the specified level where p_id matches the provided id
        const [rows] = await pool.execute(`SELECT * FROM ${level} WHERE p_id = ?`, [id]);

        // Send response with entries from the specified level
        res.json({ success: true, data: rows });
    } catch (error) {
        console.error(`Error during ${level.charAt(0).toUpperCase() + level.slice(1)} retrieval:`, error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
}



app.get('/test', (req, res) => {
    res.status(200).json({ message: "Welcome Tamil students" });
});


app.get('/', (req, res) => {
    res.status(200).json({ message: "ப்ரோ ஐஸ் குக்கிங்" });
});


//port
app.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`);
}).on('error', (err) => {
    console.error('Server start error:', err);
});
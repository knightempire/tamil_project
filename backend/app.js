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




//function to create token
const createtoken = (req, res, rows) => {

    const roll_no = rows[0].roll_no;
    const token = jwt.sign({ roll_no: roll_no }, JWT_SECRET, {
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
    console.log('api decode requested');
    try {

        const { token } = req.body;


        const decodedToken = jwt.verify(token, JWT_SECRET);

        const { roll_no } = decodedToken;

        if (!roll_no) {
            return res.status(400).json({ error: 'roll_no not found in token' });
        }


        const connection = await pool.getConnection();

        try {

            const [rows] = await connection.execute('SELECT l.roll_no, l.is_active, l.role_id, l.spl_role, p.name FROM login l LEFT JOIN profile p ON l.roll_no = p.roll_no WHERE l.roll_no = ?', [roll_no]);


            if (rows.length === 0) {
                return res.status(404).json({ error: 'User not found' });
            }


            const userData = rows[0];

            userData.profile = rows[0].name && rows[0].name !== 'Unknown' ? 1 : 0;
            console.log(userData.profile)


            userData.name = rows[0].name || 'User';

            console.log('decoded token');

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


// Route for login
app.post('/api/login', async(req, res) => {
    const { roll_no, password } = req.body;

    try {
        console.log('API login requested');

        // Query the database to check if the provided roll number exists in the login table
        const [existingUser] = await pool.execute('SELECT * FROM login WHERE roll_no = ?', [roll_no]);

        if (existingUser.length === 0) {
            // If the roll number doesn't exist in the login table, return an error
            console.log("No user found");
            return res.status(400).json({ error: 'Invalid roll number' });
        }

        // Verify the password
        const isPasswordValid = await bcrypt.compare(password, existingUser[0].password);

        if (!isPasswordValid) {
            // If the password is incorrect, return an error
            console.log("Invalid password");
            return res.status(400).json({ error: 'Invalid password' });
        }

        // Check if the user is active
        const isActive = existingUser[0].is_active;

        if (isActive === 0) {
            // If the user is not active, return a message
            console.log("User is no longer active");
            return res.status(400).json({ error: 'You are no longer an active user' });
        }

        // Assuming you want to retrieve role_id from existingUser
        const { role_id } = existingUser[0];

        // Check if the roll number exists in the profile table
        const [existingProfile] = await pool.execute('SELECT * FROM profile WHERE roll_no = ?', [roll_no]);
        let profileExists = 0;

        console.log(existingProfile)
        if (existingProfile.length > 0) {
            // If the roll number exists in the profile table, set profileExists to 1
            const profileData = existingProfile[0];
            if (profileData.name && profileData.name !== "Unknown") {
                profileExists = 1;
            }
        }

        // Call function to create token
        const token = createtoken(req, res, existingUser);
        console.log("Token:", token);

        // Send response
        res.json({ isValid: true, profile: profileExists, token, role_id });
    } catch (error) {
        console.error('Error during login:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});




// Route for user registration
app.post('/api/register', [authenticateToken, async(req, res) => {
    const { roll_no, date, role_id, sport_id, year, gender } = req.body;
    try {
        console.log('API registration requested');
        // Check if the roll number already exists (case-insensitive check)
        const [existingUser] = await pool.execute('SELECT * FROM login WHERE LOWER(roll_no) = LOWER(?)', [roll_no]);
        // Check if any rows were returned
        if (existingUser.length > 0) {
            console.log('User with the same roll number already exists');
            return res.status(400).json({ error: 'User with the same roll number already exists' });
        }
        // Set password to roll_nNo
        const password = roll_no;
        // Hash the password
        const hashedPassword = await bcrypt.hash(password, 10);
        // Insert new user into the login table
        const loginResult = await pool.execute('INSERT INTO login (roll_no, password, is_active, date, role_id) VALUES (?, ?, ?, ?, ?)', [roll_no, hashedPassword, 1, date, role_id]);
        // Insert sport_id and year into the profile table
        const profileResult = await pool.execute('INSERT INTO profile (roll_no, sport_id, year,gender) VALUES (?, ?, ?, ?)', [roll_no, sport_id, year, gender]);
        // Send response
        res.json({ success: true, message: 'User registered successfully' });
    } catch (error) {
        console.error('Error during registration:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
}]);




app.get('/test', (req, res) => {
    res.status(200).json({ message: "Welcome Tamil students" });
});



//port
app.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`);
}).on('error', (err) => {
    console.error('Server start error:', err);
});
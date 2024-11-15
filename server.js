var express = require('express')
var bodyParser = require('body-parser')
var app = express()
var http = require('http').Server(app)
var io = require('socket.io')(http)
var mysql = require('mysql2')
const path = require('path')
const bcryptjs = require('bcryptjs')
const session = require('express-session')
const fs = require('fs')
const multer = require('multer')
const port = 3000

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));



// Add session middleware
app.use(session({
    secret: 'your-secret-key',
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false } // set to true if using https
}));

// Database connection
const connection = mysql.createConnection({
    host: 'localhost',
    port: 3306,
    user: 'root',
    password: '',
    database: 'itxt'
});

connection.connect((err) => {
    if (err) {
        console.error('Error connecting to database:', err);
        return;
    }
    console.log('Connected to database');
    createTables();
});

function createTables() {
    // Users table
    const createUsersTable = `
    CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(255) NOT NULL UNIQUE,
        email VARCHAR(255) NOT NULL UNIQUE,
        password VARCHAR(255) NOT NULL,
        profile_picture VARCHAR(255),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )`;
    const createMessagesTable = `
        CREATE TABLE IF NOT EXISTS messages (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT,
            message TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            INDEX idx_created_at (created_at)
        )`;

        // Add videos table
    const createVideosTable = `
        CREATE TABLE IF NOT EXISTS videos (
            id INT AUTO_INCREMENT PRIMARY KEY,
            title VARCHAR(255) NOT NULL,
            description TEXT,
            filename VARCHAR(255) NOT NULL,
            thumbnail VARCHAR(255),
            duration VARCHAR(10),
            user_id INT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )`;

    connection.query(createUsersTable, (err) => {
        if (err) {
            console.error('Error creating users table:', err);
            return;
        }
        console.log('Users table created or already exists');

        connection.query(createMessagesTable, (err) => {
            if (err) {
                console.error('Error creating messages table:', err);
                return;
            }
            console.log('Messages table created or already exists');
        });
    
    });
}

// Authentication middleware
const requireLogin = (req, res, next) => {
    if (req.session.userId) {
        next();
    } else {
        res.redirect('/login');
    }
};

app.get(['/', '/login'], (req, res) => {
    const loginPath = path.join(__dirname, 'public', 'login.html');
    
    // Add this check
    if (!fs.existsSync(loginPath)) {
        console.error(`File not found at ${loginPath}`);
        return res.status(404).send('Login page not found');
    }

    if (req.session.userId) {
        res.redirect('/messages-view');
    } else {
        res.sendFile(loginPath, (err) => {
            if (err) {
                console.error('Error sending file:', err);
                res.status(500).send('Error loading login page');
            } else {
                console.log('Login file sent successfully');
            }
        });
    }
});

app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/login');
});


app.get('/register', (req, res) => {
    if (req.session.userId) {
        res.redirect('/messages-view');
    } else {
        res.sendFile(__dirname + '/public' + '/register.html');
    }
});

// Add this to your server.js
app.get('/api/user', requireLogin, (req, res) => {
    res.json({
        username: req.session.username
    });
});
// In server.js, update these lines
app.use(express.static(path.join(__dirname, '/public')));

app.get('/profile', requireLogin, (req, res) => {
    res.sendFile(path.join(__dirname, '/public', '/profile.html'));
});

app.get('/settings', requireLogin, (req, res) => {
    res.sendFile(path.join(__dirname, '/public', '/settings.html'));
});


app.get('/ping', requireLogin, (req, res) => {
    res.sendFile(path.join(__dirname, '/public', '/ping.html'));
});

// API routes
app.get('/api/user/stats', requireLogin, async (req, res) => {
    try {
        const userId = req.session.userId;
        
        // Get message count
        const [messageCount] = await connection.query(
            'SELECT COUNT(*) as count FROM messages WHERE user_id = ?',
            [userId]
        );

        // Calculate days active (from user creation date)
        const [user] = await connection.query(
            'SELECT DATEDIFF(NOW(), created_at) as days FROM users WHERE id = ?',
            [userId]
        );

        res.json({
            messageCount: messageCount[0].count,
            daysActive: user[0].days || 0
        });
    } catch (error) {
        console.error('Error fetching user stats:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.post('/api/user/update', requireLogin, async (req, res) => {
    try {
        const { username, email, bio } = req.body;
        const userId = req.session.userId;

        // Check if username or email already exists
        const [existing] = await connection.query(
            'SELECT id FROM users WHERE (username = ? OR email = ?) AND id != ?',
            [username, email, userId]
        );

        if (existing.length > 0) {
            return res.status(400).json({ error: 'Username or email already exists' });
        }

        await connection.query(
            'UPDATE users SET username = ?, email = ?, bio = ? WHERE id = ?',
            [username, email, bio || null, userId]
        );

        res.json({ message: 'Profile updated successfully' });
    } catch (error) {
        console.error('Error updating profile:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.post('/api/user/password', requireLogin, async (req, res) => {
    try {
        const { currentPassword, newPassword } = req.body;
        const userId = req.session.userId;

        // Verify current password
        const [user] = await connection.query(
            'SELECT password FROM users WHERE id = ?',
            [userId]
        );

        const isValid = await bcrypt.compare(currentPassword, user[0].password);
        if (!isValid) {
            return res.status(400).json({ error: 'Current password is incorrect' });
        }

        // Hash new password
        const hashedPassword = await bcrypt.hash(newPassword, 10);

        // Update password
        await connection.query(
            'UPDATE users SET password = ? WHERE id = ?',
            [hashedPassword, userId]
        );

        res.json({ message: 'Password updated successfully' });
    } catch (error) {
        console.error('Error updating password:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Add settings table to your database
const createSettingsTable = `
    CREATE TABLE IF NOT EXISTS user_settings (
        user_id INT PRIMARY KEY,
        email_notifications BOOLEAN DEFAULT true,
        sound_notifications BOOLEAN DEFAULT true,
        show_online_status BOOLEAN DEFAULT true,
        show_read_receipts BOOLEAN DEFAULT true,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )
`;

    const createVideosTable = `
        CREATE TABLE IF NOT EXISTS videos (
            id INT AUTO_INCREMENT PRIMARY KEY,
            title VARCHAR(255) NOT NULL,
            description TEXT,
            filename VARCHAR(255) NOT NULL,
            thumbnail VARCHAR(255),
            duration VARCHAR(10),
            user_id INT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )`
        

connection.query(createSettingsTable);

app.get('/api/user/settings', requireLogin, async (req, res) => {
    try {
        const userId = req.session.userId;
        
        const [settings] = await connection.query(
            'SELECT * FROM user_settings WHERE user_id = ?',
            [userId]
        );

        if (settings.length === 0) {
            // Create default settings if none exist
            await connection.query(
                'INSERT INTO user_settings (user_id) VALUES (?)',
                [userId]
            );
            
            res.json({
                emailNotifications: true,
                soundNotifications: true,
                showOnlineStatus: true,
                showReadReceipts: true
            });
        } else {
            res.json({
                emailNotifications: settings[0].email_notifications,
                soundNotifications: settings[0].sound_notifications,
                showOnlineStatus: settings[0].show_online_status,
                showReadReceipts: settings[0].show_read_receipts
            });
        }
    } catch (error) {
        console.error('Error fetching settings:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.post('/api/user/settings', requireLogin, async (req, res) => {
    try {
        const userId = req.session.userId;
        const updates = [];
        const values = [];

        // Map frontend names to database columns
        const settingsMap = {
            emailNotifications: 'email_notifications',
            soundNotifications: 'sound_notifications',
            onlineStatus: 'show_online_status',
            readReceipts: 'show_read_receipts'
        };

        Object.entries(req.body).forEach(([key, value]) => {
            const dbColumn = settingsMap[key];
            if (dbColumn) {
                updates.push(`${dbColumn} = ?`);
                values.push(value);
            }
        });

        if (updates.length > 0) {
            values.push(userId);
            await connection.query(
                `UPDATE user_settings SET ${updates.join(', ')} WHERE user_id = ?`,
                values
            );
        }

        res.json({ message: 'Settings updated successfully' });
    } catch (error) {
        console.error('Error updating settings:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.get('/register', (req, res) => {
    if (req.session.userId) {
        res.redirect('/messages-view');
    } else {
        res.sendFile(path.join(__dirname, '/public', 'register.html'));
    }
});

app.get('/messages-view', requireLogin, (req, res) => {
    res.sendFile(path.join(__dirname, '/public', 'message.html'));
});

// Updated the registration endpoint
app.post('/register', async (req, res) => {
    try {
        const { username, email, password } = req.body;

        // Validate input
        if (!username || !email || !password) {
            return res.status(400).json({ error: 'Username, email, and password are required' });
        }

        if (username.length < 3) {
            return res.status(400).json({ error: 'Username must be at least 3 characters long' });
        }

        if (password.length < 6) {
            return res.status(400).json({ error: 'Password must be at least 6 characters long' });
        }

        // Validate email format
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            return res.status(400).json({ error: 'Invalid email format' });
        }

        // Hash password
        const hashedPassword = await bcryptjs.hash(password, 10);
        
        // Insert new user
        const query = 'INSERT INTO users (username, email, password) VALUES (?, ?, ?)';
        connection.query(query, [username, email, hashedPassword], (err, results) => {
            if (err) {
                if (err.code === 'ER_DUP_ENTRY') {
                    if (err.message.includes('username')) {
                        return res.status(400).json({ error: 'Username already exists' });
                    }
                    if (err.message.includes('email')) {
                        return res.status(400).json({ error: 'Email already registered' });
                    }
                    return res.status(400).json({ error: 'User already exists' });
                }
                console.error('Registration error:', err);
                return res.status(500).json({ error: 'Error creating user' });
            }
            res.json({ message: 'Registration successful' });
        });
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ error: 'Error creating user' });
    }
});

// Login endpoint
app.post('/login', async (req, res) => {
    try {
        const { username, password } = req.body;

        // Validate input
        if (!username || !password) {
            return res.status(400).json({ error: 'Username and password are required' });
        }

        // Check user exists
        const query = 'SELECT * FROM users WHERE username = ?';
        connection.query(query, [username], async (err, results) => {
            if (err) {
                console.error('Login error:', err);
                return res.status(500).json({ error: 'Error during login' });
            }
            
            if (results.length === 0) {
                return res.status(401).json({ error: 'Invalid credentials' });
            }

            const user = results[0];
            const validPassword = await bcryptjs.compare(password, user.password);
            
            if (!validPassword) {
                return res.status(401).json({ error: 'Invalid credentials' });
            }

            // Set session
            req.session.userId = user.id;
            req.session.username = user.username;
            res.json({ message: 'Login successful' });
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Error during login' });
    }
});

// Logout endpoint
app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/login');
});

// Protected routes
app.get('/messages-view', requireLogin, (req, res) => {
    res.sendFile(__dirname + '/public' + '/message.html');
});

// Get messages
app.get('/messages', requireLogin, (req, res) => {
    const query = `
        SELECT 
            m.id,
            m.message,
            m.created_at,
            u.username as name,
            DATE_FORMAT(m.created_at, '%Y-%m-%d %H:%i:%s') as timestamp
        FROM messages m
        JOIN users u ON m.user_id = u.id
        ORDER BY m.created_at ASC
    `;

    connection.query(query, (err, results) => {
        if (err) {
            console.error('Error fetching messages:', err);
            return res.status(500).json({ error: 'Error fetching messages' });
        }
        res.json(results);
    });
});

// Post message
app.post('/messages', requireLogin, async (req, res) => {
    const newMessage = {
        user_id: req.session.userId,
        message: req.body.message,
        created_at: new Date()
    };

    try {
        // Check for bad words
        const badWords = ['insult'];
        const messageText = newMessage.message.toLowerCase();
        const hasBadWord = badWords.some(word => messageText.includes(word));

        if (hasBadWord) {
            return res.status(400).json({ error: 'Message contains inappropriate content' });
        }

        // Insert message
        connection.query('INSERT INTO messages SET ?', newMessage, (err, result) => {
            if (err) {
                console.error('Error saving message:', err);
                return res.status(500).json({ error: 'Error saving message' });
            }

            // Get inserted message with user info
            const query = `
                SELECT 
                    m.id,
                    m.message,
                    m.created_at,
                    u.username as name,
                    DATE_FORMAT(m.created_at, '%Y-%m-%d %H:%i:%s') as timestamp
                FROM messages m
                JOIN users u ON m.user_id = u.id
                WHERE m.id = ?
            `;

            connection.query(query, [result.insertId], (err, results) => {
                if (err) {
                    console.error('Error fetching saved message:', err);
                    return res.status(500).json({ error: 'Error fetching saved message' });
                }

                const savedMessage = results[0];
                io.emit('message', savedMessage);
                res.json(savedMessage);
            });
        });
    } catch (error) {
        console.error('Error processing message:', error);
        res.status(500).json({ error: 'Error processing message' });
    }
});

// Configure multer for file upload
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, 'public/uploads/profile-pictures')
    },
    filename: function (req, file, cb) {
        cb(null, `user-${req.session.userId}-${Date.now()}${path.extname(file.originalname)}`)
    }
});

const upload = multer({
    storage: storage,
    limits: {
        fileSize: 5 * 1024 * 1024 // 5MB limit
    },
    fileFilter: function (req, file, cb) {
        if (!file.originalname.match(/\.(jpg|jpeg|png|gif)$/)) {
            return cb(new Error('Only image files are allowed!'));
        }
        cb(null, true);
    }
});

// Add these routes to your server
app.post('/api/user/profile-picture', upload.single('profilePicture'), (req, res) => {
    if (!req.file) {
        return res.status(400).json({ error: 'No file uploaded' });
    }

    const imageUrl = `/uploads/profile-pictures/${req.file.filename}`;
    
    // Update user's profile picture in database
    connection.query(
        'UPDATE users SET profile_picture = ? WHERE id = ?',
        [imageUrl, req.session.userId],
        (err) => {
            if (err) {
                console.error(err);
                return res.status(500).json({ error: 'Database error' });
            }
            res.json({ url: imageUrl });
        }
    );
});

app.delete('/api/user/profile-picture', (req, res) => {
    connection.query(
        'UPDATE users SET profile_picture = NULL WHERE id = ?',
        [req.session.userId],
        (err) => {
            if (err) {
                console.error(err);
                return res.status(500).json({ error: 'Database error' });
            }
            res.json({ success: true });
        }
    );
});

// Edit message
app.put('/api/messages/:id', requireLogin, async (req, res) => {
    const messageId = req.params.id;
    const newMessage = req.body.message;
    const userId = req.session.userId;

    try {
        // First check if the message belongs to the user
        const [message] = await connection.query(
            'SELECT * FROM messages WHERE id = ? AND user_id = ?',
            [messageId, userId]
        );

        if (message.length === 0) {
            return res.status(403).json({ error: 'Not authorized to edit this message' });
        }

        // Update the message
        await connection.query(
            'UPDATE messages SET message = ? WHERE id = ?',
            [newMessage, messageId]
        );

        res.json({ success: true });
    } catch (error) {
        console.error('Error updating message:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Delete message
app.delete('/api/messages/:id', requireLogin, async (req, res) => {
    const messageId = req.params.id;
    const userId = req.session.userId;

    try {
        // First check if the message belongs to the user
        const [message] = await connection.query(
            'SELECT * FROM messages WHERE id = ? AND user_id = ?',
            [messageId, userId]
        );

        if (message.length === 0) {
            return res.status(403).json({ error: 'Not authorized to delete this message' });
        }

        // Delete the message
        await connection.query(
            'DELETE FROM messages WHERE id = ?',
            [messageId]
        );

        res.json({ success: true });
    } catch (error) {
        console.error('Error deleting message:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});


// Socket.io handling
let connectedUsers = new Map();

io.on('connection', (socket) => {
    socket.on('user connected', (username) => {
        connectedUsers.set(socket.id, username);
        io.emit('user count', connectedUsers.size);
        io.emit('active users', Array.from(connectedUsers.values()));
    });

    socket.on('disconnect', () => {
        connectedUsers.delete(socket.id);
        io.emit('user count', connectedUsers.size);
        io.emit('active users', Array.from(connectedUsers.values()));
    });

    socket.on('typing', (user) => {
        socket.broadcast.emit('typing', user);
    });

    socket.on('stop typing', () => {
        socket.broadcast.emit('stop typing');
    });
});

// Start server
var server = http.listen(port, () => {
    console.log('Server is listening on port', server.address().port)
});

// Routes
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});


// Configure multer for video uploads
const videoStorage = multer.diskStorage({
    destination: function (req, file, cb) {
        const dir = path.join(__dirname, 'public', 'videos');
        // Create the videos directory if it doesn't exist
        if (!fs.existsSync(dir)) {
            fs.mkdirSync(dir, { recursive: true });
        }
        cb(null, dir);
    },
    filename: function (req, file, cb) {
        // Generate unique filename with timestamp
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, uniqueSuffix + path.extname(file.originalname));
    }
});

// Create multer upload instance
const videoUpload = multer({
    storage: videoStorage,
    limits: {
        fileSize: 100 * 1024 * 1024, // 100MB file size limit
    },
    fileFilter: (req, file, cb) => {
        // Accept only video files
        if (file.mimetype.startsWith('video/')) {
            cb(null, true);
        } else {
            cb(new Error('Only video files are allowed!'), false);
        }
    }
});

// Add these routes for video handling
app.post('/api/upload', requireLogin, videoUpload.single('video'), (req, res) => {
    if (!req.file) {
        return res.status(400).json({ error: 'No video file uploaded' });
    }

    const videoData = {
        title: req.body.title || 'Untitled Video',
        description: req.body.description || '',
        filename: req.file.filename,
        user_id: req.session.userId
    };

    connection.query('INSERT INTO videos SET ?', videoData, (err, result) => {
        if (err) {
            console.error('Error uploading video:', err);
            return res.status(500).json({ error: 'Error uploading video' });
        }
        res.status(201).json({
            ...videoData,
            id: result.insertId
        });
    });
});

app.get('/api/videos', requireLogin, (req, res) => {
    connection.query('SELECT * FROM videos ORDER BY created_at DESC', (err, results) => {
        if (err) {
            console.error('Error fetching videos:', err);
            return res.status(500).json({ error: 'Error fetching videos' });
        }
        res.json(results);
    });
});

app.get('/api/video/:filename', requireLogin, (req, res) => {
    const videoPath = path.join(__dirname, 'public', 'videos', req.params.filename);
    
    if (!fs.existsSync(videoPath)) {
        return res.status(404).send('Video not found');
    }

    const stat = fs.statSync(videoPath);
    const fileSize = stat.size;
    const range = req.headers.range;

    if (range) {
        const parts = range.replace(/bytes=/, "").split("-");
        const start = parseInt(parts[0], 10);
        const end = parts[1] ? parseInt(parts[1], 10) : fileSize - 1;
        const chunksize = (end - start) + 1;
        const file = fs.createReadStream(videoPath, { start, end });
        const head = {
            'Content-Range': `bytes ${start}-${end}/${fileSize}`,
            'Accept-Ranges': 'bytes',
            'Content-Length': chunksize,
            'Content-Type': 'video/mp4',
        };
        res.writeHead(206, head);
        file.pipe(res);
    } else {
        const head = {
            'Content-Length': fileSize,
            'Content-Type': 'video/mp4',
        };
        res.writeHead(200, head);
        fs.createReadStream(videoPath).pipe(res);
    }
});


process.on('SIGINT', () => {
    connection.end((err) => {
        if (err) {
            console.error('Error closing MySQL connection:', err);
        }
        process.exit();
    });
});

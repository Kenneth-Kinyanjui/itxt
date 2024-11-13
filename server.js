var express = require('express')
var bodyParser = require('body-parser')
var app = express()
var http = require('http').Server(app)
var io = require('socket.io')(http)
var mysql = require('mysql2')



app.use(express.static(__dirname))
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({extended: false}))


var messages = [
    {name: 'Tim', message: 'Hello'},
    {name: 'Jane', message: 'Hi'}
]

app.get('/messages', (req, res) => {
    connection.query('SELECT * FROM messages', (err, results) => {
        if (err) {
            console.error('Error fetching messages:', err);
            return res.sendStatus(500);
        }

        res.send(results);
    });
});

app.post('/messages', async (req, res) => {
    const newMessage = {
        name: req.body.name,
        message: req.body.message
    };

    const queryDb = (sql, params) => {
        return new Promise((resolve, reject) => {
            connection.query(sql, params, (err, results) => {
                if (err) reject(err);
                resolve(results);
            });
        });
    };

    try {
        // Define specific bad words to check for
        const badWords = ['badword', 'insult', 'when']; // Add more bad words to this array as needed
        const messageText = newMessage.message.toLowerCase();
        const hasBadWord = badWords.some(word => messageText.includes(word));

        if (hasBadWord) {
            console.log('Censored word found');
            return res.sendStatus(400);
        }

        // Save the message if no bad words found
        const saveResult = await queryDb(
            'INSERT INTO messages SET ?', 
            newMessage
        );

        // Emit message to all connected clients
        io.emit('message', newMessage);
        
        // Send success response
        res.sendStatus(200);

    } catch (error) {
        console.error('Error processing message:', error);
        res.sendStatus(500);
    }
});






io.on('connection', (socket) => {
     console.log('user connected')
})

const connection = mysql.createConnection({
    host: 'localhost',
    port: 3306,
    user: 'root',
    password: '',
    database: 'itxt'
})

connection.connect((err) => {
    if (err) {
        console.error('Error connecting to database:', err);
        return;
    }
    console.log('Connected to database');
});

var message = `
CREATE TABLE IF NOT EXISTS messages (
  id INT AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(255) NOT NULL,
  message TEXT NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)`;
connection.query(message, (err, result) => {
    if (err) throw err;
    console.log('Messages table created or already exists');
});

var server = http.listen(8000, () => {
    console.log('Server is listening on port', server.address().port)
})


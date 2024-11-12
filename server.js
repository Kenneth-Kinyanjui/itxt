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

app.post('/messages', (req, res) => {
    const newMessage = {
        name: req.body.name,
        message: req.body.message
    };

    // Function to check and delete messages with bad words
    const checkAndDeleteBadWords = () => {
        connection.query(
            'DELETE FROM messages WHERE message LIKE ?',
            ['%badword%'],
            (err, deleteResults) => {
                if (err) {
                    console.error('Error removing censored message:', err);
                }
                if (deleteResults.affectedRows > 0) {
                    console.log('Removed censored message');
                }
            }
        );
    };

    connection.query('INSERT INTO messages SET ?', newMessage, (err, results) => {
        if (err) {
            console.error('Error saving message:', err);
            return res.sendStatus(500);
        }

        // Check for bad words after insertion
        connection.query(
            'SELECT * FROM messages WHERE message LIKE ? AND id = ?',
            ['%badword%', results.insertId],
            (err, censored) => {
                if (err) {
                    console.error('Error checking for bad words:', err);
                } else if (censored && censored.length > 0) {
                    console.log('Censored word found', censored);
                    checkAndDeleteBadWords();
                }
            }
        );

        io.emit('message', newMessage);
        res.sendStatus(200);
    });
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


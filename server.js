var express = require('express')
var app = express()

app.use(express.static(__dirname))

var messages = [
    {name: 'Ken', message: 'hi'},
    {name: 'Ben', message: 'hello'}
]

app.get('/messages', (req, res) =>
res.send(messages)
)

var server = app.listen(8000, () => {
    console.log('Server is listening on port', server.address().port)
})
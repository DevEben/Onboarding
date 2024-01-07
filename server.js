require('./dbConfig/dbConfig');
const express = require('express');
require('dotenv').config();
const bodyParser = require('body-parser');
const router = require('./router/userRouter');

const app = express();

const port = process.env.PORT;

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.json());
app.get('/api/v1', (req, res) => {
    res.send("Welcome to Eben Designz Onboarding site");
})
app.use('/api/v1', router);

app.listen(port, () => {
    console.log(`Server up and running on port: ${port}`);
})
const mongoose = require('mongoose');
require('dotenv').config();

const DB = process.env.DATABASE;

mongoose.connect(DB)
.then(() => {
    console.log('Connection to database established successfully');
})
.catch((err) => {
    console.log('Error connecting to database: ' + err.message);
})
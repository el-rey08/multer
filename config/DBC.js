require('dotenv').config
const mongoose = require('mongoose')
const url = process.env.DATABASE_URL
mongoose.connect(url).then(()=>{
    console.log('connection to database is successfull');
}).catch((error)=>{
    console.log('error connecting to database', error.message);
})

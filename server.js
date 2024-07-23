require('dotenv').config()
require('./config/DBC')
const express = require('express')
const app = express()
const router =require('./router/userRouter')
app.use(express.json())
app.use(router)
const port = process.env.port || 3454
app.listen(port,()=>{
    console.log(`server is running on port: ${port}`)
})
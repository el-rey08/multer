const mongoose = require('mongoose')
const userSchema =new mongoose.Schema({
    fullname:{
        type:String,
        required:true,
        trim:true
    },
    email:{
        type:String,
        required:true,
        trim:true,
        lowerCase:true
    },
    password:{
        type:String,
        required:true,
    },
    image:{
        type:String
    },
    isVerified:{
        type:Boolean,
        default:false
    },
    blackList:[]
    
},{timestamps:true})
const userModel = mongoose.model('user',userSchema)
module.exports =userModel
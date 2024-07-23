const express = require('express')
const { signUp, logIn } = require('../controller/userController')
const upload = require('../utils/muler')
const router = express.Router()
router.post('/api/v1/user/sign-up',upload.single('image'),signUp)
router.post('/api/v1/user/log-in',logIn)
module.exports = router
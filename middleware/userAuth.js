const userModel = require('../model/userModel')
const jwt = require('jsonwebtoken')
require('dotenv').config()
const authenticate = async (req, res, next) => {
  try {
      const auth = req.headers.authorization;
      if(!auth) {
          return res.status(401).json({
              message: 'Authorization required'
          })
      }
      const token = auth.split(' ')[1];

      if(!token){
          return res.status(401).json({
              message: 'invalid token'
          })
      }
      const decodedToken = jwt.verify(token, process.env.JWT_SECRET);
      const user = await userModel.findById(decodedToken.userId);
      if(!user){
          return res.status(401).json({
              message: 'Authentication failed:  User not found'
          })
      }
      if(user.blackList.includes(token)){
          return res.status(401).json({
              message: 'Session expired: Please login to continue'
          })
      }

      req.user = decodedToken
      next();

  } catch (error) {
      if(error instanceof jwt.JsonWebTokenError){
          return res.json({message: 'Session expired: Please login to continue'})
      }
      res.status(500).json({
          message: error.message
      })
  }
}
module.exports = authenticate
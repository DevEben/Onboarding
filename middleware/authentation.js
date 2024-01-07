const userModel = require('../models/userModel');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const authenticate = async (req, res, next) => {
    try {
        const hasAuthorization = req.headers.authorization;
        if (!hasAuthorization) {
            return res.status(400).json({
                message: 'Invalid authorization',
            })
        }
        const token = hasAuthorization.split(" ")[1];
        if (!token) {
            return res.status(404).json({
                message: "Token not found",
            });
        }
        const decodeToken = jwt.verify(token, process.env.secret)
        const user = await userModel.findById(decodeToken.userId);
        if (!user) {
            return res.status(404).json({
                message: "Not authorized: User not found",
            });
        }
        if (user.blacklist.includes(token)) {
            return res.status(400).json({
                message: 'Authorization Falied: Please login to continue'
            })
        }

        req.user = decodeToken;

        next();
        
    } catch (err) {
        if (err instanceof jwt.JsonWebTokenError){
            return res.status(501).json({
                message: 'Session timeout, please login to continue',
            })
        }
        return res.status(500).json({
            Error: "Authentication error: " + err.message,
        })        
    }
};

module.exports = {
    authenticate,

}
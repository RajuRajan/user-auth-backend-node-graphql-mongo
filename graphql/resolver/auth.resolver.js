const Auth = require("../../models/Auth")
const jwt = require('jsonwebtoken')
const UserHelper = require("../_helpers/user.helper")
module.exports = {
    getAccessToken: async (args,req) => {
        const authHeader = req.get("RefreshToken")
        var decodedToken = authHeader && jwt.verify(authHeader, 'refreshToken')
        if(decodedToken){
            const token = jwt.sign({userId: decodedToken.userId, email: decodedToken.email}, 'secret',{
                expiresIn: "1h"
            })
            const refreshToken = jwt.sign({userId: decodedToken.userId, email: decodedToken.email}, 'refreshToken')
            UserHelper.setAuth(decodedToken.userId, token, refreshToken)
            return {token, refreshToken, userId: decodedToken.userId}
        }
        throw new Error("UNAUTHORIZED")
    }
}
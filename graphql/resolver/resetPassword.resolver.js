const ResetPassword = require("../../models/resetPassword")
const User = require("../../models/user")
const bcrypt = require('bcryptjs')
const jwt = require("jsonwebtoken")
const userHelper  = require("../_helpers/user.helper")

module.exports = {
    forgotPassword: async (args) => {
        try { 
            // TokenExpired is checked if db alreaddy contains expiredtoken of restpassword
            const TokenExpired = await ResetPassword.findOne({email: args.email})
            //if token expired then particular users old token details deleted
                try{
                  var isTokenNotExpired = TokenExpired && jwt.verify(TokenExpired.secretKey, 'secret')
                }
                catch {
                    const DeleteTokenExpired = await ResetPassword.deleteOne({email: args.email})
                }
            //if token Not expired then it insists to use the same secret key from the mail
            if(TokenExpired && isTokenNotExpired){
                return {status: "Use Mail secret Key",code:200}
            }
 
            const randomKey = Math.floor(100000 + Math.random() * 900000)
            const randomKeyToken = jwt.sign({key: randomKey}, 'secret',{
                expiresIn: "300000ms" //for 5min
            })

            const isUserExists = await User.findOne({email:args.email})
            if(!isUserExists){
                throw new Error('Email Not registered');
            }

            ResetPassword.create({ email: args.email, secretKey: randomKeyToken})
            .then(userHelper.sendMail(args.email,randomKey))

            return {status:"Mailed", code:200}

        } catch (err) {
            throw new Error(err.message)
        }
    },
    checkSecretKey: async(args) => {
        try {
            const reset = await ResetPassword.findOne({email: args.email})
            try{
                var decodedToken = jwt.verify(reset.secretKey, 'secret')
                if(decodedToken.key === args.secretKey){
                    return {...reset , status:"MATCHED", isMatched:true}
                }
            }
            catch {
                return {status:"CHECK SECRET KEY AND MAIL ID", isMatched:false, code:200}
            }
        } catch (err) {
            throw new Error(err.message)
        }
    },
    resetPassword: async(args) => {
        try { 
            const reset = await ResetPassword.findOne({email: args.email})
            try{
                var decodedToken = jwt.verify(reset.secretKey, 'secret')
                
                if(decodedToken && decodedToken.key === args.secretKey){
                    const filter = { email: args.email };
                    const hashedPass = await bcrypt.hash(args.password ,12);

                    const update = { password: hashedPass};
                    const user = await User.updateOne(filter, update)
                    return {status:"PASSWORD CHANGED", isMatched: true, isPasswordChanged: true,code:200}
                }
             } catch {
                 return {status:"CHECK SECRET KEY AND MAIL ID", isMatched: false, isPasswordChanged: false, code:200}
             }
        } catch (err) {
            throw new Error(err.message)
        }
    }
}
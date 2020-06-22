const nodemailer = require("nodemailer");
const { google } = require("googleapis");
const Auth = require("../../models/Auth");
const user = require("../../models/user");

 class UserHelper {
    static sendMail(email , randomKey){
        const OAuth2 = google.auth.OAuth2;

        const oauth2Client = new OAuth2(
        process.env.CLIENT_ID_MAIL, // ClientID
        process.env.CLIENT_SECRET_MAIL, // Client Secret
        "https://developers.google.com/oauthplayground" // Redirect URL
        );

        oauth2Client.setCredentials({
        refresh_token: process.env.REFRESH_TOKEN_MAIL,
        });

        const accessToken = oauth2Client.getAccessToken();
        const smtpTransport = nodemailer.createTransport({
        service: "gmail",
        auth: {
            type: "OAuth2",
            user: process.env.MAIL_AUTH_GMAIL,
            clientId:  process.env.CLIENT_ID_MAIL,
            clientSecret: process.env.CLIENT_SECRET_MAIL,
            refreshToken: process.env.REFRESH_TOKEN_MAIL,
            accessToken: accessToken,
        },
        });

        const mailOptions = {
        from:  process.env.MAIL_AUTH_GMAIL,
        to: email,
        subject: "CMS Forget Password",
        generateTextFromHTML: true,
        html: `<h2>SECRET KEY ${randomKey}</h2>`,
        };

        smtpTransport.sendMail(mailOptions, (error, response) => {
        error ? console.log(error) : res.send(response);
        smtpTransport.close();
        });

    }

    static async setAuth(userId, accessToken, refreshToken){
        try{
            const isAuthExists = await Auth.findOne({userId})
            if(isAuthExists){
              const deleteAuth = await  Auth.deleteOne({userId})
            }
            const Authres = new Auth({
                userId,
                accessToken,
                refreshToken
            })
            Authres.save()
         } catch (err) {
             throw new Error(err.message)
         }
    }
 }
 module.exports = UserHelper
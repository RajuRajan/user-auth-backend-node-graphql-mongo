const UserResolver = require("./user.resolver")
const ResetPasswordResolver = require("./resetPassword.resolver")
const AuthResolver = require("./auth.resolver")

module.exports = {
    ...UserResolver,
    ...ResetPasswordResolver,
    ...AuthResolver
}

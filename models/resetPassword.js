const mongoose = require('mongoose')

const Schema = mongoose.Schema;

const resetSchema = new Schema({
    secretKey: {
        type: String,
        required: true
    },
    email: {
        type: String,
        required: true
    }
},{timestamps: true })
module.exports = mongoose.model('ResetPassword',resetSchema)
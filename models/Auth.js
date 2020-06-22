const mongoose = require('mongoose')

const Schema = mongoose.Schema;

const authSchema = new Schema({
    userId: {
        type: String,
        required: true
    },
    accessToken: {
        type: String,
        required: true
    },
    refreshToken: {
        type: String,
        required: true
    }
},{timestamps: true })
module.exports = mongoose.model('Auth',authSchema)
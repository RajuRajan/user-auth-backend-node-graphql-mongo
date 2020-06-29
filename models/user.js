const mongoose = require('mongoose')

const Schema = mongoose.Schema;

const userSchema = new Schema({
    firstName: {
        type: String,
        required: true
    }, 
    lastName: {
        type: String,
        required: true
    },
    phoneNo: {
        type: Number,
        required: true
    },
    telephoneNo: {
        type: Number
    },
    email: {
        type: String,
        required: true
    },
    roleId: {
        type: Number,
        required: true
    },
    countryId: {
        type: Number,
        required: true
    },
    cityId: {
        type: Number,
        required: true
    },
    designationId: {
        type: Number,
        required: true
    },
    dob: {
        type: Number,
        required: true
    },
    password: {
        type: String,
        required: true
    }
},{timestamps: true })

module.exports = mongoose.model('User',userSchema)
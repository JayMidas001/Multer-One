const mongoose = require('mongoose')

const userSchema = new mongoose.Schema({
    fullName: {
        type: String,
        required: true
    },
    email: {
        type: String,
        required: true
    },
    password: {
        type: String,
        required: true
    },
    stack: {
        type: String,
        required: true
    },
    image: {
        type: String,
        require: true
    },
    isVerified:{
        type:String
    }
}, {timestamps: true})

const UserModel = mongoose.model('User', userSchema);

module.exports = UserModel
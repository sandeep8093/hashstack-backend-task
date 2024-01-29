const mongoose = require('mongoose');
const userSchema = mongoose.Schema(
    {
        username:{
            type:String,
            required:true,
            unique:true
        },
        password: {
            type:String,
            required:true
        },
        randomSalt: {
            type:String
        },
        signature: {
            type:String
        },
        publicKey:{
            type:String
        },
        privateKey:{
            type:String
        },
        isVerified:{
            type:Boolean
        }
    },{timestamps:true},
    {minimize:false}
);
module.exports = mongoose.model('User',userSchema);
const User = require('../models/User');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const crypto = require('crypto')


exports.signup = async(req,res)=>{
    try{
        const {username,password,randomSalt} = req.body;
        const {publicKey, privateKey} = crypto.generateKeyPairSync('rsa',{
            modulusLength:2048,
            publicKeyEncoding : {type:'spki',format:'pem'},
            privateKeyEncoding: {type:'pkcs8',format:'pem'}
        });

        const newUser = new User({
            username:username,
            password: bcrypt.hashSync(password,10),
            randomSalt: bcrypt.hashSync(randomSalt,10),
            publicKey:publicKey,
            privateKey:privateKey
        })
        await newUser.save();
        return res.status(200).json({"message":"registered Successfully"});
    }catch(err){
        console.log(err)
        res.status(500).json(err);
    }
}

exports.login= async(req,res) =>{
    try{
        const {username,password} = req.body;
        const savedUser = await User.findOne({username:username});
     
        if(!savedUser){
            return res.status(200).json("User with this username does not exists");
        }
        if(bcrypt.compareSync(password,savedUser.password)){
            const payload = {
                id:savedUser._id,
                username:savedUser.username,
                publicKey:savedUser.publicKey
            }
            const token=jwt.sign(payload,process.env.JWT_SECRET,{expiresIn: '5h'});
            return res.status(200).json({
                token,
                payload
            })
        }
        else{
            return res.status(200).json("Wrong Password Entered");
        }
    }catch(err){
        res.status(500).json(err);
    }
    
}

exports.sign=async(req,res)=>{
    try{
        const {message} = req.body;
        const savedUser = await User.findOne({publicKey:req.user.publicKey});
        console.log(savedUser)
        var crypt = new JSEncrypt();
        crypt.setKey(savedUser.privateKey);
        
        // Encrypt the data with the public key.
        var enc = crypt.encrypt(message);
        savedUser.signature = enc;
        await savedUser.save();
        return res.status(200).json({"signature":enc});
    
    }catch(err){
        res.status(500).json(err);
    }
}

exports.verify=async(req,res)=>{
    try{
        const {message,publicKey}= req.body;
        const savedUser = await User.findOne({publicKey:req.user.publicKey});
            
        var crypt = new JSEncrypt();
        crypt.setKey(savedUser.privateKey);
        
        var dec = crypt.decrypt(savedUser.signature);
        if(dec == message && publicKey == savedUser.publicKey){
            savedUser.isVerified = true;
            await savedUser.save();
            return res.status(200).json({"message":"Signature verified successfully"});
        }
        return res.status(200).json({"message":"invalid message or public key"});
    }catch(err){
        console.log(err);
    }
}

exports.getSignatures = async(req,res)=>{
    try{
        const savedUsers= await User.find({where:{
            "isVerified":true
        }});
        return res.status(200).json({"data":savedUsers});
    }catch(err){
        console.log(err);
    }
}
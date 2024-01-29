const User = require('../models/User');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const crypto = require('crypto')

exports.signup = async(req,res)=>{
    try{
        const {username,password,randomSalt} = req.body;
        const savedUser = await User.findOne({username:username});
        if (savedUser) {
            if(bcrypt.compareSync(randomSalt,savedUser.randomSalt))
                return res.status(200).json({ message: 'User Already Exists' });
        }
        
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
  
// Encrypt data with public key
function encryptWithPublicKey(data,publicKey) {
    const bufferData = Buffer.from(data, 'utf-8');
    const encrypted = crypto.publicEncrypt(publicKey, bufferData);
    return encrypted.toString('base64');
}
  
// Decrypt data with private key
function decryptWithPrivateKey(encryptedData,privateKey) {
    const bufferEncryptedData = Buffer.from(encryptedData, 'base64');
    const decrypted = crypto.privateDecrypt(privateKey, bufferEncryptedData);
    return decrypted.toString('utf-8');
}

exports.sign = async(req,res) => {
    try{
        const {message} = req.body;
        const savedUser = await User.findOne({_id:req.user.id});
        if (!savedUser) {
            return res.status(404).json({ message: 'User not found' });
        }
             
        // Encrypt the data with the public key.
        var enc = encryptWithPublicKey(message,savedUser.publicKey);
        savedUser.signature = enc;
        await savedUser.save();
        return res.status(200).json({"signature":enc});
    
    }catch(err){
        res.status(500).json(err);
    }
}

//same user or any other user having access to private key verifying this signature 
exports.verify = async (req, res) => {
    try {
      const { message, publicKey = "", username = "" } = req.body;
      let savedUser;

      // Checking if either publicKey or username is provided
      if (publicKey) {
        savedUser = await User.findOne({ publicKey: publicKey });
      } else if (username) {
        savedUser = await User.findOne({ username: username });
      } else {
        return res.status(400).json({ message: 'Provide either publicKey or username' });
      }

      if (!savedUser) {
        return res.status(404).json({ message: 'User not found' });
      }
    
      // decrypt with private key
      var dec = decryptWithPrivateKey(savedUser.signature, savedUser.privateKey);
      
      if (dec === message ) {
        savedUser.isVerified = true;
        await savedUser.save();
        return res.status(200).json({ message: 'Signature verified successfully' });
      }

      return res.status(200).json({ message: 'Invalid message or public key' });
    } catch (err) {
      console.error(err);
      res.status(500).json(err);
    }
};

exports.getSignatures = async(req,res)=>{
    try{
        const savedUsers= await User.find({
            "isVerified":1
        });
        const reqData = savedUsers.map(user => ({
            username: user.username,
            signature: user.signature,
            publicKey: user.publicKey
        }));

        return res.status(200).json({ "data": reqData });
    }catch(err){
        console.log(err);
        res.status(500).json(err);
    }
}
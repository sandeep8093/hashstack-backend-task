const jwt = require('jsonwebtoken');
const verifyToken = (req,res,next)=>{
    let user;
    if(req.headers.authorization){
        const token = req.headers.authorization.split(" ")[1];
        try{
            user = jwt.verify(token,process.env.JWT_SECRET);
        }catch{
            err={
                name:'TokeExprired',
                message: 'Auth token Expired'
            }
            return res.status(400).json(err);
        }
    }
    req.user = user;
    if(!user){
        return res.status(400).json({"error":"no auth token found"});
    }
    next();
}

module.exports = {
    verifyToken
}
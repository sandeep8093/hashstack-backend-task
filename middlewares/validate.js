const Joi = require('joi');

const signUp = (req,res,next) => {

  const schema = Joi.object({
    username: Joi.string().required(),
    password: Joi.string().required(),
    randomSalt: Joi.string().required(),
  });
  const { error } = schema.validate(req.body);
  if (error) {
    return res.status(400).json({ error: error.details[0].message });
  }

  next(); 
};

const login = (req,res,next) => {
    const schema = Joi.object({
      username: Joi.string().required(),
      password: Joi.string().required()
    });
    const { error } = schema.validate(req.body);
    if (error) {
      return res.status(400).json({ error: error.details[0].message });
    }
  
    next(); 
};

const sign = (req,res,next) => {
  const schema = Joi.object({
    message: Joi.string().required(),
  });

  const { error } = schema.validate(req.body);
  if (error) {
    return res.status(400).json({ error: error.details[0].message });
  }

  next(); 
};

const verify = (req,res,next) => {
    const schema = Joi.object({
      message: Joi.string().required(),
      publicKey: Joi.string(),
      username: Joi.string(),
    });
    
    const { error } = schema.validate(req.body);
    if (error) {
      return res.status(400).json({ error: error.details[0].message });
    }
  
    next(); 
};

module.exports = {
    signUp,
    login,
    sign,
    verify
}

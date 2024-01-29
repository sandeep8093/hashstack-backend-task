const router = require('express').Router();
const user = require('../controllers/user.controller');
const {verifyToken} = require('../middlewares/index')
const validator = require('../middlewares/validate')

router.post('/signup',validator.signUp, user.signup);
router.post('/login',validator.login, user.login);

router.post('/sign', validator.sign, verifyToken, user.sign);
router.post('/verify',validator.verify, verifyToken, user.verify);

router.get('/getSignatures',user.getSignatures);

module.exports = router
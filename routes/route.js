const router = require('express').Router();
const user = require('../controllers/user.controller');
const {verifyToken} = require('../middlewares/index')

router.post('/signup',user.signup);
router.post('/login',user.login);

router.post('/sign',verifyToken, user.sign);
router.post('/verify',verifyToken, user.verify);

router.post('/getSignatures',user.getSignatures);

module.exports = router
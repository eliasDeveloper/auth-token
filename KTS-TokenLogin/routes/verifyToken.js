const jwt = require('jsonwebtoken')

module.exports = function (req, res, next){
    const token = req.headers['auth-token']

    if(typeof token === 'undefined' || !token) return res.status(401).send('Access Denied')

    try{
        const bearer = token.split(' ')
        const bearerToken = bearer[1];
        const verified = jwt.verify(token, 'secretkey');
        req.user = verified;
        req.token = bearerToken
        next()
    }
    catch(err){
        res.status(400).send('Invalid '+ err)
    }
}
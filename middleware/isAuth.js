const jwt = require('jsonwebtoken')

module.exports = (req, res, next) => {
    const authHeader = req.get('Authorization');
    if(!authHeader){
        req.isAuth = false;
        return next();
    }
    const token = authHeader; 
    if(!token || token ==='') {
        req.isAuth = false;
        return next()
    }
    try{
        
    var decodedToken = jwt.verify(token, 'secret')
    
    } catch (err) {
        req.isAuth = false;
        return next()
    }
    if(!decodedToken){
        req.isAuth = false
        return next()
    }
    
    req.isAuth = true;
    req.userId = decodedToken.userId;
    next()
}
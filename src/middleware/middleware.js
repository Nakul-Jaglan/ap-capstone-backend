const jwt = require('jsonwebtoken');

async function isValidToken(req, res, next) {
    try {
        const token = req.headers?.authorization?.split(' ')?.[1];

        if (!token) {
            return res.status(401).json({ message: "No token provided" })
        }

        const decoded = jwt.verify(token, process.env.JWT_SECRET)

        req.user = decoded;

        next()
    } catch (error) {
        console.error('Token verification error:', error.message)
        return res.status(401).json({ message: "Invalid or expired token" })
    }
}

module.exports = { isValidToken }
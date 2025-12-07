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

async function isAdmin(req, res, next) {
    try {
        if (req.user.role !== 'admin') {
            return res.status(403).json({ message: "Access denied. Admin role required." })
        }
        next()
    } catch (error) {
        console.error('Admin check error:', error.message)
        return res.status(403).json({ message: "Access denied" })
    }
}

module.exports = { isValidToken, isAdmin }
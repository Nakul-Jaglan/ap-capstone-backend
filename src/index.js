require('dotenv').config();
const bcrypt = require('bcrypt')
const express = require('express')
const cors = require('cors')
const { PrismaClient } = require('@prisma/client')
var jwt = require('jsonwebtoken');
const prisma = new PrismaClient()
const app = express()
const { isValidToken } = require('./middleware/middleware');

// Enable CORS for frontend
app.use(cors({
  origin: process.env.FRONTEND_URL,
  credentials: true
}))

app.use(express.json())

app.get('/', (req, res) => {
  res.json({message: 'This is the backend server of CollabSpace!'});
});

app.post('/signup', async (req, res) => {
  const { username, email, password, name } = req.body

  if (!username || !email || !password) {
    return res.status(400).json({ message: "Username, email, and password are required" })
  }

  try {
    const existingUser = await prisma.user.findFirst({
      where: {
        OR: [
          { email: email },
          { username: username }
        ]
      }
    })

    if (existingUser) {
      if (existingUser.email === email) {
        return res.status(422).json({ message: "Email already exists" })
      }
      if (existingUser.username === username) {
        return res.status(422).json({ message: "Username already exists" })
      }
    }

    const hashedPassword = await bcrypt.hash(password, 10)

    const newUser = await prisma.user.create({
      data: {
        username: username,
        email: email,
        password: hashedPassword,
        name: name || null,
        role: "user"
      }
    })

    return res.status(201).json({
      message: "User created successfully!",
      user: {
        id: newUser.id,
        username: newUser.username,
        email: newUser.email,
        name: newUser.name,
        role: newUser.role
      }
    })
  } catch (error) {
    console.error('Signup error:', error)
    return res.status(500).json({ message: "Something went wrong" })
  }
})

app.post('/login', async (req, res) => {
  const { login, password } = req.body;

  if (!login || !password) {
    return res.status(400).json({ message: "Login (email or username) and password are required" })
  }

  try {
    const user = await prisma.user.findFirst({
      where: {
        OR: [
          { email: login },
          { username: login }
        ]
      }
    })

    if (!user) {
      return res.status(422).json({ message: "User does not exist" })
    }

    const isPasswordMatch = await bcrypt.compare(password, user.password);

    if (isPasswordMatch) {
      await prisma.user.update({
        where: { id: user.id },
        data: { lastActiveAt: new Date() }
      })

      const token = jwt.sign(
        {
          id: user.id,
          email: user.email,
          username: user.username,
          role: user.role
        },
        process.env.JWT_SECRET,
        { expiresIn: process.env.JWT_EXPIRES_IN }
      )

      return res.status(200).json({
        token: token,
        user: {
          id: user.id,
          username: user.username,
          email: user.email,
          name: user.name,
          avatarUrl: user.avatarUrl,
          role: user.role
        }
      })
    } else {
      return res.status(401).json({ message: "Password is incorrect" })
    }
  } catch (error) {
    console.error('Login error:', error)
    return res.status(500).json({ message: "Something went wrong" })
  }
})

app.get("/users", isValidToken, async (req, res) => {
  const users = await prisma.user.findMany();

  return res.status(200).json({ data: users })
})

app.listen(4000, () => {
  console.log(`Server is running on port 4000`);
});
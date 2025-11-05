const express = require('express');
const app = express();
const { clerkMiddleware } = require("@clerk/express")

app.use(express.json());
app.use(clerkMiddleware());

app.get('/', (req, res) => {
  res.send('Hello World!');
});

app.listen(4000, () => {
  console.log(`Server is running on port 4000`);
});
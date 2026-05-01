const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const path = require("path");

const app = express();

app.use(express.json());
app.use(cors());
app.use(express.static("public"));

// 🔗 MongoDB Connection
mongoose.connect("mongodb://127.0.0.1:27017/authDB")
  .then(() => console.log("✅ DB connected"))
  .catch(err => console.log(err));

// 📦 User Model
const User = require("./models/User");


// 🔐 SIGNUP
app.post("/signup", async (req, res) => {
  try {
    const username = req.body.username.trim();
    const email = req.body.email.trim();
    const password = req.body.password.trim();

    // ❗ validation
    if (!username || !email || !password) {
      return res.json({ message: "All fields required ❌" });
    }

    // check if user exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.json({ message: "User already exists ❌" });
    }

    // 🔒 hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    const user = new User({
      username,
      email,
      password: hashedPassword
    });

    await user.save();

    res.json({ message: "User created ✅" });

  } catch (err) {
    console.log(err);
    res.json({ message: "Server error ❌" });
  }
});


// 🔐 LOGIN
app.post("/login", async (req, res) => {
  try {
    const email = req.body.email.trim();
    const password = req.body.password.trim();

    // ❗ validation
    if (!email || !password) {
      return res.json({ message: "All fields required ❌" });
    }

    const user = await User.findOne({ email });

    if (!user) {
      return res.json({ message: "User not found ❌" });
    }

    // 🔥 correct password check
    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return res.json({ message: "Wrong password ❌" });
    }

    // 🔑 create real token
    const token = jwt.sign(
      { id: user._id },
      "secretkey",
      { expiresIn: "1h" }
    );

    res.json({
      token,
      username: user.username
    });

  } catch (err) {
    console.log(err);
    res.json({ message: "Server error ❌" });
  }
});


// 🛡️ VERIFY TOKEN (Improved)
const verifyToken = (req, res, next) => {
  const token = req.headers["authorization"];

  if (!token) {
    return res.status(401).send("No token ❌");
  }

  try {
    const verified = jwt.verify(token, "secretkey");
    req.user = verified;
    next();
  } catch {
    res.status(403).send("Invalid token ❌");
  }
};


// 🔒 DASHBOARD (returns username)
app.get("/dashboard", verifyToken, async (req, res) => {
  const user = await User.findById(req.user.id);
  res.send(`Welcome ${user.username} 🎉`);
});


// ❌ DELETE ACCOUNT (secure)
app.delete("/delete", verifyToken, async (req, res) => {
  await User.findByIdAndDelete(req.user.id);
  res.send("Account deleted successfully ❌");
});


// 🌐 DEFAULT ROUTE
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});


// 🚀 START SERVER
app.listen(5000, () => {
  console.log("🚀 Server running on http://127.0.0.1:5000");
});
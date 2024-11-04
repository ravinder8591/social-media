// server.js
const express = require("express");
const fs = require("fs");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();
app.use(express.json());

const PORT = 3000;
const JWT_SECRET = "your_jwt_secret"; // Use environment variable in production

// functions to read and write data to JSON files

const readData = (filePath) => {
    const data = fs.readFileSync(filePath);
    return JSON.parse(data);
};

const writeData = (filePath, data) => {
    fs.writeFileSync(filePath, JSON.stringify(data, null, 2));
};


// Register a new user
app.post("/register", async (req, res) => {
    const { username, password, role } = req.body;
    const users = readData("data/users.json");

    if (users.some(user => user.username === username)) {
        return res.status(400).json({ message: "Username already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = {
        id: Date.now(),
        username,
        password: hashedPassword,
        role, // "user" or "admin"
        followers: [],
        following: []
    };

    users.push(newUser);
    writeData("data/users.json", users);

    res.status(201).json({ message: "User registered successfully" });
});

// Login a user
app.post("/login", async (req, res) => {
    const { username, password } = req.body;
    const users = readData("data/users.json");
    const user = users.find(user => user.username === username);

    if (!user || !(await bcrypt.compare(password, user.password))) {
        return res.status(400).json({ message: "Invalid credentials" });
    }

    const token = jwt.sign({ id: user.id, role: user.role }, JWT_SECRET, { expiresIn: "1h" });
    res.json({ token });
});


// middleware to verify JWT tokens(Authentication Middleware)
const authMiddleware = (req, res, next) => {
    const token = req.headers["authorization"];

    if (!token) return res.status(401).json({ message: "Access denied" });

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded;
        next();
    } catch {
        res.status(400).json({ message: "Invalid token" });
    }
};

// Create a new post (only for registered users)
app.post("/posts", authMiddleware, (req, res) => {
    const { role, id: userId } = req.user;
    const { content } = req.body;

    if (role === "guest") return res.status(403).json({ message: "Guests cannot create posts... Not Allowed" });

    const posts = readData("data/posts.json");
    const newPost = {
        id: Date.now(),
        userId,
        content,
        likes: 0,
        comments: [],
        timestamp: new Date()
    };

    posts.push(newPost);
    writeData("data/posts.json", posts);

    res.status(201).json({ message: "New Post created" });
});

// Get all posts (everyone can view)
app.get("/posts", (req, res) => {
    const posts = readData("data/posts.json");
    res.json(posts);
});

// Edit a post (only the owner or admin)
app.put("/posts/:postId", authMiddleware, (req, res) => {
    const { role, id: userId } = req.user;
    const { postId } = req.params;
    const { content } = req.body;

    const posts = readData("data/posts.json");
    const post = posts.find(p => p.id == postId);

    if (!post) return res.status(404).json({ message: "Post not found" });

    if (post.userId !== userId && role !== "admin") {
        return res.status(403).json({ message: "Not authorized" });
    }

    post.content = content;
    writeData("data/posts.json", posts);

    res.json({ message: "Post updated" });
});


// Like a post (everyone can like)
app.post("/posts/:postId/like", authMiddleware, (req, res) => {
    const { postId } = req.params;
    const posts = readData("data/posts.json");

    const post = posts.find(p => p.id == postId);
    if (!post) return res.status(404).json({ message: "Post not found" });

    post.likes += 1;
    writeData("data/posts.json", posts);

    res.json({ message: "Post liked" });
});


// Comment on a post (only registered users)
app.post("/posts/:postId/comment", authMiddleware, (req, res) => {
    const { role, id: userId } = req.user;
    const { postId } = req.params;
    const { comment } = req.body;

    if (role === "guest") return res.status(403).json({ message: "Guests cannot comment" });

    const posts = readData("data/posts.json");
    const post = posts.find(p => p.id == postId);

    if (!post) return res.status(404).json({ message: "Post not found" });

    post.comments.push({ userId, comment });
    writeData("data/posts.json", posts);

    res.json({ message: "Comment added" });
});

app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});

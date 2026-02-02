const express = require('express');
const http = require('http');
const mongoose = require('mongoose');
const { Server } = require("socket.io");
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');
const createCsvWriter = require('csv-writer').createObjectCsvWriter;

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: "*" } });

// --- CONFIG ---
const MONGO_URI = process.env.MONGO_URI || "mongodb+srv://YOUR_MONGO_STRING"; // Set in Render Env Vars
const JWT_SECRET = process.env.JWT_SECRET || "supersecretbiocube";

// --- MIDDLEWARE ---
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public'))); // Serve the frontend

// --- DATABASE MODELS ---
mongoose.connect(MONGO_URI).then(() => console.log("MongoDB Connected"));

const UserSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: { type: String, default: 'viewer' }, // 'admin' or 'viewer'
    isBanned: { type: Boolean, default: false }
});
const User = mongoose.model('User', UserSchema);

const LogSchema = new mongoose.Schema({
    timestamp: { type: Date, default: Date.now },
    temp_in: Number,
    hum_in: Number,
    soil_moisture: Number,
    npk_n: Number,
    npk_p: Number,
    npk_k: Number
});
const SensorLog = mongoose.model('Log', LogSchema);

// --- AUTH ROUTES ---
app.post('/api/register', async (req, res) => {
    const { username, password } = req.body;
    // Check if this is the FIRST user -> make Admin
    const isFirst = (await User.countDocuments({})) === 0;
    const role = isFirst ? 'admin' : 'viewer';
    
    const hashedPassword = await bcrypt.hash(password, 10);
    try {
        const user = await User.create({ username, password: hashedPassword, role });
        res.json({ status: 'ok', role });
    } catch (e) {
        res.json({ status: 'error', error: 'Username taken' });
    }
});

app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    const user = await User.findOne({ username });
    if (!user) return res.json({ status: 'error', error: 'Invalid user' });
    if (user.isBanned) return res.json({ status: 'error', error: 'User is banned' });

    if (await bcrypt.compare(password, user.password)) {
        const token = jwt.sign({ id: user._id, role: user.role, username: user.username }, JWT_SECRET);
        res.json({ status: 'ok', token, role: user.role });
    } else {
        res.json({ status: 'error', error: 'Invalid password' });
    }
});

// --- ADMIN ROUTES ---
app.get('/api/users', async (req, res) => {
    // In production, verify JWT Admin here
    const users = await User.find({}, 'username role isBanned');
    res.json(users);
});

app.post('/api/admin/action', async (req, res) => {
    const { targetUser, action } = req.body;
    // action: promote, ban, unban
    if(action === 'ban') await User.updateOne({username: targetUser}, {isBanned: true});
    if(action === 'unban') await User.updateOne({username: targetUser}, {isBanned: false});
    if(action === 'promote') await User.updateOne({username: targetUser}, {role: 'admin'});
    res.json({status: 'ok'});
});

// --- DATA EXPORT ---
app.get('/api/download/standard', async (req, res) => {
    const logs = await SensorLog.find().sort({timestamp: -1}).limit(1000); // Last 1000 entries
    const csvWriter = createCsvWriter({
        path: 'biocube_logs.csv',
        header: [
            {id: 'timestamp', title: 'TIME'},
            {id: 'temp_in', title: 'TEMP'},
            {id: 'hum_in', title: 'HUMIDITY'},
            {id: 'soil_moisture', title: 'SOIL %'}
        ]
    });
    await csvWriter.writeRecords(logs);
    res.download('biocube_logs.csv');
});

// --- SOCKET.IO REALTIME ---
io.on('connection', (socket) => {
    console.log('Client connected');

    // From Pi: Camera Feed
    socket.on('camera_frame', (data) => {
        io.emit('feed', data); // Broadcast to all web users
    });

    // From Pi: Sensor Data
    socket.on('sensor_data', async (data) => {
        io.emit('update', data); // Broadcast to frontend
        // Log to DB (every 10th reading to save space, logic simplified here)
        if(Math.random() < 0.1) { 
             await SensorLog.create(data);
        }
    });

    // From Web App: Commands
    socket.on('control_cmd', (data) => {
        io.emit('control_cmd', data); // Send to Pi
    });
    
    // Status
    socket.on('pi_status', (data) => {
        io.emit('pi_status', data);
    });
});

server.listen(3000, () => console.log('Server running on port 3000'));

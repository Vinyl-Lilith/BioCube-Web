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
const io = new Server(server, { 
    cors: { origin: "*" },
    maxHttpBufferSize: 1e8 // Increased for high-res camera frames
});

// --- CONFIG ---
const MONGO_URI = process.env.MONGO_URI || "mongodb+srv://YOUR_MONGO_STRING";
const JWT_SECRET = process.env.JWT_SECRET || "supersecretbiocube";

// --- MIDDLEWARE ---
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// --- DATABASE MODELS ---
mongoose.connect(MONGO_URI)
    .then(() => console.log(">> BIOCUBE CORE: Database Link Established"))
    .catch(err => console.error(">> CORE CRITICAL: DB Connection Failed", err));

const UserSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: { type: String, default: 'operator' }, 
    isBanned: { type: Boolean, default: false },
    canManual: { type: Boolean, default: true },
    canEditAuto: { type: Boolean, default: true }
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

// --- AUTHENTICATION ENGINE ---

app.post('/api/register', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ status: 'error', error: 'Missing Credentials' });

    // ADMIN OVERRIDE LOGIC
    const userCount = await User.countDocuments({});
    let role = (userCount === 0 || username.toLowerCase() === 'admin') ? 'admin' : 'operator';

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        await User.create({ 
            username, 
            password: hashedPassword, 
            role,
            canManual: true,
            canEditAuto: true
        });
        console.log(`>> NEW OPERATOR: ${username} assigned as ${role}`);
        res.json({ status: 'ok', role });
    } catch (e) {
        res.json({ status: 'error', error: 'Operator ID already registered' });
    }
});

app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    const user = await User.findOne({ username });
    
    if (!user) return res.json({ status: 'error', error: 'Invalid ID' });
    if (user.isBanned) return res.json({ status: 'error', error: 'Access Revoked' });

    const isMatch = await bcrypt.compare(password, user.password);
    if (isMatch) {
        // Force role check for the hardcoded Admin account
        const activeRole = (username.toLowerCase() === 'admin') ? 'admin' : user.role;
        const token = jwt.sign({ id: user._id, role: activeRole, username: user.username }, JWT_SECRET);
        res.json({ status: 'ok', token, role: activeRole });
    } else {
        res.json({ status: 'error', error: 'Invalid Access Code' });
    }
});

// --- OPERATOR MANAGEMENT ---

app.get('/api/users', async (req, res) => {
    try {
        const users = await User.find({}, 'username role isBanned canManual canEditAuto');
        res.json(users);
    } catch (e) { res.status(500).send("Internal Error"); }
});

app.post('/api/admin/action', async (req, res) => {
    const { targetUser, action } = req.body;
    console.log(`>> ADMIN ACTION: ${action} on ${targetUser}`);
    
    try {
        if (action === 'ban') await User.updateOne({username: targetUser}, {isBanned: true});
        if (action === 'promote') await User.updateOne({username: targetUser}, {role: 'admin'});
        if (action === 'delete') await User.deleteOne({username: targetUser});
        res.json({status: 'ok'});
    } catch (e) { res.status(500).json({status: 'error'}); }
});

// --- EXCEL-READY EXPORT ENGINE ---

const CSV_HEADER = [
    {id: 'timestamp', title: 'DATETIME'},
    {id: 'temp_in', title: 'TEMPERATURE_C'},
    {id: 'hum_in', title: 'HUMIDITY_PCT'},
    {id: 'soil_moisture', title: 'SOIL_MOISTURE_PCT'},
    {id: 'npk_n', title: 'NITROGEN_MGKG'},
    {id: 'npk_p', title: 'PHOSPHORUS_MGKG'},
    {id: 'npk_k', title: 'POTASSIUM_MGKG'}
];

app.get('/api/download/standard', async (req, res) => {
    const logs = await SensorLog.find().sort({timestamp: -1}).limit(5000);
    const filePath = path.join(__dirname, 'biocube_master_logs.csv');
    const writer = createCsvWriter({ path: filePath, header: CSV_HEADER });
    
    await writer.writeRecords(logs);
    res.download(filePath);
});

app.get('/api/download/academic', async (req, res) => {
    // Both routes now output CSV to prevent Excel/JSON confusion
    const logs = await SensorLog.find().sort({timestamp: -1});
    const filePath = path.join(__dirname, 'biocube_full_history.csv');
    const writer = createCsvWriter({ path: filePath, header: CSV_HEADER });
    
    await writer.writeRecords(logs);
    res.download(filePath);
});

// --- REAL-TIME DATA HUB ---

io.on('connection', (socket) => {
    const clientIp = socket.handshake.address;
    console.log(`>> LINK ACTIVE: ${clientIp}`);

    socket.on('camera_frame', (data) => {
        socket.broadcast.emit('feed', data); 
    });

    socket.on('sensor_data', async (data) => {
        // High-frequency live broadcast
        io.emit('update', data); 
        
        // Low-frequency database logging (Every 30 seconds)
        const now = new Date();
        if (now.getSeconds() === 0 || now.getSeconds() === 30) { 
            try { 
                await SensorLog.create(data); 
                console.log(`>> DATA LOGGED: T:${data.temp_in} S:${data.soil_moisture}`);
            } catch(e) { console.error("Log error", e); }
        }
    });

    socket.on('control_cmd', (data) => {
        // Broadcaster for Arduino/Pi to pick up
        console.log(`>> OVERRIDE ISSUED: [${data.cmd}] Value:`, data.val);
        io.emit('control_cmd', data); 
    });
    
    socket.on('pi_status', (data) => {
        io.emit('pi_status', data);
    });

    socket.on('disconnect', () => console.log(`>> LINK SEVERED: ${clientIp}`));
});

// --- SERVER INITIALIZATION ---
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
    console.log(`
    --------------------------------------
    BIOCUBE CORE INTERFACE ONLINE
    PORT: ${PORT}
    MODE: PRODUCTION_STABLE
    --------------------------------------
    `);
});

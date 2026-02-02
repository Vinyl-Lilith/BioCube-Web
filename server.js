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
const MONGO_URI = process.env.MONGO_URI || "mongodb+srv://YOUR_MONGO_STRING";
const JWT_SECRET = process.env.JWT_SECRET || "supersecretbiocube";

// --- MIDDLEWARE ---
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// --- DATABASE MODELS ---
mongoose.connect(MONGO_URI).then(() => console.log("CORE SYSTEM: MongoDB Connected"));

const UserSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: { type: String, default: 'operator' }, 
    isBanned: { type: Boolean, default: false },
    canManual: { type: Boolean, default: true }, // Permission to use Manual Overrides
    canEditAuto: { type: Boolean, default: true } // Permission to change thresholds
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
    const isFirst = (await User.countDocuments({})) === 0;
    
    // First user is Admin with full permissions
    const role = isFirst ? 'admin' : 'operator';
    const hashedPassword = await bcrypt.hash(password, 10);
    
    try {
        const user = await User.create({ 
            username, 
            password: hashedPassword, 
            role,
            canManual: true,
            canEditAuto: true
        });
        res.json({ status: 'ok', role });
    } catch (e) {
        res.json({ status: 'error', error: 'Operator ID already exists' });
    }
});

app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    const user = await User.findOne({ username });
    
    if (!user) return res.json({ status: 'error', error: 'Invalid ID' });
    if (user.isBanned) return res.json({ status: 'error', error: 'Access Denied: Banned' });

    if (await bcrypt.compare(password, user.password)) {
        const token = jwt.sign({ id: user._id, role: user.role }, JWT_SECRET);
        res.json({ status: 'ok', token, role: user.role });
    } else {
        res.json({ status: 'error', error: 'Invalid Password' });
    }
});

// --- ADMIN CONTROL ROUTES ---
app.get('/api/users', async (req, res) => {
    // In a live system, add JWT verification middleware here
    const users = await User.find({}, 'username role isBanned canManual canEditAuto');
    res.json(users);
});

app.post('/api/admin/action', async (req, res) => {
    const { targetUser, action } = req.body;
    
    switch(action) {
        case 'ban': 
            await User.updateOne({username: targetUser}, {isBanned: true}); break;
        case 'promote': 
            await User.updateOne({username: targetUser}, {role: 'admin'}); break;
        case 'toggle_manual':
            const uM = await User.findOne({username: targetUser});
            await User.updateOne({username: targetUser}, {canManual: !uM.canManual}); break;
        case 'toggle_auto':
            const uA = await User.findOne({username: targetUser});
            await User.updateOne({username: targetUser}, {canEditAuto: !uA.canEditAuto}); break;
    }
    res.json({status: 'ok'});
});

// --- DATA EXPORT ---
app.get('/api/download/standard', async (req, res) => {
    const logs = await SensorLog.find().sort({timestamp: -1}).limit(2000);
    const csvWriter = createCsvWriter({
        path: 'biocube_master_logs.csv',
        header: [
            {id: 'timestamp', title: 'DATETIME'},
            {id: 'temp_in', title: 'TEMP_CELSIUS'},
            {id: 'hum_in', title: 'HUMIDITY_PERCENT'},
            {id: 'soil_moisture', title: 'SOIL_MOISTURE_PERCENT'},
            {id: 'npk_n', title: 'NITROGEN'},
            {id: 'npk_p', title: 'PHOSPHORUS'},
            {id: 'npk_k', title: 'POTASSIUM'}
        ]
    });
    await csvWriter.writeRecords(logs);
    res.download('biocube_master_logs.csv');
});

// --- SOCKET.IO REALTIME HUB ---
io.on('connection', (socket) => {
    console.log('New link established');

    // Camera Stream Handling
    socket.on('camera_frame', (data) => {
        io.emit('feed', data); 
    });

    // Sensor Data Inbound from Pi/Arduino
    socket.on('sensor_data', async (data) => {
        io.emit('update', data); 
        
        // Database Logging Throttling (log every 30 seconds approx)
        if(Date.now() % 30 === 0) { 
             try { await SensorLog.create(data); } catch(e) {}
        }
    });

    // Command Handling (Web -> Pi)
    socket.on('control_cmd', async (data) => {
        // Here you could add server-side validation:
        // if(data.cmd === 'water' && !user.canManual) return;
        
        console.log(`Command Issued: ${data.cmd} -> ${JSON.stringify(data.val)}`);
        io.emit('control_cmd', data); 
    });
    
    socket.on('pi_status', (data) => {
        io.emit('pi_status', data);
    });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`BIOCUBE SERVER ONLINE: PORT ${PORT}`));

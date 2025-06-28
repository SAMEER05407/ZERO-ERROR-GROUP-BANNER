const express = require('express');
const { makeWASocket, useMultiFileAuthState, DisconnectReason } = require('@whiskeysockets/baileys');
const QRCode = require('qrcode');
const fs = require('fs');
const path = require('path');
const { Server } = require('socket.io');
const http = require('http');
const session = require('express-session');
const crypto = require('crypto');

const app = express();
const server = http.createServer(app);
const io = new Server(server);

const PORT = 5000;
const sessionsDir = './sessions';
const tokensFile = './tokens.json';

// Store active WhatsApp sockets for each user
const userSockets = new Map();
const userConnections = new Map();

// Telegram redirect URL
const TELEGRAM_REDIRECT = 'https://t.me/reemasilhen';

// Initialize tokens file with simple format
if (!fs.existsSync(tokensFile)) {
    const initialTokens = '"9209778319"\n"9999999999"';
    fs.writeFileSync(tokensFile, initialTokens);
}

// Generate secure 10-digit token (phone number format)
function generateSecureToken() {
    // Use crypto for truly random numbers
    const buffer = crypto.randomBytes(5);
    const number = buffer.readUIntBE(0, 5) % 10000000000;
    return number.toString().padStart(10, '0');
}

// Load tokens from file
function loadTokens() {
    try {
        const data = fs.readFileSync(tokensFile, 'utf8');
        const lines = data.split('\n').filter(line => line.trim());
        const tokens = {};
        
        lines.forEach((line, index) => {
            const token = line.replace(/"/g, '').trim();
            if (token && token.length === 10) {
                tokens[token] = {
                    id: index === 0 ? "admin_primary" : `user_${token}`,
                    token: token,
                    isAdmin: index === 0, // First token is admin
                    createdAt: new Date().toISOString(),
                    lastLogin: null,
                    description: index === 0 ? "Primary Admin - Full Access" : "User Access",
                    loginAttempts: 0,
                    lockedUntil: null,
                    phone: token
                };
            }
        });
        
        return tokens;
    } catch (error) {
        return {};
    }
}

// Save tokens to file
function saveTokens(tokens) {
    const lines = Object.keys(tokens).map(token => `"${token}"`);
    fs.writeFileSync(tokensFile, lines.join('\n'));
}

// Rate limiting for login attempts
function isAccountLocked(tokenData) {
    if (!tokenData.lockedUntil) return false;

    const now = new Date();
    const lockTime = new Date(tokenData.lockedUntil);

    if (now < lockTime) {
        return true;
    } else {
        // Unlock account
        tokenData.lockedUntil = null;
        tokenData.loginAttempts = 0;
        return false;
    }
}

// Lock account after failed attempts
function lockAccount(tokenData) {
    tokenData.loginAttempts = (tokenData.loginAttempts || 0) + 1;

    if (tokenData.loginAttempts >= 3) {
        // Lock for 15 minutes after 3 failed attempts
        const lockTime = new Date();
        lockTime.setMinutes(lockTime.getMinutes() + 15);
        tokenData.lockedUntil = lockTime.toISOString();
    }
}

// Ensure sessions directory exists
if (!fs.existsSync(sessionsDir)) {
    fs.mkdirSync(sessionsDir);
}

// Session middleware with enhanced security
app.use(session({
    secret: crypto.randomBytes(64).toString('hex'),
    resave: false,
    saveUninitialized: false,
    cookie: { 
        secure: false,
        maxAge: 60 * 60 * 1000, // 1 hour
        httpOnly: true,
        sameSite: 'strict'
    },
    rolling: true, // Extend session on activity
    genid: function(req) {
        return crypto.randomUUID(); // Use crypto for session IDs
    }
}));

app.use(express.static('public'));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Authentication middleware
function requireAuth(req, res, next) {
    if (!req.session.loggedIn) {
        return res.redirect('/login');
    }
    next();
}

// Sanitize user ID for safe file operations
function sanitizeUserID(userID) {
    return userID.replace(/[^a-zA-Z0-9_]/g, '');
}

// Get user session directory
function getUserSessionDir(userID) {
    const sanitized = sanitizeUserID(userID);
    const userSessionPath = path.join(sessionsDir, `user_${sanitized}`);

    if (!fs.existsSync(userSessionPath)) {
        fs.mkdirSync(userSessionPath, { recursive: true });
        console.log(`Created session directory for user: ${userID}`);
    }

    return userSessionPath;
}

// Login page
app.get('/login', (req, res) => {
    if (req.session.loggedIn) {
        return res.redirect('/');
    }

    let errorMessage = '';
    const error = req.query.error;
    if (error === 'missing') {
        errorMessage = '<div class="error">🔑 10-digit access token is required!</div>';
    } else if (error === 'invalid') {
        errorMessage = '<div class="error">❌ Invalid 10-digit access token! Contact @reemasilhen on Telegram</div>';
    } else if (error === 'locked') {
        errorMessage = '<div class="error">🔒 Account locked due to multiple failed attempts. Try again in 15 minutes.</div>';
    }

    res.send(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>🔐 Secure Access - WhatsApp Banner Tool</title>
        <style>
            * {
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }
            body {
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh;
                display: flex;
                align-items: center;
                justify-content: center;
                padding: 20px;
            }
            .login-container {
                background: white;
                border-radius: 20px;
                box-shadow: 0 25px 50px rgba(0,0,0,0.25);
                padding: 50px;
                max-width: 450px;
                width: 100%;
                position: relative;
                overflow: hidden;
            }
            .login-container::before {
                content: '';
                position: absolute;
                top: 0;
                left: 0;
                right: 0;
                height: 5px;
                background: linear-gradient(90deg, #ff6b6b, #4ecdc4, #45b7d1, #96ceb4);
            }
            .header {
                text-align: center;
                margin-bottom: 40px;
            }
            .header h1 {
                color: #2c3e50;
                font-size: 2.2em;
                margin-bottom: 10px;
                font-weight: 700;
            }
            .header p {
                color: #7f8c8d;
                font-size: 1.1em;
            }
            .form-group {
                margin-bottom: 25px;
            }
            .form-group label {
                display: block;
                margin-bottom: 10px;
                font-weight: 600;
                color: #2c3e50;
                font-size: 1.1em;
            }
            .token-input {
                width: 100%;
                padding: 18px 20px;
                border: 3px solid #ecf0f1;
                border-radius: 12px;
                font-size: 20px;
                font-weight: 600;
                text-align: center;
                letter-spacing: 8px;
                transition: all 0.3s ease;
                background: #f8f9fa;
            }
            .token-input:focus {
                outline: none;
                border-color: #667eea;
                box-shadow: 0 0 0 4px rgba(102, 126, 234, 0.15);
                background: white;
            }
            .btn {
                width: 100%;
                padding: 18px;
                background: linear-gradient(135deg, #667eea, #764ba2);
                color: white;
                border: none;
                border-radius: 12px;
                font-size: 18px;
                font-weight: 600;
                cursor: pointer;
                transition: all 0.3s ease;
                position: relative;
                overflow: hidden;
            }
            .btn:hover {
                transform: translateY(-2px);
                box-shadow: 0 10px 25px rgba(102, 126, 234, 0.4);
            }
            .btn:active {
                transform: translateY(0);
            }
            .error {
                background: linear-gradient(135deg, #ff6b6b, #ee5a6f);
                color: white;
                padding: 15px 20px;
                border-radius: 10px;
                margin-bottom: 25px;
                text-align: center;
                font-weight: 500;
                box-shadow: 0 5px 15px rgba(255, 107, 107, 0.3);
            }
            .contact-note {
                background: linear-gradient(135deg, #f8f9fa, #e9ecef);
                border: 2px solid #dee2e6;
                border-radius: 12px;
                padding: 20px;
                margin-top: 30px;
                text-align: center;
                font-size: 14px;
                color: #495057;
            }
            .telegram-link {
                color: #0088cc;
                text-decoration: none;
                font-weight: 600;
                transition: color 0.3s ease;
            }
            .telegram-link:hover {
                color: #006699;
            }
            .security-badge {
                position: absolute;
                top: 20px;
                right: 20px;
                background: linear-gradient(135deg, #28a745, #20c997);
                color: white;
                padding: 8px 12px;
                border-radius: 20px;
                font-size: 12px;
                font-weight: 600;
                box-shadow: 0 3px 10px rgba(40, 167, 69, 0.3);
            }
            .examples {
                margin-top: 10px;
                font-size: 13px;
                color: #6c757d;
                text-align: center;
            }
        </style>
    </head>
    <body>
        <div class="login-container">
            <div class="security-badge">🔒 SECURE</div>

            <div class="header">
                <h1>🔐 Secure Access</h1>
                <p>WhatsApp Banner Tool - Phone Login</p>
            </div>

            ${errorMessage}

            <form method="POST" action="/login">
                <div class="form-group">
                    <label for="token">🔑 Access Token</label>
                    <input type="text" id="token" name="token" class="token-input" placeholder="••••••••••" maxlength="10" required autocomplete="off">
                    <div class="examples">Enter your 10-digit access token</div>
                </div>

                <button type="submit" class="btn">🚀 Access System</button>
            </form>

            <div class="contact-note">
                <strong>Need Access?</strong><br>
                Contact <a href="${TELEGRAM_REDIRECT}" class="telegram-link" target="_blank">@reemasilhen</a> on Telegram for token
            </div>
        </div>

        <script>
            // Auto redirect to Telegram on invalid token
            const urlParams = new URLSearchParams(window.location.search);
            if (urlParams.get('error') === 'invalid') {
                setTimeout(() => {
                    window.open('${TELEGRAM_REDIRECT}', '_blank');
                }, 3000);
            }

            // Token input validation
            document.getElementById('token').addEventListener('input', function(e) {
                e.target.value = e.target.value.replace(/\D/g, '').substring(0, 10);
            });

            // Prevent form submission with invalid token
            document.querySelector('form').addEventListener('submit', function(e) {
                const token = document.getElementById('token').value;
                if (token.length !== 10) {
                    e.preventDefault();
                    alert('Please enter a valid 10-digit token');
                }
            });
        </script>
    </body>
    </html>
    `);
});

// Handle login
app.post('/login', (req, res) => {
    const { token } = req.body;

    if (!token || token.length !== 10) {
        return res.redirect('/login?error=missing');
    }

    const tokens = loadTokens();
    const tokenData = tokens[token];

    if (!tokenData) {
        return res.redirect('/login?error=invalid');
    }

    // Check if account is locked
    if (isAccountLocked(tokenData)) {
        return res.redirect('/login?error=locked');
    }

    // Reset login attempts on successful login
    tokenData.loginAttempts = 0;
    tokenData.lockedUntil = null;
    tokenData.lastLogin = new Date().toISOString();
    saveTokens(tokens);

    // Set session
    req.session.loggedIn = true;
    req.session.token = token;
    req.session.userID = tokenData.id;
    req.session.isAdmin = tokenData.isAdmin || false;

    console.log(`User ${tokenData.id} logged in with token ${token}`);
    res.redirect('/dashboard');
});

// Logout
app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/login');
});

// Root page - redirect to login if not authenticated, otherwise go to dashboard
app.get('/', (req, res) => {
    if (!req.session || !req.session.loggedIn) {
        return res.redirect('/login');
    }

    const tokens = loadTokens();
    const tokenData = tokens[req.session.token];

    if (!tokenData) {
        req.session.destroy((err) => {
            if (err) console.log('Session destroy error:', err);
            return res.redirect('/login');
        });
        return;
    }

    res.redirect('/dashboard');
});

// Dashboard/Tool page (protected)
app.get('/dashboard', requireAuth, (req, res) => {
    const tokens = loadTokens();
    const tokenData = tokens[req.session.token];

    if (!tokenData) {
        req.session.destroy((err) => {
            if (err) console.log('Session destroy error:', err);
            return res.redirect('/login');
        });
        return;
    }

    console.log(`User ${req.session.userID} accessing dashboard`);
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Enhanced WhatsApp connection with improved QR generation
async function connectUserToWhatsApp(userID, socketId = null) {
    try {
        console.log(`Initializing enhanced WhatsApp connection for user: ${userID}`);

        // Prevent multiple simultaneous connections for the same user
        if (userSockets.has(userID)) {
            console.log(`Connection already exists for user ${userID}, cleaning up first...`);
            const existingSock = userSockets.get(userID);
            try {
                existingSock.ev.removeAllListeners();
                // Check if socket is still active before attempting logout
                if (existingSock.user && existingSock.ws && existingSock.ws.readyState === 1) {
                    await existingSock.logout();
                }
                // Safely end the socket
                if (existingSock.end) {
                    existingSock.end();
                }
            } catch (error) {
                console.log(`Error closing existing socket for ${userID}:`, error.message);
            }
            userSockets.delete(userID);
            
            // Wait a bit before creating new connection
            await new Promise(resolve => setTimeout(resolve, 2000));
        }

        const userSessionDir = getUserSessionDir(userID);
        const { state, saveCreds } = await useMultiFileAuthState(userSessionDir);

        const sock = makeWASocket({
            auth: state,
            printQRInTerminal: false,
            generateHighQualityLinkPreview: true,
            qrTimeout: 60000, // 60 second QR timeout
            connectTimeoutMs: 60000,
            defaultQueryTimeoutMs: 60000,
            keepAliveIntervalMs: 30000,
            browser: ["WhatsApp Banner Tool", "Chrome", "1.0.0"],
            syncFullHistory: false,
            markOnlineOnConnect: true
        });

        // Store socket immediately to prevent duplicate connections
        userSockets.set(userID, sock);

        sock.ev.on('creds.update', saveCreds);

        sock.ev.on('connection.update', async (update) => {
            const { connection, lastDisconnect, qr } = update;

            if (qr) {
                console.log(`Enhanced QR generated for user ${userID}`);

                try {
                    // Generate high-quality QR with custom styling
                    const qrCodeDataURL = await QRCode.toDataURL(qr, {
                        errorCorrectionLevel: 'M',
                        type: 'image/png',
                        quality: 0.92,
                        margin: 2,
                        color: {
                            dark: '#2c3e50',
                            light: '#ffffff'
                        },
                        width: 300
                    });

                    if (socketId) {
                        io.to(socketId).emit('qr', qrCodeDataURL);
                    } else {
                        io.to(`user-${userID}`).emit('qr', qrCodeDataURL);
                    }
                } catch (qrError) {
                    console.error(`QR generation error for user ${userID}:`, qrError);
                }
            }

            if (connection === 'close') {
                const shouldReconnect = (lastDisconnect?.error)?.output?.statusCode !== DisconnectReason.loggedOut;
                userConnections.set(userID, false);

                console.log(`User ${userID} WhatsApp connection closed`);

                if (socketId) {
                    io.to(socketId).emit('disconnected');
                } else {
                    io.to(`user-${userID}`).emit('disconnected');
                }

                // Clean up the socket from memory
                userSockets.delete(userID);

                if (shouldReconnect) {
                    console.log(`Reconnecting user ${userID} in 5 seconds...`);
                    setTimeout(() => {
                        if (!userSockets.has(userID)) { // Only reconnect if no new connection exists
                            connectUserToWhatsApp(userID, socketId);
                        }
                    }, 5000);
                } else {
                    console.log(`Cleaning up session for user ${userID}`);
                    userConnections.delete(userID);
                }
            } else if (connection === 'open') {
                userConnections.set(userID, true);

                if (socketId) {
                    io.to(socketId).emit('connected');
                } else {
                    io.to(`user-${userID}`).emit('connected');
                }

                console.log(`User ${userID} successfully connected to WhatsApp`);
            }
        });

        // Add comprehensive error handling for the socket
        sock.ev.on('error', (error) => {
            console.error(`WhatsApp socket error for user ${userID}:`, error);
            userConnections.set(userID, false);
            
            // Clean up socket on error
            if (userSockets.has(userID)) {
                userSockets.delete(userID);
            }
            
            if (socketId) {
                io.to(socketId).emit('error', 'Connection error occurred');
            } else {
                io.to(`user-${userID}`).emit('error', 'Connection error occurred');
            }
        });

        // Handle WebSocket close errors specifically
        process.on('uncaughtException', (error) => {
            if (error.message.includes('WebSocket was closed before the connection was established')) {
                console.error(`WebSocket connection error for user ${userID}:`, error.message);
                userConnections.set(userID, false);
                
                // Clean up socket on WebSocket error
                if (userSockets.has(userID)) {
                    userSockets.delete(userID);
                }
                
                if (socketId) {
                    io.to(socketId).emit('error', 'WebSocket connection failed');
                    io.to(socketId).emit('disconnected');
                } else {
                    io.to(`user-${userID}`).emit('error', 'WebSocket connection failed');
                    io.to(`user-${userID}`).emit('disconnected');
                }
                return; // Don't crash the server
            }
            
            // Re-throw other uncaught exceptions
            throw error;
        });

        return sock;

    } catch (error) {
        console.error(`Error connecting user ${userID} to WhatsApp:`, error);
        
        // Clean up on error
        if (userSockets.has(userID)) {
            userSockets.delete(userID);
        }
        
        if (socketId) {
            io.to(socketId).emit('error', error.message);
        } else {
            io.to(`user-${userID}`).emit('error', error.message);
        }
        return null;
    }
}

// Get user's socket status
app.get('/user-status', (req, res) => {
    if (!req.session || !req.session.loggedIn) {
        return res.status(401).json({ 
            error: 'Not authenticated',
            connected: false,
            userID: null,
            redirectToLogin: true
        });
    }

    const tokens = loadTokens();
    const tokenData = tokens[req.session.token];

    if (!tokenData) {
        req.session.destroy((err) => {
            if (err) console.log('Session destroy error:', err);
        });
        return res.status(401).json({ 
            error: 'Invalid token',
            connected: false,
            userID: null,
            redirectToLogin: true
        });
    }

    const userID = req.session.userID;
    const isConnected = userConnections.get(userID) || false;

    res.json({ 
        connected: isConnected, 
        userID: userID,
        user: tokenData
    });
});

// Process groups - Banner Tool Logic
app.post('/process-groups', requireAuth, async (req, res) => {
    const userID = req.session.userID;
    const sock = userSockets.get(userID);
    const isConnected = userConnections.get(userID) || false;

    if (!isConnected || !sock) {
        return res.json({ success: false, message: 'WhatsApp not connected' });
    }

    const { groupLinks, makeAdmin, foreignNumbers } = req.body;
    const links = groupLinks.split('\n').filter(link => link.trim());
    const numbers = foreignNumbers.filter(num => num.trim());

    try {
        for (const link of links) {
            try {
                io.emit('user-status', { userID, message: `🔗 Processing group: ${link}` });

                const groupCode = link.split('/').pop().split('?')[0];
                const joinResult = await sock.groupAcceptInvite(groupCode);
                io.emit('user-status', { userID, message: `✅ Joined group: ${joinResult}` });

                await new Promise(resolve => setTimeout(resolve, 3000));

                const groupMetadata = await sock.groupMetadata(joinResult);
                const currentUserId = sock.user.id;

                if (makeAdmin) {
                    io.emit('user-status', { userID, message: `👥 Making all members admin...` });

                    const nonAdmins = groupMetadata.participants
                        .filter(p => !p.admin && p.id !== currentUserId);

                    if (nonAdmins.length > 0) {
                        const numbersToPromote = nonAdmins.map(p => p.id);

                        try {
                            await sock.groupParticipantsUpdate(joinResult, numbersToPromote, 'promote');
                            io.emit('user-status', { userID, message: `🔥 Promoted ${numbersToPromote.length} members to admin` });
                        } catch (promoteError) {
                            io.emit('user-status', { userID, message: `⚠️ Failed to promote some members: ${promoteError.message}` });
                        }

                        try {
                            await sock.groupParticipantsUpdate(joinResult, [currentUserId], 'promote');
                            io.emit('user-status', { userID, message: `👑 Current user promoted to admin` });
                        } catch (selfPromoteError) {
                            io.emit('user-status', { userID, message: `⚠️ Already admin or failed to promote self` });
                        }
                    }

                    await new Promise(resolve => setTimeout(resolve, 2000));
                }

                if (numbers.length > 0) {
                    io.emit('user-status', { userID, message: `🌍 Adding ${numbers.length} foreign numbers...` });

                    const formattedNumbers = numbers.map(num => {
                        let formatted = num.replace(/\D/g, '');
                        if (formatted.startsWith('00')) {
                            formatted = formatted.substring(2);
                        }
                        if (!formatted.includes('@')) {
                            formatted = formatted + '@s.whatsapp.net';
                        }
                        return formatted;
                    });

                    try {
                        await sock.groupParticipantsUpdate(joinResult, formattedNumbers, 'add');
                        io.emit('user-status', { userID, message: `🚀 Successfully added all foreign numbers` });
                    } catch (addError) {
                        if (addError.message.includes('not allowed') || addError.message.includes('privacy')) {
                            io.emit('user-status', { userID, message: `⚠️ Group privacy settings prevent adding numbers` });
                        } else if (addError.message.includes('full') || addError.message.includes('capacity')) {
                            io.emit('user-status', { userID, message: `⚠️ Group is full, skipping number additions` });
                        } else {
                            io.emit('user-status', { userID, message: `⚠️ Failed to add numbers: ${addError.message}` });
                        }
                    }
                }

                await new Promise(resolve => setTimeout(resolve, 1500));

            } catch (groupError) {
                io.emit('user-status', { userID, message: `❌ Error processing group ${link}: ${groupError.message}` });
            }
        }

        io.emit('user-status', { userID, message: '🎉 All groups processed successfully! Banner tool complete.' });
        res.json({ success: true });

    } catch (error) {
        io.emit('user-status', { userID, message: `💥 Error: ${error.message}` });
        res.json({ success: false, message: error.message });
    }
});

// Restart session for specific user
app.post('/restart-session', requireAuth, async (req, res) => {
    const userID = req.session.userID;

    try {
        console.log(`Restarting session for user ${userID}`);

        // First, properly clean up existing socket
        if (userSockets.has(userID)) {
            const sock = userSockets.get(userID);
            try {
                // Remove all event listeners to prevent memory leaks
                sock.ev.removeAllListeners();
                
                // Only attempt logout if socket is properly connected
                if (sock.user && sock.ws && sock.ws.readyState === 1) {
                    await Promise.race([
                        sock.logout(),
                        new Promise((_, reject) => setTimeout(() => reject(new Error('Logout timeout')), 5000))
                    ]);
                }
                
                // Force close the socket
                if (sock.end) {
                    sock.end();
                }
                
                // Also close WebSocket connection if it exists
                if (sock.ws && sock.ws.readyState === 1) {
                    sock.ws.close();
                }
            } catch (error) {
                console.log(`Error during socket cleanup for ${userID}:`, error.message);
                // Continue with cleanup even if logout fails
            }
            userSockets.delete(userID);
        }

        // Clean up session directory
        const userSessionDir = getUserSessionDir(userID);
        if (fs.existsSync(userSessionDir)) {
            try {
                fs.rmSync(userSessionDir, { recursive: true, force: true });
                console.log(`Deleted session directory for user ${userID}`);
            } catch (fsError) {
                console.log(`Error deleting session directory: ${fsError.message}`);
            }
        }

        // Update connection status
        userConnections.set(userID, false);
        
        // Emit disconnected state to client
        io.to(`user-${userID}`).emit('disconnected');

        // Return success immediately and start new connection after response
        res.json({ success: true, message: 'Session restarted successfully' });

        // Initialize new session after a delay
        setTimeout(async () => {
            try {
                console.log(`Initializing fresh session for user ${userID}`);
                await connectUserToWhatsApp(userID);
            } catch (connectError) {
                console.error(`Error initializing fresh session for ${userID}:`, connectError.message);
                io.to(`user-${userID}`).emit('error', 'Failed to initialize new session');
            }
        }, 3000);

    } catch (error) {
        console.error(`Error restarting session for ${userID}:`, error);
        res.json({ success: false, message: `Restart failed: ${error.message}` });
    }
});

// Socket.io connection
io.on('connection', (socket) => {
    console.log('Client connected');

    socket.on('initialize-session', (sessionData) => {
        const userID = sessionData?.userID;

        if (!userID) {
            console.log(`Socket ${socket.id} missing user authentication`);
            socket.emit('error', 'Authentication required');
            socket.disconnect();
            return;
        }

        const tokens = loadTokens();
        const validUser = Object.values(tokens).find(token => token.id === userID);

        if (!validUser) {
            console.log(`Socket ${socket.id} invalid user: ${userID}`);
            console.log('Available user IDs:', Object.values(tokens).map(t => t.id));
            socket.emit('error', 'Invalid user');
            socket.disconnect();
            return;
        }

        // Additional validation to ensure this socket session matches an active user session
        socket.userID = userID;
        socket.join(`user-${userID}`);
        console.log(`Socket ${socket.id} authenticated and joined room for user ${userID}`);

        const isConnected = userConnections.get(userID) || false;
        if (isConnected) {
            socket.emit('connected');
        } else {
            // Only create new connection if one doesn't exist
            if (!userSockets.has(userID)) {
                console.log(`Initializing new WhatsApp session for user ${userID}`);
                connectUserToWhatsApp(userID, socket.id);
            } else {
                // If socket exists but not connected, emit disconnected state
                socket.emit('disconnected');
            }
        }
    });

    socket.on('request-qr', async () => {
        if (socket.userID) {
            const userID = socket.userID;
            const isConnected = userConnections.get(userID) || false;

            console.log(`Manual QR request for user ${userID}, connected: ${isConnected}`);

            if (!isConnected) {
                // Close existing socket if any
                if (userSockets.has(userID)) {
                    const existingSock = userSockets.get(userID);
                    try {
                        existingSock.ev.removeAllListeners();
                        if (existingSock.end) {
                            existingSock.end();
                        }
                    } catch (error) {
                        console.log(`Error closing existing socket: ${error.message}`);
                    }
                    userSockets.delete(userID);
                }

                console.log(`Generating fresh enhanced QR for user ${userID}`);
                // Wait a moment before creating new connection
                setTimeout(async () => {
                    await connectUserToWhatsApp(userID, socket.id);
                }, 1000);
            } else {
                socket.emit('error', 'Already connected to WhatsApp');
            }
        }
    });

    socket.on('disconnect', () => {
        console.log('Client disconnected');
        if (socket.userID) {
            const userID = socket.userID;
            // Don't close WhatsApp connection just because web client disconnected
            console.log(`Web client disconnected for user ${userID}, keeping WhatsApp session`);
        }
    });
});

// Clear all existing sessions on server start
function clearAllSessions() {
    try {
        userSockets.clear();
        userConnections.clear();
        console.log('✅ All previous sessions cleared');
    } catch (error) {
        console.log('Error clearing sessions:', error.message);
    }
}

// Start server
server.listen(PORT, '0.0.0.0', () => {
    console.log(`Server running on http://0.0.0.0:${PORT}`);
    console.log('Enhanced Secure WhatsApp Banner Tool ready!');

    const tokens = loadTokens();
    const adminTokens = Object.keys(tokens).filter(token => tokens[token].isAdmin);
    console.log(`Admin tokens: ${adminTokens.join(', ')}`);

    clearAllSessions();
    console.log('🔐 All users must login again with secure tokens');
});

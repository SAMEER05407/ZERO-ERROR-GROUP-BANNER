
// Admin endpoints for user management
app.get('/admin', requireAuth, (req, res) => {
    if (!req.session.isAdmin) {
        return res.redirect('/dashboard');
    }
    res.sendFile(path.join(__dirname, 'admin.html'));
});

app.get('/admin/users', requireAuth, (req, res) => {
    if (!req.session.isAdmin) {
        return res.json({ success: false, message: 'Access denied' });
    }

    const tokens = loadTokens();
    const users = {};

    Object.values(tokens).forEach(user => {
        users[user.token] = {
            phone: user.token,
            description: user.description,
            isAdmin: user.isAdmin,
            createdAt: user.createdAt,
            lastLogin: user.lastLogin
        };
    });

    res.json({ success: true, users });
});

app.post('/admin/add-user', requireAuth, (req, res) => {
    if (!req.session.isAdmin) {
        return res.json({ success: false, message: 'Access denied' });
    }

    const { phone, description, isAdmin } = req.body;

    if (!phone || phone.length !== 10) {
        return res.json({ success: false, message: 'Phone number must be 10 digits' });
    }

    const tokens = loadTokens();

    if (tokens[phone]) {
        return res.json({ success: false, message: 'Phone number already exists' });
    }

    // Add to simple format file
    const currentData = fs.readFileSync(tokensFile, 'utf8');
    const newData = currentData.trim() + '\n' + `"${phone}"`;
    fs.writeFileSync(tokensFile, newData);

    res.json({ 
        success: true, 
        phone: phone,
        message: 'Phone number added successfully' 
    });
});

app.post('/admin/remove-user', requireAuth, (req, res) => {
    if (!req.session.isAdmin) {
        return res.json({ success: false, message: 'Access denied' });
    }

    const { phone } = req.body;
    const tokens = loadTokens();

    if (!tokens[phone]) {
        return res.json({ success: false, message: 'Phone number not found' });
    }

    if (tokens[phone].isAdmin && phone === req.session.token) {
        return res.json({ success: false, message: 'Cannot remove your own admin account' });
    }

    // Remove from simple format file
    const currentData = fs.readFileSync(tokensFile, 'utf8');
    const lines = currentData.split('\n').filter(line => {
        const cleanLine = line.replace(/"/g, '').trim();
        return cleanLine !== phone && line.trim() !== '';
    });
    fs.writeFileSync(tokensFile, lines.join('\n'));

    res.json({ success: true, message: 'Phone number removed successfully' });
});

app.post('/admin/regenerate-code', requireAuth, (req, res) => {
    if (!req.session.isAdmin) {
        return res.json({ success: false, message: 'Access denied' });
    }

    const { oldPhone } = req.body;
    const tokens = loadTokens();

    if (!tokens[oldPhone]) {
        return res.json({ success: false, message: 'Phone number not found' });
    }

    const newPhone = generateSecureToken();
    
    // Update in simple format file
    const currentData = fs.readFileSync(tokensFile, 'utf8');
    const lines = currentData.split('\n').map(line => {
        const cleanLine = line.replace(/"/g, '').trim();
        if (cleanLine === oldPhone) {
            return `"${newPhone}"`;
        }
        return line;
    });
    fs.writeFileSync(tokensFile, lines.join('\n'));

    res.json({ 
        success: true, 
        phone: newPhone,
        message: 'New phone number generated successfully' 
    });
});

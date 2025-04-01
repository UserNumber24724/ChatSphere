const express = require('express');
const WebSocket = require('ws');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const path = require('path');
const fs = require('fs').promises;

const app = express();
const port = 3000;

const dbConfig = {
    host: 'localhost',
    user: 'root', // Replace with your MariaDB username
    password: '', // Replace with your MariaDB password
    database: 'chat_app',
    connectionLimit: 10
};

const pool = mysql.createPool(dbConfig);

const uploadsDir = path.join(__dirname, 'public', 'uploads');
fs.mkdir(uploadsDir, { recursive: true }).catch(err => console.error('Failed to create uploads dir:', err));

async function initializeDatabase() {
    try {
        const connection = await pool.getConnection();
        await connection.query('CREATE DATABASE IF NOT EXISTS chat_app');
        await connection.query('USE chat_app');

        await connection.query(`
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(15) UNIQUE NOT NULL,
                password VARCHAR(255) NOT NULL,
                isAdmin TINYINT DEFAULT 0,
                banned TINYINT DEFAULT 0
            )
        `);

        await connection.query(`
            CREATE TABLE IF NOT EXISTS messages (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(15) NOT NULL,
                message TEXT,
                file_type VARCHAR(50),
                file_path VARCHAR(255),
                reply_to INT,  -- New column for reply reference
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (reply_to) REFERENCES messages(id) ON DELETE SET NULL
            )
        `);

        connection.release();
        console.log('Connected to MariaDB and initialized tables');
    } catch (err) {
        console.error('Database initialization error:', err);
        process.exit(1);
    }
}

initializeDatabase();

app.use(express.static('public'));
app.use(express.json());
app.use('/uploads', express.static(uploadsDir));

app.get('/admin', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

app.post('/register', async (req, res) => {
    const { username, password } = req.body;
    if (!username || username.length > 20) {
        return res.status(400).json({ error: 'Username must be between 10 and 15 characters' });
    }
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        await pool.query(
            'INSERT INTO users (username, password) VALUES (?, ?)',
            [username, hashedPassword]
        );
        res.status(201).json({ 
            message: 'User registered successfully',
            username: username 
        });
    } catch (err) {
        if (err.code === 'ER_DUP_ENTRY') {
            res.status(400).json({ error: 'Username already exists' });
        } else {
            console.error('Register error:', err);
            res.status(500).json({ error: 'Server error' });
        }
    }
});

app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    if (!username || username.length > 20) {
        return res.status(400).json({ error: 'Username must be between 10 and 15 characters' });
    }
    try {
        const [rows] = await pool.query(
            'SELECT * FROM users WHERE username = ?',
            [username]
        );
        
        if (rows.length === 0) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const user = rows[0];
        if (user.banned) {
            return res.status(403).json({ error: 'You are banned' });
        }

        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        res.json({ 
            username: user.username,
            isAdmin: user.isAdmin
        });
    } catch (err) {
        console.error('Login error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

const server = app.listen(port, () => console.log(`Server running on port ${port}`));
const wss = new WebSocket.Server({ server });
const clients = new Map();
const MAX_CHARS = 2000;
const MAX_FILE_SIZE = 500 * 1024 * 1024; // 500MB

wss.on('connection', (ws) => {
    let clientUsername = null;

    ws.on('message', async (data) => {
        try {
            const messageStr = data.toString();
            console.log('Raw data received:', messageStr);

            let message;
            try {
                message = JSON.parse(messageStr);
            } catch (parseErr) {
                console.error('JSON parse error:', parseErr);
                ws.send(JSON.stringify({
                    type: 'error',
                    text: 'Invalid message format'
                }));
                return;
            }

            console.log('Parsed message:', message);

            if (message.type === 'auth') {
                clientUsername = message.username;
                if (!clientUsername) {
                    ws.send(JSON.stringify({
                        type: 'error',
                        text: 'Username required for authentication'
                    }));
                    return;
                }

                const existingClient = clients.get(clientUsername);
                if (existingClient && existingClient.readyState === WebSocket.OPEN) {
                    console.log(`Kicking existing connection for ${clientUsername}`);
                    existingClient.send(JSON.stringify({
                        type: 'kicked_elsewhere',
                        text: 'Logged in from another location'
                    }));
                    existingClient.close(1000, 'Logged in elsewhere');
                    await new Promise(resolve => setTimeout(resolve, 100));
                }

                clients.set(clientUsername, ws);
                console.log(`Client authenticated: ${clientUsername}`);
                console.log('Current clients:', Array.from(clients.keys()));
                broadcastUserList();
                broadcastJoin(clientUsername);
            } else if (message.type === 'message') {
                if (!clientUsername) {
                    ws.send(JSON.stringify({
                        type: 'error',
                        text: 'Not authenticated'
                    }));
                    return;
                }

                const [userRows] = await pool.query(
                    'SELECT isAdmin FROM users WHERE username = ?',
                    [clientUsername]
                );
                if (userRows.length === 0) {
                    ws.send(JSON.stringify({
                        type: 'error',
                        text: 'User not found'
                    }));
                    return;
                }
                const isAdmin = userRows[0].isAdmin;

                let fileType = 'text';
                let filePath = null;
                let text = message.text || null;
                let replyTo = message.reply_to || null; // New: Reply reference

                if (text && typeof text === 'string' && text.length > MAX_CHARS) {
                    ws.send(JSON.stringify({
                        type: 'error',
                        text: `Message exceeds ${MAX_CHARS} characters`
                    }));
                    return;
                }
                if ((!text || text.trim() === '') && !message.file) {
                    ws.send(JSON.stringify({
                        type: 'error',
                        text: 'Message cannot be empty or blank'
                    }));
                    return;
                }

                if (message.file && message.file_data) {
                    const fileSize = Buffer.byteLength(message.file_data, 'base64');
                    if (fileSize > MAX_FILE_SIZE) {
                        ws.send(JSON.stringify({
                            type: 'error',
                            text: 'File size exceeds 500MB limit'
                        }));
                        return;
                    }
                    fileType = message.file;
                    const fileName = `${Date.now()}-${Math.random().toString(36).substring(2, 15)}.${fileType.split('/')[1]}`;
                    filePath = `/uploads/${fileName}`;
                    const fileBuffer = Buffer.from(message.file_data, 'base64');
                    await fs.writeFile(path.join(uploadsDir, fileName), fileBuffer);
                    text = null;
                }

                if (isAdmin && text && text.startsWith('/')) {
                    const [command, target] = text.split(' ');
                    if (command === '/kick' && target) {
                        if (target === 'UserNumber2') {
                            broadcastSystemMessage(`${clientUsername} attempted to kick UserNumber2 (protected)`);
                            return;
                        }
                        const targetWs = clients.get(target);
                        if (targetWs) {
                            targetWs.send(JSON.stringify({ type: 'kick' }));
                            targetWs.close(1000, 'Kicked by admin');
                            clients.delete(target);
                            broadcastSystemMessage(`${target} has been kicked by ${clientUsername}`);
                            broadcastUserList();
                        } else {
                            ws.send(JSON.stringify({
                                type: 'error',
                                text: `User ${target} not found or not online`
                            }));
                        }
                    } else if (command === '/ban' && target) {
                        console.log(`Ban attempt by ${clientUsername} on ${target}`);
                        if (target === clientUsername) {
                            ws.send(JSON.stringify({
                                type: 'error',
                                text: 'You cannot ban yourself'
                            }));
                            return;
                        }
                        if (target === 'UserNumber2') {
                            broadcastSystemMessage(`${clientUsername} attempted to ban UserNumber2 (protected)`);
                            return;
                        }
                        const [targetRows] = await pool.query(
                            'SELECT * FROM users WHERE username = ?',
                            [target]
                        );
                        if (targetRows.length === 0) {
                            ws.send(JSON.stringify({
                                type: 'error',
                                text: `User ${target} not found in database`
                            }));
                            return;
                        }
                        console.log(`Updating DB: Banning ${target}`);
                        await pool.query(
                            'UPDATE users SET banned = 1 WHERE username = ?',
                            [target]
                        );
                        const targetWs = clients.get(target);
                        if (targetWs) {
                            console.log(`Closing WebSocket for ${target}`);
                            targetWs.send(JSON.stringify({ type: 'ban' }));
                            targetWs.close(1000, 'Banned by admin');
                            clients.delete(target);
                        }
                        broadcastSystemMessage(`${target} has been banned by ${clientUsername}`);
                        broadcastUserList();
                    } else if (command === '/unban' && target) {
                        console.log(`Unban attempt by ${clientUsername} on ${target}`);
                        if (target === 'UserNumber2') {
                            broadcastSystemMessage(`${clientUsername} attempted to unban UserNumber2 (not banned)`);
                            return;
                        }
                        const [targetRows] = await pool.query(
                            'SELECT * FROM users WHERE username = ?',
                            [target]
                        );
                        if (targetRows.length === 0) {
                            ws.send(JSON.stringify({
                                type: 'error',
                                text: `User ${target} not found in database`
                            }));
                            return;
                        }
                        if (!targetRows[0].banned) {
                            ws.send(JSON.stringify({
                                type: 'error',
                                text: `${target} is not banned`
                            }));
                            return;
                        }
                        console.log(`Updating DB: Unbanning ${target}`);
                        await pool.query(
                            'UPDATE users SET banned = 0 WHERE username = ?',
                            [target]
                        );
                        broadcastSystemMessage(`${target} has been unbanned by ${clientUsername}`);
                    } else if (command === '/clear') {
                        console.log(`Clear chat attempt by ${clientUsername}`);
                        const [rows] = await pool.query('SELECT file_path FROM messages WHERE file_path IS NOT NULL');
                        for (const row of rows) {
                            try {
                                await fs.unlink(path.join(__dirname, 'public', row.file_path));
                            } catch (err) {
                                console.error(`Failed to delete file ${row.file_path}:`, err);
                            }
                        }
                        await pool.query('DELETE FROM messages');
                        wss.clients.forEach(client => {
                            if (client.readyState === WebSocket.OPEN) {
                                client.send(JSON.stringify({ type: 'clear' }));
                            }
                        });
                        broadcastSystemMessage(`Chat cleared by ${clientUsername}`);
                        return;
                    } else if (command === '/admingrant' && target) {
                        const [targetRows] = await pool.query(
                            'SELECT * FROM users WHERE username = ?',
                            [target]
                        );
                        if (targetRows.length > 0) {
                            await pool.query(
                                'UPDATE users SET isAdmin = 1 WHERE username = ?',
                                [target]
                            );
                            broadcastSystemMessage(`${target} has been granted admin privileges by ${clientUsername}`);
                        } else {
                            broadcastSystemMessage(`User ${target} not found`);
                        }
                    } else if (command === '/adminrevoke' && target) {
                        if (target === 'UserNumber2') {
                            broadcastSystemMessage(`${clientUsername} attempted to revoke admin from UserNumber2 (protected)`);
                            return;
                        }
                        const [targetRows] = await pool.query(
                            'SELECT * FROM users WHERE username = ?',
                            [target]
                        );
                        if (targetRows.length > 0) {
                            await pool.query(
                                'UPDATE users SET isAdmin = 0 WHERE username = ?',
                                [target]
                            );
                            broadcastSystemMessage(`${target}'s admin privileges have been revoked by ${clientUsername}`);
                        } else {
                            broadcastSystemMessage(`User ${target} not found`);
                        }
                    } else if (command === '/admindelete' && target) {
                        if (target === 'UserNumber2') {
                            broadcastSystemMessage(`${clientUsername} attempted to delete UserNumber2 (protected)`);
                            return;
                        }
                        const [targetRows] = await pool.query(
                            'SELECT * FROM users WHERE username = ?',
                            [target]
                        );
                        if (targetRows.length > 0) {
                            await pool.query(
                                'DELETE FROM users WHERE username = ?',
                                [target]
                            );
                            const targetWs = clients.get(target);
                            if (targetWs) {
                                targetWs.send(JSON.stringify({ type: 'account_deleted' }));
                                targetWs.close(1000, 'Account deleted by admin');
                                clients.delete(target);
                            }
                            broadcastSystemMessage(`${target} has been deleted by ${clientUsername}`);
                            broadcastUserList();
                        } else {
                            broadcastSystemMessage(`User ${target} not found`);
                        }
                    }
                    return;
                }

                console.log('Inserting into DB:', { clientUsername, text, fileType, filePath, replyTo });
                const [result] = await pool.query(
                    'INSERT INTO messages (username, message, file_type, file_path, reply_to) VALUES (?, ?, ?, ?, ?)',
                    [clientUsername, text, fileType, filePath, replyTo]
                );
                const messageId = result.insertId;

                const broadcastMessage = {
                    type: 'message',
                    id: messageId,
                    username: clientUsername,
                    text: text,
                    file_type: fileType,
                    file_path: filePath,
                    reply_to: replyTo, // Include reply reference
                    timestamp: new Date()
                };
                console.log('Broadcasting:', broadcastMessage);

                wss.clients.forEach(client => {
                    if (client.readyState === WebSocket.OPEN) {
                        client.send(JSON.stringify(broadcastMessage));
                    }
                });
            } else if (message.type === 'delete' && message.id) {
                if (!clientUsername) {
                    ws.send(JSON.stringify({
                        type: 'error',
                        text: 'Not authenticated'
                    }));
                    return;
                }

                const [userRows] = await pool.query(
                    'SELECT isAdmin FROM users WHERE username = ?',
                    [clientUsername]
                );
                if (userRows.length === 0 || !userRows[0].isAdmin) {
                    ws.send(JSON.stringify({
                        type: 'error',
                        text: 'Only admins can delete messages'
                    }));
                    return;
                }

                const [messageRows] = await pool.query(
                    'SELECT file_path FROM messages WHERE id = ?',
                    [message.id]
                );
                if (messageRows.length === 0) {
                    ws.send(JSON.stringify({
                        type: 'error',
                        text: 'Message not found'
                    }));
                    return;
                }

                if (messageRows[0].file_path) {
                    try {
                        await fs.unlink(path.join(__dirname, 'public', messageRows[0].file_path));
                    } catch (err) {
                        console.error(`Failed to delete file ${messageRows[0].file_path}:`, err);
                    }
                }

                await pool.query(
                    'DELETE FROM messages WHERE id = ?',
                    [message.id]
                );
                console.log(`Message ${message.id} deleted by ${clientUsername}`);

                const deleteBroadcast = {
                    type: 'delete_message',
                    id: message.id
                };
                wss.clients.forEach(client => {
                    if (client.readyState === WebSocket.OPEN) {
                        client.send(JSON.stringify(deleteBroadcast));
                    }
                });
            } else {
                ws.send(JSON.stringify({
                    type: 'error',
                    text: 'Unknown message type'
                }));
            }
        } catch (err) {
            console.error('WebSocket message processing error:', err);
            ws.send(JSON.stringify({
                type: 'error',
                text: `Server error: ${err.message}`
            }));
        }
    });

    ws.on('close', () => {
        if (clientUsername) {
            clients.delete(clientUsername);
            console.log(`Client disconnected: ${clientUsername}`);
            console.log('Current clients after disconnect:', Array.from(clients.keys()));
            broadcastUserList();
        }
    });

    (async () => {
        try {
            const [rows] = await pool.query(
                'SELECT id, username, message, file_type, file_path, reply_to, timestamp FROM messages ORDER BY timestamp DESC LIMIT 50'
            );
            console.log('Sending history:', rows);
            ws.send(JSON.stringify({
                type: 'history',
                messages: rows.reverse()
            }));
        } catch (err) {
            console.error('History fetch error:', err);
            ws.send(JSON.stringify({
                type: 'error',
                text: 'Failed to fetch message history'
            }));
        }
    })();
});

function broadcastSystemMessage(text) {
    const message = {
        type: 'message',
        username: 'System',
        text: text,
        file_type: 'text',
        timestamp: new Date()
    };
    wss.clients.forEach(client => {
        if (client.readyState === WebSocket.OPEN) {
            client.send(JSON.stringify(message));
        }
    });
}

function broadcastUserList() {
    const userList = Array.from(clients.keys());
    console.log('Broadcasting user list:', userList);
    const message = {
        type: 'userlist',
        users: userList
    };
    wss.clients.forEach(client => {
        if (client.readyState === WebSocket.OPEN) {
            client.send(JSON.stringify(message));
        }
    });
}

function broadcastJoin(username) {
    const message = {
        type: 'join',
        username: username
    };
    wss.clients.forEach(client => {
        if (client.readyState === WebSocket.OPEN && client !== clients.get(username)) {
            client.send(JSON.stringify(message));
        }
    });
}

process.on('SIGINT', async () => {
    try {
        await pool.end();
        console.log('MariaDB connection pool closed');
        process.exit(0);
    } catch (err) {
        console.error('Error closing pool:', err);
        process.exit(1);
    }
});
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
    user: 'root',
    password: '',
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
                ip VARCHAR(45),
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
                reply_to INT,
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

app.use((req, res, next) => {
    req.clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    next();
});

app.get('/admin', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

app.post('/register', async (req, res) => {
    const { username, password } = req.body;
    const ip = req.clientIp;
    if (!username || username.length > 15) {
        return res.status(400).json({ error: 'Username must be 1-15 characters' });
    }
    try {
        const [bannedRows] = await pool.query('SELECT * FROM users WHERE ip = ? AND banned = 1', [ip]);
        if (bannedRows.length > 0) {
            return res.status(403).json({ error: 'Your IP is banned' });
        }
        const hashedPassword = await bcrypt.hash(password, 10);
        await pool.query('INSERT INTO users (username, password, ip) VALUES (?, ?, ?)', [username, hashedPassword, ip]);
        res.status(201).json({ message: 'User registered successfully', username });
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
    const ip = req.clientIp;
    if (!username || username.length > 15) {
        return res.status(400).json({ error: 'Username must be 1-15 characters' });
    }
    try {
        const [rows] = await pool.query('SELECT * FROM users WHERE username = ?', [username]);
        if (rows.length === 0) return res.status(401).json({ error: 'Invalid credentials' });
        
        const user = rows[0];
        if (user.banned || (await pool.query('SELECT * FROM users WHERE ip = ? AND banned = 1', [ip]))[0].length > 0) {
            return res.status(403).json({ error: 'You are banned' });
        }
        
        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) return res.status(401).json({ error: 'Invalid credentials' });
        
        await pool.query('UPDATE users SET ip = ? WHERE username = ?', [ip, username]);
        res.json({ username: user.username, isAdmin: user.isAdmin });
    } catch (err) {
        console.error('Login error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

const server = app.listen(port, () => console.log(`Server running on port ${port}`));
const wss = new WebSocket.Server({ server });
const clients = new Map();
const MAX_CHARS = 2000;
const MAX_FILE_SIZE = 500 * 1024 * 1024;

wss.on('connection', (ws, req) => {
    let clientUsername = null;
    const clientIp = req.socket.remoteAddress;

    ws.on('message', async (data) => {
        try {
            const message = JSON.parse(data.toString());
            
            if (message.type === 'auth') {
                clientUsername = message.username;
                if (!clientUsername) {
                    ws.send(JSON.stringify({ type: 'error', text: 'Username required' }));
                    return;
                }
                const [bannedRows] = await pool.query('SELECT * FROM users WHERE ip = ? AND banned = 1', [clientIp]);
                if (bannedRows.length > 0) {
                    ws.send(JSON.stringify({ type: 'ban', text: 'Your IP is banned' }));
                    ws.close(1000, 'IP Banned');
                    return;
                }
                const existingClient = clients.get(clientUsername);
                if (existingClient && existingClient.readyState === WebSocket.OPEN) {
                    existingClient.send(JSON.stringify({ type: 'kicked_elsewhere', text: 'Logged in elsewhere' }));
                    existingClient.close(1000, 'Logged in elsewhere');
                    await new Promise(resolve => setTimeout(resolve, 100));
                }
                clients.set(clientUsername, ws);
                broadcastUserList();
                broadcastJoin(clientUsername);
            } else if (message.type === 'message') {
                if (!clientUsername) {
                    ws.send(JSON.stringify({ type: 'error', text: 'Not authenticated' }));
                    return;
                }
                const [userRows] = await pool.query('SELECT isAdmin FROM users WHERE username = ?', [clientUsername]);
                if (userRows.length === 0) {
                    ws.send(JSON.stringify({ type: 'error', text: 'User not found' }));
                    return;
                }
                const isAdmin = userRows[0].isAdmin;
                
                let fileType = 'text';
                let filePath = null;
                let text = message.text || null;
                let replyTo = message.reply_to || null;

                if (text && text.length > MAX_CHARS) {
                    ws.send(JSON.stringify({ type: 'error', text: `Message exceeds ${MAX_CHARS} characters` }));
                    return;
                }
                if ((!text || text.trim() === '') && !message.file) {
                    ws.send(JSON.stringify({ type: 'error', text: 'Message cannot be empty' }));
                    return;
                }

                if (message.file && message.file_data) {
                    const fileSize = Buffer.byteLength(message.file_data, 'base64');
                    if (fileSize > MAX_FILE_SIZE) {
                        ws.send(JSON.stringify({ type: 'error', text: 'File size exceeds 500MB' }));
                        return;
                    }
                    fileType = message.file;
                    const fileName = `${Date.now()}-${Math.random().toString(36).substring(2, 15)}.${fileType.split('/')[1]}`;
                    filePath = `/uploads/${fileName}`;
                    await fs.writeFile(path.join(uploadsDir, fileName), Buffer.from(message.file_data, 'base64'));
                    text = null;
                }

                if (isAdmin && text && text.startsWith('/')) {
                    const [command, target] = text.split(' ');
                    if (command === '/kick' && target) {
                        const [targetRows] = await pool.query('SELECT isAdmin FROM users WHERE username = ?', [target]);
                        if (targetRows.length && targetRows[0].isAdmin) {
                            broadcastSystemMessage(`${clientUsername} attempted to kick admin ${target} (protected)`);
                            return;
                        }
                        const targetWs = clients.get(target);
                        if (targetWs) {
                            targetWs.send(JSON.stringify({ type: 'kick' }));
                            targetWs.close(1000, 'Kicked by admin');
                            clients.delete(target);
                            broadcastSystemMessage(`${target} kicked by ${clientUsername}`);
                            broadcastUserList();
                        }
                    } else if (command === '/ban' && target) {
                        const [targetRows] = await pool.query('SELECT isAdmin, ip FROM users WHERE username = ?', [target]);
                        if (targetRows.length && targetRows[0].isAdmin) {
                            broadcastSystemMessage(`${clientUsername} attempted to ban admin ${target} (protected)`);
                            return;
                        }
                        if (targetRows.length > 0) {
                            const targetIp = targetRows[0].ip;
                            await pool.query('UPDATE users SET banned = 1 WHERE username = ? OR ip = ?', [target, targetIp]);
                            const targetWs = clients.get(target);
                            if (targetWs) {
                                targetWs.send(JSON.stringify({ type: 'ban' }));
                                targetWs.close(1000, 'Banned by admin');
                                clients.delete(target);
                            }
                            broadcastSystemMessage(`${target} and their IP banned by ${clientUsername}`);
                            broadcastUserList();
                        }
                    } else if (command === '/unban' && target) {
                        const [targetRows] = await pool.query('SELECT banned FROM users WHERE username = ?', [target]);
                        if (targetRows.length && targetRows[0].banned) {
                            await pool.query('UPDATE users SET banned = 0 WHERE username = ?', [target]);
                            broadcastSystemMessage(`${target} unbanned by ${clientUsername}`);
                        } else {
                            ws.send(JSON.stringify({ type: 'error', text: `${target} is not banned` }));
                        }
                    } else if (command === '/clear') {
                        const [rows] = await pool.query('SELECT file_path FROM messages WHERE file_path IS NOT NULL');
                        for (const row of rows) {
                            await fs.unlink(path.join(__dirname, 'public', row.file_path)).catch(() => {});
                        }
                        await pool.query('DELETE FROM messages');
                        wss.clients.forEach(client => {
                            if (client.readyState === WebSocket.OPEN) {
                                client.send(JSON.stringify({ type: 'clear' }));
                            }
                        });
                        broadcastSystemMessage(`Chat cleared by ${clientUsername}`);
                    } else if (command === '/admingrant' && target) {
                        const [targetRows] = await pool.query('SELECT * FROM users WHERE username = ?', [target]);
                        if (targetRows.length) {
                            await pool.query('UPDATE users SET isAdmin = 1 WHERE username = ?', [target]);
                            broadcastSystemMessage(`${target} granted admin by ${clientUsername}`);
                            const targetWs = clients.get(target);
                            if (targetWs) {
                                targetWs.send(JSON.stringify({ type: 'admingrant', username: target }));
                            }
                        }
                    } else if (command === '/adminrevoke' && target) {
                        const [targetRows] = await pool.query('SELECT * FROM users WHERE username = ?', [target]);
                        if (targetRows.length) {
                            await pool.query('UPDATE users SET isAdmin = 0 WHERE username = ?', [target]);
                            broadcastSystemMessage(`${target}'s admin revoked by ${clientUsername}`);
                        }
                    } else if (command === '/delete' && target) {
                        const [targetRows] = await pool.query('SELECT isAdmin FROM users WHERE username = ?', [target]);
                        if (targetRows.length && targetRows[0].isAdmin) {
                            broadcastSystemMessage(`${clientUsername} attempted to delete admin ${target} (protected)`);
                            return;
                        }
                        if (targetRows.length) {
                            await pool.query('DELETE FROM users WHERE username = ?', [target]);
                            const targetWs = clients.get(target);
                            if (targetWs) {
                                targetWs.send(JSON.stringify({ type: 'account_deleted' }));
                                targetWs.close(1000, 'Deleted by admin');
                                clients.delete(target);
                            }
                            broadcastSystemMessage(`${target} deleted by ${clientUsername}`);
                            broadcastUserList();
                        }
                    }
                    return;
                }

                const [result] = await pool.query(
                    'INSERT INTO messages (username, message, file_type, file_path, reply_to) VALUES (?, ?, ?, ?, ?)',
                    [clientUsername, text, fileType, filePath, replyTo]
                );
                const broadcastMessage = {
                    type: 'message',
                    id: result.insertId,
                    username: clientUsername,
                    text,
                    file_type: fileType,
                    file_path: filePath,
                    reply_to: replyTo,
                    timestamp: new Date()
                };
                wss.clients.forEach(client => {
                    if (client.readyState === WebSocket.OPEN) {
                        client.send(JSON.stringify(broadcastMessage));
                    }
                });
            } else if (message.type === 'delete' && message.id) {
                if (!clientUsername) return;
                const [userRows] = await pool.query('SELECT isAdmin FROM users WHERE username = ?', [clientUsername]);
                if (userRows.length && userRows[0].isAdmin) {
                    const [messageRows] = await pool.query('SELECT file_path FROM messages WHERE id = ?', [message.id]);
                    if (messageRows.length) {
                        if (messageRows[0].file_path) {
                            await fs.unlink(path.join(__dirname, 'public', messageRows[0].file_path)).catch(() => {});
                        }
                        await pool.query('DELETE FROM messages WHERE id = ?', [message.id]);
                        wss.clients.forEach(client => {
                            if (client.readyState === WebSocket.OPEN) {
                                client.send(JSON.stringify({ type: 'delete_message', id: message.id }));
                            }
                        });
                    }
                }
            } else if (message.type === 'voice_offer' || message.type === 'voice_answer' || message.type === 'ice_candidate') {
                broadcastToAllExceptSender(clientUsername, message);
            } else if (message.type === 'join_voice') {
                broadcastVoiceStatus(clientUsername, 'join_voice');
            } else if (message.type === 'leave_voice') {
                broadcastVoiceStatus(clientUsername, 'leave_voice');
            }
        } catch (err) {
            console.error('WebSocket error:', err);
            ws.send(JSON.stringify({ type: 'error', text: 'Server error' }));
        }
    });

    ws.on('close', () => {
        if (clientUsername) {
            clients.delete(clientUsername);
            broadcastUserList();
        }
    });

    (async () => {
        const [rows] = await pool.query('SELECT * FROM messages ORDER BY timestamp DESC LIMIT 50');
        ws.send(JSON.stringify({ type: 'history', messages: rows.reverse() }));
    })();
});

function broadcastSystemMessage(text) {
    wss.clients.forEach(client => {
        if (client.readyState === WebSocket.OPEN) {
            client.send(JSON.stringify({
                type: 'message',
                username: 'System',
                text,
                file_type: 'text',
                timestamp: new Date()
            }));
        }
    });
}

function broadcastUserList() {
    const userList = Array.from(clients.keys());
    wss.clients.forEach(client => {
        if (client.readyState === WebSocket.OPEN) {
            client.send(JSON.stringify({ type: 'userlist', users: userList }));
        }
    });
}

function broadcastJoin(username) {
    wss.clients.forEach(client => {
        if (client.readyState === WebSocket.OPEN && client !== clients.get(username)) {
            client.send(JSON.stringify({ type: 'join', username }));
        }
    });
}

function broadcastToAllExceptSender(senderUsername, message) {
    wss.clients.forEach(client => {
        if (client.readyState === WebSocket.OPEN && clients.get(senderUsername) !== client) {
            client.send(JSON.stringify(message));
        }
    });
}

function broadcastVoiceStatus(username, type) {
    wss.clients.forEach(client => {
        if (client.readyState === WebSocket.OPEN) {
            client.send(JSON.stringify({ type, username }));
        }
    });
}

process.on('SIGINT', async () => {
    await pool.end();
    console.log('MariaDB connection pool closed');
    process.exit(0);
});
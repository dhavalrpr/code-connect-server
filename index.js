// Constants and imports
const express = require("express");
const http = require("http");
const { Server } = require("socket.io");
const cors = require("cors");
const { log } = require("console");

// Actions for socket events
const ACTIONS = {
  JOIN: 'join',
    JOINED: 'joined',
    DISCONNECTED: 'disconnected',
    CODE_CHANGE: 'code-change',
    SYNC_CODE: 'sync-code',
    LEAVE: 'leave',
    COMPILE: 'compile',
    COMPILE_RESULT: 'compile-result',
    TYPING: 'typing',
    STOP_TYPING: 'stop-typing',
    SEND_MESSAGE: 'send-message',
  RECEIVE_MESSAGE: 'receive-message',
};

// Logger utility
const logger = {
  info: (message, data = {}) => console.log(`[INFO] ${new Date().toISOString()} - ${message}`, data),
  error: (message, error = {}) => console.error(`[ERROR] ${new Date().toISOString()} - ${message}`, error)
};

// CORS configuration
const corsOptions = {
  origin: ["https://codeconnect.up.railway.app"],
  methods: ['GET', 'POST'],
  credentials: true
};

// Server setup
const app = express();
app.use(cors(corsOptions));
const server = http.createServer(app);

// Socket.IO setup
const io = new Server(server, {
  cors: corsOptions,
  pingTimeout: 60000,
  connectTimeout: 60000,
  transports: ['websocket']
});

// State management
const state = {
  userSocketMap: new Map(),
  roomToClientsMap: new Map(),
  roomCodeMap: new Map(),
  typingUsers: new Map(),
  sandboxes: new Map() // Store code execution contexts
};

const typingTimeouts = new Map();
const chatMessages = new Map(); // Store messages by room

// Get all connected clients in a room
function getAllConnectedClients(roomId) {
  try {
    const room = io.sockets.adapter.rooms.get(roomId);
    if (!room) return [];

    const clients = Array.from(room).map(socketId => ({
      socketId,
      username: state.userSocketMap.get(socketId)
    }));

    state.roomToClientsMap.set(roomId, clients);
    return clients;
  } catch (error) {
    logger.error('Error getting connected clients', error);
    return [];
  }
}


// Add sandbox execution with safety limits
function createSandbox(code) {
  const vm = require('vm');
  const context = {
    console: {
      log: (...args) => args.join(' '),
      error: (...args) => args.join(' '),
      warn: (...args) => args.join(' ')
    },
    setTimeout,
    clearTimeout,
    Buffer: Buffer,
    process: {
      hrtime: process.hrtime,
      cwd: process.cwd
    }
  };
  
  const script = new vm.Script(code);
  const timeout = 5000; // 5 second timeout
  
  try {
    return script.runInNewContext(context, { timeout });
  } catch (error) {
    return { error: error.message };
  }
}

// Add compile handler
function handleCompile(socket, { roomId, code, language }) {
  logger.info('Code compilation request', { roomId, language });
  
  try {
    const vm = require('vm');
    let output = [];
    
    const context = {
      console: {
        log: (...args) => {
          const message = args.map(arg => 
            typeof arg === 'object' ? JSON.stringify(arg) : String(arg)
          ).join(' ');
          output.push(message);
        },
        error: (...args) => {
          output.push(`Error: ${args.join(' ')}`);
        }
      },
      setTimeout,
      clearTimeout,
    };

    const script = new vm.Script(code);
    script.runInNewContext(context, { 
      timeout: 5000,
      displayErrors: true
    });

    logger.info('Code compiled successfully', { roomId, language, output });
    
    socket.emit(ACTIONS.COMPILE_RESULT, {
      result: output.join('\n')
    });

  } catch (error) {
    logger.error('Compilation error', { error: error.message });
    socket.emit(ACTIONS.COMPILE_RESULT, { 
      error: error.message 
    });
  }
}

// Handle code changes
function handleCodeChange(socket, { roomId, code }) {
  try {
    state.roomCodeMap.set(roomId, code);
    socket.to(roomId).emit(ACTIONS.CODE_CHANGE, { code });
    logger.info('Code changed', { roomId, code });
  } catch (error) {
    logger.error('Code change error', error);
  }
}

// Socket connection handler
// Replace your io.on("connection") handler with this:


function handleDisconnect(socket) {
  const rooms = Array.from(socket.rooms);
  const user = state.userSocketMap.get(socket.id);

  if (!user) return;

  rooms.forEach(roomId => {
    if (roomId === socket.id) return;

    const clients = getAllConnectedClients(roomId)
      .filter(client => client.socketId !== socket.id);

    // Clean up typing state
    const roomTyping = state.typingUsers.get(roomId);
    if (roomTyping) {
      roomTyping.delete(user);
      if (roomTyping.size === 0) {
        state.typingUsers.delete(roomId);
      }
      io.to(roomId).emit(ACTIONS.STOP_TYPING, { username: user });
    }

    // Clear any existing timeout
    const timeoutKey = `${roomId}-${socket.id}`;
    if (typingTimeouts.has(timeoutKey)) {
      clearTimeout(typingTimeouts.get(timeoutKey));
      typingTimeouts.delete(timeoutKey);
    }

    // Broadcast disconnect
    io.to(roomId).emit(ACTIONS.DISCONNECTED, {
      socketId: socket.id,
      user,
      clients
    });

    state.roomToClientsMap.set(roomId, clients);
  });

  state.userSocketMap.delete(socket.id);
  logger.info('Client disconnected', { socketId: socket.id, user });
}

function handleLeaveRoom(socket, roomId) {
  const user = state.userSocketMap.get(socket.id);
  if (!user || !roomId) return;

  // Clean up typing state before leaving
  const roomTyping = state.typingUsers.get(roomId);
  if (roomTyping) {
    roomTyping.delete(user);
    if (roomTyping.size === 0) {
      state.typingUsers.delete(roomId);
    }
    io.to(roomId).emit(ACTIONS.STOP_TYPING, { username: user });
  }

  // Clear any existing timeout
  const timeoutKey = `${roomId}-${socket.id}`;
  if (typingTimeouts.has(timeoutKey)) {
    clearTimeout(typingTimeouts.get(timeoutKey));
    typingTimeouts.delete(timeoutKey);
  }

  socket.leave(roomId);
  const clients = getAllConnectedClients(roomId);
  
  io.in(roomId).emit(ACTIONS.DISCONNECTED, {
    socketId: socket.id,
    user,
    clients
  });

  state.userSocketMap.delete(socket.id);
  logger.info('User left room', { roomId, user, socketId: socket.id });
}


function handleJoin(socket, { id: roomId, user }) {
  try {
    if (!roomId || !user) {
      throw new Error('Room ID and username are required');
    }

    // Leave previous rooms
    socket.rooms.forEach(room => {
      if (room !== socket.id) socket.leave(room);
    });

    // Join new room
    state.userSocketMap.set(socket.id, user);
    socket.join(roomId);

    const clients = getAllConnectedClients(roomId);
    
    // Sync existing code
    const existingCode = state.roomCodeMap.get(roomId);
    if (existingCode) {
      socket.emit(ACTIONS.SYNC_CODE, { code: existingCode });
    }

    // Send chat history to the joining user
    if (chatMessages.has(roomId)) {
      const roomHistory = chatMessages.get(roomId);
      // Send each message individually to maintain order
      roomHistory.forEach(message => {
        socket.emit(ACTIONS.RECEIVE_MESSAGE, message);
      });
    }

    // Notify all clients
    io.to(roomId).emit(ACTIONS.JOINED, {
      clients,
      user,
      socketId: socket.id
    });

    logger.info('User joined room', { roomId, user, socketId: socket.id });
  } catch (error) {
    logger.error('Join error', error);
    socket.emit('error', { message: error.message });
  }
}

function handleSendMessage(socket, { roomId, message }) {
  try {
    // Initialize room's message array if it doesn't exist
    if (!chatMessages.has(roomId)) {
      chatMessages.set(roomId, []);
    }
    
    // Store message in server's memory
    chatMessages.get(roomId).push(message);
    
    // Broadcast to all clients in the room including sender
    io.to(roomId).emit(ACTIONS.RECEIVE_MESSAGE, message);
    
    logger.info('Message sent', { roomId, sender: message.sender });
  } catch (error) {
    logger.error('Error sending message', error);
  }
}

// Update handleTyping to use socket.id for tracking
// In your server's index.js, update the handleTyping function
function handleTyping(socket, { roomId, username }) {
  if (!username || !roomId) return;
  
  // Clear any existing timeout for this user
  const timeoutKey = `${roomId}-${username}`;
  if (typingTimeouts.has(timeoutKey)) {
    clearTimeout(typingTimeouts.get(timeoutKey));
  }

  // Broadcast typing event to all clients in the room
  io.in(roomId).emit(ACTIONS.TYPING, {
    username,
    socketId: socket.id
  });

  // Set timeout to automatically clear typing status
  const timeout = setTimeout(() => {
    handleStopTyping(socket, { roomId, username });
  }, 1500);

  typingTimeouts.set(timeoutKey, timeout);
}

// Update the handleStopTyping function
function handleStopTyping(socket, { roomId, username }) {
  if (!username || !roomId) return;

  const timeoutKey = `${roomId}-${username}`;
  if (typingTimeouts.has(timeoutKey)) {
    clearTimeout(typingTimeouts.get(timeoutKey));
    typingTimeouts.delete(timeoutKey);
  }

  // Broadcast stop typing event to all clients
  io.in(roomId).emit(ACTIONS.STOP_TYPING, {
    username,
    socketId: socket.id
  });
}
// Connection handler setup
io.on("connection", (socket) => {
  logger.info("New connection", { socketId: socket.id });
  
  socket.on(ACTIONS.JOIN, data => handleJoin(socket, data));
  socket.on(ACTIONS.CODE_CHANGE, data => handleCodeChange(socket, data));
  socket.on(ACTIONS.LEAVE, ({ roomId }) => handleLeaveRoom(socket, roomId));
  socket.on(ACTIONS.TYPING, data => handleTyping(socket, data));
  socket.on(ACTIONS.STOP_TYPING, data => handleStopTyping(socket, data));
  socket.on(ACTIONS.COMPILE, data => handleCompile(socket, data));
  socket.on(ACTIONS.SEND_MESSAGE, (data) => handleSendMessage(socket, data));
  socket.on('disconnect', () => {
    const user = state.userSocketMap.get(socket.id);
    if (user) {
      Array.from(socket.rooms).forEach(roomId => {
        if (roomId !== socket.id) {
          handleStopTyping(socket, { roomId, username: user });
        }
      });
    }
    handleDisconnect(socket);
  });
});


// Health check endpoint
app.get("/", (req, res) => {
  res.json({
    status: "healthy",
    timestamp: new Date().toISOString(),
    connections: io.engine.clientsCount
  });
});

// Health check endpoint
app.get("/health", (req, res) => {
  res.json({
    status: "healthy af",
    timestamp: new Date().toISOString(),
    connections: io.engine.clientsCount
  });
});

// Error handling
app.use((err, req, res, next) => {
  logger.error('Express error', err);
  res.status(500).json({ error: 'Internal server error' });
});

// Process handlers
const gracefulShutdown = () => {
  server.close(() => {
    logger.info('Server closed');
    process.exit(0);
  });
};

process.on('SIGTERM', gracefulShutdown);
process.on('uncaughtException', error => {
  logger.error('Uncaught Exception:', error);
  process.exit(1);
});
process.on('unhandledRejection', (reason, promise) => {
  logger.error('Unhandled Rejection:', { promise, reason });
  process.exit(1);
});

// Start server
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => logger.info(`Server running on port ${PORT}`));

module.exports = { ACTIONS };
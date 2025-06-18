require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const compression = require('compression');
const rateLimit = require('express-rate-limit');
const winston = require('winston');
const { createServer } = require('http');
const { Server } = require('socket.io');

// Configuración del logger
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  transports: [
    new winston.transports.Console({
      format: winston.format.simple()
    })
  ]
});

// Configuración de la aplicación
const app = express();
const server = createServer(app);
const io = new Server(server, {
  cors: {
    origin: process.env.CORS_ORIGIN || "*",
    methods: ["GET", "POST", "PUT", "DELETE"]
  }
});

const PORT = process.env.PORT || 3000;

// Middleware de seguridad
app.use(helmet());
app.use(cors({
  origin: process.env.CORS_ORIGIN || "*",
  credentials: true
}));
app.use(compression());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutos
  max: 100, // máximo 100 requests por ventana
  message: {
    error: 'Demasiadas solicitudes, intenta nuevamente en 15 minutos'
  },
  standardHeaders: true,
  legacyHeaders: false
});

app.use('/api/', limiter);

// Middleware de autenticación
const authenticate = (req, res, next) => {
  const apiKey = req.headers['x-api-key'] || req.query.apiKey;
  
  if (!apiKey) {
    return res.status(401).json({ 
      error: 'API Key requerida',
      message: 'Incluye tu API Key en el header X-API-Key' 
    });
  }
  
  if (apiKey !== process.env.API_KEY) {
    return res.status(403).json({ 
      error: 'API Key inválida',
      message: 'Verifica tu API Key' 
    });
  }
  
  next();
};

// Middleware de logging
app.use((req, res, next) => {
  logger.info(`${req.method} ${req.path} - ${req.ip}`);
  next();
});

// Datos de ejemplo (en producción usarías una base de datos)
let users = [
  { id: 1, name: 'Juan Pérez', email: 'juan@example.com', role: 'admin' },
  { id: 2, name: 'María García', email: 'maria@example.com', role: 'user' },
  { id: 3, name: 'Carlos López', email: 'carlos@example.com', role: 'user' }
];

let posts = [
  { id: 1, title: 'Primer Post', content: 'Contenido del primer post', authorId: 1, createdAt: new Date() },
  { id: 2, title: 'Segundo Post', content: 'Contenido del segundo post', authorId: 2, createdAt: new Date() }
];

// Rutas públicas
app.get('/', (req, res) => {
  res.json({
    message: '🚀 API Evolución funcionando correctamente',
    version: '1.0.0',
    endpoints: {
      public: [
        'GET / - Este endpoint',
        'GET /health - Estado del servidor'
      ],
      protected: [
        'GET /api/users - Lista de usuarios',
        'POST /api/users - Crear usuario',
        'GET /api/users/:id - Usuario específico',
        'PUT /api/users/:id - Actualizar usuario',
        'DELETE /api/users/:id - Eliminar usuario',
        'GET /api/posts - Lista de posts',
        'POST /api/posts - Crear post'
      ]
    },
    websocket: '/socket.io para conexiones en tiempo real',
    authentication: 'Requerida para endpoints /api/*'
  });
});

app.get('/health', (req, res) => {
  res.json({
    status: 'OK',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    memory: process.memoryUsage(),
    environment: process.env.NODE_ENV || 'development'
  });
});

// Rutas protegidas - USUARIOS
app.get('/api/users', authenticate, (req, res) => {
  const { page = 1, limit = 10, search = '' } = req.query;
  
  let filteredUsers = users;
  if (search) {
    filteredUsers = users.filter(user => 
      user.name.toLowerCase().includes(search.toLowerCase()) ||
      user.email.toLowerCase().includes(search.toLowerCase())
    );
  }
  
  const startIndex = (page - 1) * limit;
  const endIndex = startIndex + parseInt(limit);
  const paginatedUsers = filteredUsers.slice(startIndex, endIndex);
  
  res.json({
    users: paginatedUsers,
    pagination: {
      currentPage: parseInt(page),
      totalPages: Math.ceil(filteredUsers.length / limit),
      totalUsers: filteredUsers.length,
      hasNext: endIndex < filteredUsers.length,
      hasPrev: startIndex > 0
    }
  });
});

app.get('/api/users/:id', authenticate, (req, res) => {
  const user = users.find(u => u.id === parseInt(req.params.id));
  
  if (!user) {
    return res.status(404).json({ 
      error: 'Usuario no encontrado',
      message: `No existe usuario con ID ${req.params.id}` 
    });
  }
  
  res.json({ user });
});

app.post('/api/users', authenticate, (req, res) => {
  const { name, email, role = 'user' } = req.body;
  
  if (!name || !email) {
    return res.status(400).json({
      error: 'Datos incompletos',
      message: 'Nombre y email son requeridos'
    });
  }
  
  const emailExists = users.find(u => u.email === email);
  if (emailExists) {
    return res.status(409).json({
      error: 'Email ya existe',
      message: 'Este email ya está registrado'
    });
  }
  
  const newUser = {
    id: Math.max(...users.map(u => u.id)) + 1,
    name,
    email,
    role,
    createdAt: new Date()
  };
  
  users.push(newUser);
  
  // Notificar via WebSocket
  io.emit('userCreated', newUser);
  
  res.status(201).json({
    message: 'Usuario creado exitosamente',
    user: newUser
  });
});

app.put('/api/users/:id', authenticate, (req, res) => {
  const userId = parseInt(req.params.id);
  const userIndex = users.findIndex(u => u.id === userId);
  
  if (userIndex === -1) {
    return res.status(404).json({
      error: 'Usuario no encontrado'
    });
  }
  
  const { name, email, role } = req.body;
  const updatedUser = {
    ...users[userIndex],
    ...(name && { name }),
    ...(email && { email }),
    ...(role && { role }),
    updatedAt: new Date()
  };
  
  users[userIndex] = updatedUser;
  
  // Notificar via WebSocket
  io.emit('userUpdated', updatedUser);
  
  res.json({
    message: 'Usuario actualizado exitosamente',
    user: updatedUser
  });
});

app.delete('/api/users/:id', authenticate, (req, res) => {
  const userId = parseInt(req.params.id);
  const userIndex = users.findIndex(u => u.id === userId);
  
  if (userIndex === -1) {
    return res.status(404).json({
      error: 'Usuario no encontrado'
    });
  }
  
  const deletedUser = users[userIndex];
  users.splice(userIndex, 1);
  
  // Notificar via WebSocket
  io.emit('userDeleted', { id: userId });
  
  res.json({
    message: 'Usuario eliminado exitosamente',
    user: deletedUser
  });
});

// Rutas protegidas - POSTS
app.get('/api/posts', authenticate, (req, res) => {
  const { page = 1, limit = 10, authorId } = req.query;
  
  let filteredPosts = posts;
  if (authorId) {
    filteredPosts = posts.filter(post => post.authorId === parseInt(authorId));
  }
  
  const startIndex = (page - 1) * limit;
  const endIndex = startIndex + parseInt(limit);
  const paginatedPosts = filteredPosts.slice(startIndex, endIndex);
  
  // Agregar información del autor
  const postsWithAuthor = paginatedPosts.map(post => ({
    ...post,
    author: users.find(u => u.id === post.authorId)
  }));
  
  res.json({
    posts: postsWithAuthor,
    pagination: {
      currentPage: parseInt(page),
      totalPages: Math.ceil(filteredPosts.length / limit),
      totalPosts: filteredPosts.length
    }
  });
});

app.post('/api/posts', authenticate, (req, res) => {
  const { title, content, authorId } = req.body;
  
  if (!title || !content || !authorId) {
    return res.status(400).json({
      error: 'Datos incompletos',
      message: 'Título, contenido y autorId son requeridos'
    });
  }
  
  const author = users.find(u => u.id === parseInt(authorId));
  if (!author) {
    return res.status(404).json({
      error: 'Autor no encontrado'
    });
  }
  
  const newPost = {
    id: Math.max(...posts.map(p => p.id)) + 1,
    title,
    content,
    authorId: parseInt(authorId),
    createdAt: new Date()
  };
  
  posts.push(newPost);
  
  // Notificar via WebSocket
  io.emit('postCreated', { ...newPost, author });
  
  res.status(201).json({
    message: 'Post creado exitosamente',
    post: { ...newPost, author }
  });
});

// WebSocket para comunicación en tiempo real
io.on('connection', (socket) => {
  logger.info(`Cliente conectado: ${socket.id}`);
  
  socket.emit('welcome', {
    message: 'Conectado al servidor WebSocket',
    timestamp: new Date().toISOString()
  });
  
  socket.on('disconnect', () => {
    logger.info(`Cliente desconectado: ${socket.id}`);
  });
  
  // Eventos personalizados
  socket.on('ping', () => {
    socket.emit('pong', { timestamp: new Date().toISOString() });
  });
});

// Manejo de errores
app.use((err, req, res, next) => {
  logger.error('Error interno del servidor:', err);
  res.status(500).json({
    error: 'Error interno del servidor',
    message: process.env.NODE_ENV === 'development' ? err.message : 'Algo salió mal'
  });
});

// Ruta 404
app.use('*', (req, res) => {
  res.status(404).json({
    error: 'Endpoint no encontrado',
    message: `La ruta ${req.method} ${req.originalUrl} no existe`,
    availableEndpoints: [
      'GET /',
      'GET /health',
      'GET /api/users',
      'POST /api/users',
      'GET /api/posts',
      'POST /api/posts'
    ]
  });
});

// Iniciar servidor
server.listen(PORT, () => {
  logger.info(`🚀 Servidor iniciado en puerto ${PORT}`);
  logger.info(`📡 WebSocket habilitado en puerto ${PORT}`);
  logger.info(`🔒 Autenticación: ${process.env.API_KEY ? 'Configurada' : 'NO CONFIGURADA'}`);
  logger.info(`🌍 Entorno: ${process.env.NODE_ENV || 'development'}`);
});

// Manejo de señales para cierre limpio
process.on('SIGTERM', () => {
  logger.info('Cerrando servidor...');
  server.close(() => {
    logger.info('Servidor cerrado exitosamente');
    process.exit(0);
  });
});

process.on('SIGINT', () => {
  logger.info('Cerrando servidor...');
  server.close(() => {
    logger.info('Servidor cerrado exitosamente');
    process.exit(0);
  });
});

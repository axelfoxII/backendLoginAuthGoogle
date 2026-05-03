/**
 * =====================================================
 * SERVIDOR PRINCIPAL - AUTH SYSTEM
 * =====================================================
 * Este archivo configura y arranca el servidor Express
 * con todas las configuraciones de seguridad, rutas y middlewares
 */

require('dotenv').config(); // Carga variables de entorno desde .env
const express = require('express'); // Framework web
const helmet = require('helmet'); // Seguridad de headers HTTP
const rateLimit = require('express-rate-limit'); // Limitar solicitudes
const path = require('path'); // Manejo de rutas

// Importar configuración
const config = require('./config');
// Importar función de conexión a MongoDB
const { connectDB } = require('./config/database');
// Importar rutas de autenticación
const authRoutes = require('./routes/auth');
// Importar rutas de usuarios
const userRoutes = require('./routes/users');

// =====================================================
// INICIALIZACIÓN DE EXPRESS
// =====================================================
const app = express();

// =====================================================
// SEGURIDAD - HELMET
// =====================================================
// Helmet establece headers de seguridad HTTP
// contentSecurityPolicy: false - Permite cargar recursos externos (imágenes, scripts)
// crossOriginEmbedderPolicy: false - Permite embedding de recursos
app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginEmbedderPolicy: false
}));

// =====================================================
// CORS - CROSS-ORIGIN RESOURCE SHARING
// =====================================================
// Permite que el frontend (puerto 4200) haga solicitudes al backend (puerto 3000)
// Access-Control-Allow-Origin: * - Permite cualquier dominio
// Access-Control-Allow-Headers: * - Permite cualquier header en las peticiones
// Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS - Métodos permitidos
// El método OPTIONS se usa en preflight requests (CORS)
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Headers', '*');
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  if (req.method === 'OPTIONS') {
    return res.sendStatus(204); // Responder preflight inmediatamente
  }
  next();
});

// =====================================================
// PARSEO DEL BODY
// =====================================================
// express.json() - Parsea application/json
// limit: '10kb' - Limita el tamaño del body a 10KB para seguridad
// express.urlencoded() - Parsea datos de formulario
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));

// =====================================================
// RATE LIMITING - LIMITADOR DE PETICIONES
// =====================================================
// Protege contra ataques de fuerza bruta y DDoS
// generalLimiter: 100 peticiones cada 15 minutos (para cualquier ruta /api)
// loginLimiter: 10 peticiones cada 15 minutos (específico para /auth/login)
const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutos en milisegundos
  max: 100, // Máximo de peticiones
  message: { message: 'Too many requests, please try again later' }
});

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10, // Menos intentos para login
  message: { message: 'Too many login attempts, please try again later' }
});

// Aplicar rate limiters
app.use('/api/auth/login', loginLimiter); // Rate limit específico para login
app.use('/api', generalLimiter); // Rate limit general para /api

// =====================================================
// ARCHIVOS ESTÁTICOS - IMÁGENES
// =====================================================
// Serve archivos de la carpeta 'uploads' públicamente
// localhost:3000/uploads/archivo.jpg para acceder a imágenes
// express.static() sirve archivos sin necesidad de ruta específica
app.use('/uploads', express.static('uploads'));
app.use('/avatars', express.static('uploads')); // Alias para /uploads

// =====================================================
// RUTAS DE LA API
// =====================================================
// /api/auth/* - Rutas de autenticación (login, register, logout, google)
// /api/users/* - Rutas de usuarios (CRUD)
app.use('/api/auth', authRoutes);
app.use('/api/users', userRoutes);

// =====================================================
// ENDPOINT DE SALUD
// =====================================================
// GET /api/health - Verifica que el servidor esté funcionando
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    timestamp: new Date().toISOString() 
  });
});

// =====================================================
// MANEJO DE ERRORES
// =====================================================
// Captura errores no manejados y responde con JSON
app.use((err, req, res, next) => {
  console.error(err.stack); // Imprime el error en consola
  res.status(500).json({ message: 'Something went wrong!' });
});

// =====================================================
// INICIAR SERVIDOR
// =====================================================
const startServer = async () => {
  try {
    // 1. Conectar a MongoDB
    await connectDB();
    
    // 2. Iniciar servidor en el puerto configurado
    app.listen(config.port, () => {
      console.log(`✅ Server running on port ${config.port}`);
    });
  } catch (error) {
    console.error('❌ Failed to start server:', error.message);
    process.exit(1); // Salir con código de error
  }
};

// Arrancar el servidor
startServer();

// Exportar app para testing
module.exports = app;
/**
 * =====================================================
 * MIDDLEWARE DE AUTENTICACIÓN JWT
 * =====================================================
 * Este middleware verifica y valida el token JWT en cada petición
 * Protege las rutas que requieren sesión activa
 * 
 * USO: agregar require('../middleware/auth') como segundo argumento
 * Ejemplo: router.get('/ruta', require('../middleware/auth'), handler)
 */

const jwt = require('jsonwebtoken');
const config = require('../config');
const User = require('../models/User');

// =====================================================
// BLACKLIST DE TOKENS - Invalidar tokens al hacer logout
// =====================================================
// Set para almacenar tokens que ya no son válidos
// Cuando un usuario hace logout, su token se agrega aquí
const tokenBlacklist = new Set();

/**
 * Middleware de autenticación
 * @param {Object} req - Request de Express
 * @param {Object} res - Response de Express  
 * @param {Function} next - Función para continuar al siguiente middleware
 */
const auth = async (req, res, next) => {
  // DEBUG: Agregado para debugging de errores 401 en PATCH /avatar
  console.log('=== AUTH MIDDLEWARE DEBUG ===');
  console.log('Method:', req.method);
  console.log('URL:', req.originalUrl);
  console.log('Authorization header:', req.headers.authorization ? 'Present' : 'Missing');
  
  try {
    // 1. Obtener header de autorización
    const authHeader = req.headers.authorization;
    
    // 2. Verificar que existe y tiene formato "Bearer <token>"
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      console.log('AUTH ERROR: No token provided');
      return res.status(401).json({ message: 'No token provided' });
    }
    
    // 3. Extraer el token (去除 "Bearer ")
    const token = authHeader.split(' ')[1];
    console.log('Token extracted, length:', token ? token.length : 0);
    
    // 4. Verificar si el token está en blacklist (logout previo)
    if (tokenBlacklist.has(token)) {
      console.log('AUTH ERROR: Token in blacklist');
      return res.status(401).json({ message: 'Token has been revoked' });
    }
    
    // 5. Verificar y decodificar el token JWT
    // CAMBIO: Agregado debug para ver si el token es válido
    console.log('Verifying token...');
    const decoded = jwt.verify(token, config.jwt.secret);
    console.log('Token decoded, user ID:', decoded.id);
    
    // 6. Buscar el usuario en la base de datos usando el ID del token
    // Importante: siempre buscar en BD para obtener datos actualizados
    const user = await User.findById(decoded.id);
    if (!user) {
      console.log('AUTH ERROR: User not found in DB');
      return res.status(401).json({ message: 'User not found' });
    }
    
    console.log('AUTH SUCCESS: User authenticated:', user.email);
    
    // 7. Adjuntar usuario y token al request para usar en el controlador
    req.user = user; // Objeto completo del usuario
    req.token = token; // Token para posible blacklist en logout
    
    // 8. Continuar al siguiente middleware/controlador
    next();
  } catch (error) {
    // DEBUG: Agregado para ver qué tipo de error ocurre
    console.log('AUTH ERROR:', error.name, error.message);
    // Manejar errores específicos de JWT
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({ message: 'Token expired' });
    }
    // Cualquier otro error de token
    return res.status(401).json({ message: 'Invalid token' });
  }
};

// Exportar middleware y blacklist para usar en rutas
module.exports = auth;
module.exports.tokenBlacklist = tokenBlacklist;
/**
 * =====================================================
 * SERVICIO DE TOKENS JWT
 * =====================================================
 * Maneja la generación y verificación de tokens JWT
 * 
 * TIPOS DE TOKEN:
 * 1. Access Token: Token principal para autenticación (15 min)
 * 2. Refresh Token: Token para renovar acceso (7 días)
 * 
 * FLUJO:
 * 1. Usuario se loguea → recibe access + refresh token
 * 2. Access token expira (15 min) → usar refresh para obtener nuevo
 * 3. Refresh token expira (7 días) → usuario debe loguearse de nuevo
 */

const jwt = require('jsonwebtoken');
const config = require('../config');

/**
 * Generar Token de Acceso (JWT)
 * @param {Object} user - Objeto usuario de MongoDB
 * @returns {string} Token JWT firmad
 * 
 * Payload del token contiene:
 * - id: ID del usuario en MongoDB
 * - email: Email del usuario
 * - role: Rol del usuario (user/editor/admin)
 */
const generateToken = (user) => {
  return jwt.sign(
    { 
      id: user._id, 
      email: user.email, 
      role: user.role 
    },
    config.jwt.secret,
    { expiresIn: config.jwt.expiresIn } // 15 minutos
  );
};

/**
 * Generar Refresh Token
 * @param {Object} user - Objeto usuario de MongoDB
 * @returns {string} Refresh Token JWT
 * 
 * Este token tiene menor información (solo ID)
 * y dura más tiempo (7 días)
 * Se usa para obtener nuevos access tokens sin login
 */
const generateRefreshToken = (user) => {
  return jwt.sign(
    { id: user._id }, // Solo ID para validar
    config.jwt.secret,
    { expiresIn: config.jwt.refreshExpiresIn } // 7 días
  );
};

/**
 * Verificar un token JWT
 * @param {string} token - Token a verificar
 * @returns {Object} Payload decodificado
 * @throws Error si el token es inválido o expirado
 */
const verifyToken = (token) => {
  return jwt.verify(token, config.jwt.secret);
};

// Exportar todas las funciones
module.exports = {
  generateToken,
  generateRefreshToken,
  verifyToken
};
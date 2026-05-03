/**
 * =====================================================
 * CONFIGURACIÓN CENTRAL DEL PROYECTO
 * =====================================================
 * Carga variables de entorno y define constantes globales
 * Estas configuraciones se usan en todo el servidor
 */

require('dotenv').config(); // Carga variables del archivo .env

/**
 * Objeto de configuración global
 */
module.exports = {
  // =====================================================
  // PUERTO DEL SERVIDOR
  // =====================================================
  // Lee de variable de entorno PORT, por defecto 3000
  port: process.env.PORT || 3000,

  // =====================================================
  // URI DE MONGODB
  // =====================================================
  // Conexión a MongoDB local o Atlas
  // Formato: mongodb://usuario:password@servidor:puerto/baseDatos
  mongoUri: process.env.MONGO_URI || 'mongodb://admin:123456@localhost:27017/?authSource=admin',

  // =====================================================
  // CONFIGURACIÓN JWT
  // =====================================================
  jwt: {
    // Clave secreta para firmar tokens JWT
    // IMPORTANTE: Cambiar en producción!
    secret: process.env.JWT_SECRET || 'default-secret-change-me',
    
    // Tiempo de expiración del token de acceso
    expiresIn: '15m', // 15 minutos
    
    // Tiempo de expiración del token de refresh
    refreshExpiresIn: '7d' // 7 días
  },

  // =====================================================
  // CONFIGURACIÓN GOOGLE OAUTH
  // =====================================================
  google: {
    // Client ID de Google Cloud Console
    clientId: process.env.GOOGLE_CLIENT_ID
  },

  // =====================================================
  // CONFIGURACIÓN DE SUBIDA DE ARCHIVOS
  // =====================================================
  upload: {
    // Tamaño máximo: 2MB (2 * 1024 * 1024 bytes)
    maxSize: 2 * 1024 * 1024,
    
    // Tipos de archivo permitidos para avatares
    allowedTypes: ['image/png', 'image/jpeg', 'image/jpg']
  }
};
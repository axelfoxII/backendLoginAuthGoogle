/**
 * =====================================================
 * CONEXIÓN A MONGODB
 * =====================================================
 * Establece la conexión con la base de datos MongoDB
 * Maneja errores de conexión y eventos de desconexión
 */

const mongoose = require('mongoose');

/**
 * Conectar a MongoDB
 * async - Función asíncrona
 * 
 * Proceso:
 * 1. Obtener URI de .env o usar默认值 local
 * 2. Conectar con Mongoose
 * 3. Configurar listeners de eventos
 * 4. Manejar errores
 */
const connectDB = async () => {
  try {
    // Obtener URI de variable de entorno
    // Formato local: mongodb://admin:123456@localhost:27017/?authSource=admin
    const mongoUri = process.env.MONGO_URI || 'mongodb://admin:123456@localhost:27017/?authSource=admin';
    
    // Conectar a MongoDB
    // Mongoose maneja automáticamente:
    // - Pool de conexiones
    // - Reintentos en caso de error
    // - Buffer de operaciones
    await mongoose.connect(mongoUri);
    
    console.log('✅ MongoDB connected successfully');
    
    // Listener: Error en la conexión después de establecida
    mongoose.connection.on('error', (err) => {
      console.error('MongoDB connection error:', err);
    });
    
    // Listener: Desconexión inesperada
    mongoose.connection.on('disconnected', () => {
      console.log('MongoDB disconnected');
    });
    
  } catch (error) {
    console.error('❌ MongoDB connection error:', error.message);
    // Salir del proceso si no puede conectar
    // El servidor no puede funcionar sin base de datos
    process.exit(1);
  }
};

// Exportar función de conexión
module.exports = { connectDB };
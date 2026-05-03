/**
 * =====================================================
 * MODELO DE USUARIO - MONGODB/MONGOOSE
 * =====================================================
 * Define la estructura de datos de un usuario en la base de datos
 * Incluye validaciones, métodos de autenticación y sanitización
 */

const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

/**
 * Esquema de usuario con todos los campos necesarios
 */
const userSchema = new mongoose.Schema({
  // =====================================================
  // EMAIL - Identificador único del usuario
  // =====================================================
  email: {
    type: String,
    required: true, // Obligatorio
    unique: true, // No puede haber duplicados
    lowercase: true, // Guardar en minúsculas
    trim: true // Eliminar espacios al inicio/final
  },

  // =====================================================
  // PASSWORD - Contraseña hasheada (nullable para Google)
  // =====================================================
  password: {
    type: String,
    nullable: true // Puede ser nulo si usa Google
  },

  // =====================================================
  // GOOGLE ID - ID de usuario en Google OAuth
  // =====================================================
  googleId: {
    type: String,
    nullable: true
  },

  // =====================================================
  // NAME - Nombre completo del usuario
  // =====================================================
  name: {
    type: String,
    required: true,
    trim: true
  },

  // =====================================================
  // AVATAR - Ruta o URL de la imagen de perfil
  // =====================================================
  avatar: {
    type: String,
    default: '' // Empty por defecto
  },

  // =====================================================
  // ROLE - Rol del usuario para permisos
  // =====================================================
  role: {
    type: String,
    enum: ['user', 'editor', 'admin'], // Solo estos valores permitidos
    default: 'user' // Por defecto usuario normal
  },

  // =====================================================
  // PROVIDER - Método de autenticación usado
  // =====================================================
  provider: {
    type: String,
    enum: ['local', 'google'], // local = email/password, google = OAuth
    default: 'local'
  },

  // =====================================================
  // LOCKED - Estado de bloqueo de la cuenta
  // =====================================================
  locked: {
    type: Boolean,
    default: false // false = cuenta activa
  },

  // =====================================================
  // LOCKED UNTIL - Fecha de desbloqueo automático
  // =====================================================
  lockedUntil: {
    type: Date,
    nullable: true // null = no bloqueado o ya desbloqueado
  },

  // =====================================================
  // FAILED ATTEMPTS - Contador de intentos fallidos
  // =====================================================
  failedAttempts: {
    type: Number,
    default: 0 // Se reinicia al login exitoso
  },

  // =====================================================
  // REFRESH TOKEN - Token para renovar acceso
  // =====================================================
  refreshToken: {
    type: String,
    nullable: true
  }
}, {
  // =====================================================
  // TIMESTAGS - Fechas automáticas de creación/actualización
  // =====================================================
  timestamps: true // Crea createdAt y updatedAt automáticamente
});

// =====================================================
// MIDDLEWARE PRE-SAVE - HASH DE CONTRASEÑA
// =====================================================
// Se ejecuta antes de guardar en la BD
// Hashea la contraseña con bcrypt (salt = 10 rounds)
// Solo ejecuta si: se modifica el password Y no es nulo
userSchema.pre('save', async function(next) {
  // Si no se modificó el password o está vacío, continuar
  if (!this.isModified('password') || !this.password) return next();
  
  try {
    // Generar salt (texto aleatorio para seguridad)
    const salt = await bcrypt.genSalt(10);
    // Hashear contraseña con el salt
    this.password = await bcrypt.hash(this.password, salt);
    next(); // Continuar con el save
  } catch (error) {
    next(error); // Pasar error al manejador
  }
});

// =====================================================
// MÉTODO: COMPARAR CONTRASEÑA
// =====================================================
// Compara contraseña ingresada con la hash en BD
// Retorna true/false
userSchema.methods.comparePassword = async function(candidatePassword) {
  if (!this.password) return false; // Google users no tienen password
  return bcrypt.compare(candidatePassword, this.password);
};

// =====================================================
// MÉTODO: CONVERTIR A JSON
// =====================================================
// Se ejecuta al convertir el documento a JSON (respuesta API)
// Elimina campos sensibles que NO deben enviarse al frontend
userSchema.methods.toJSON = function() {
  const obj = this.toObject();
  delete obj.password; // NUNCA enviar contraseña hasheada
  delete obj.refreshToken; // Token de sesión no se envía
  delete obj.locked; // Estado interno
  delete obj.lockedUntil; // Datos de bloqueo interno
  delete obj.failedAttempts; // Contador interno
  return obj;
};

// =====================================================
// EXPORTAR MODELO
// =====================================================
module.exports = mongoose.model('User', userSchema);
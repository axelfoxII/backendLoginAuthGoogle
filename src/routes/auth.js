/**
 * =====================================================
 * RUTAS DE AUTENTICACIÓN - /api/auth/*
 * =====================================================
 * Maneja todas las operaciones de autenticación:
 * - Registro de usuarios
 * - Login con email/password
 * - Login con Google OAuth
 * - Logout
 * - Obtener usuario actual
 */

const express = require('express');
const multer = require('multer'); // Middleware para manejo de archivos
const path = require('path');
const fs = require('fs');
const { body, validationResult } = require('express-validator'); // Validación de inputs
const { check } = require('express-validator');
const User = require('../models/User');
const { generateToken, generateRefreshToken } = require('../services/tokenService');
const { tokenBlacklist } = require('../middleware/auth');
const config = require('../config');

const router = express.Router();

// =====================================================
// CONFIGURACIÓN DE MULTER - SUBIDA DE AVATARES
// =====================================================
// Multer maneja la subida de archivos al servidor
// Configuración de almacenamiento en disco

// storage: Define dónde y cómo guardar los archivos
const storage = multer.diskStorage({
  // destination: Carpeta destino para las imágenes
  destination: (req, file, cb) => {
    const uploadDir = path.join(__dirname, '../../uploads');
    // Crear carpeta si no existe
    if (!fs.existsSync(uploadDir)) {
      fs.mkdirSync(uploadDir, { recursive: true });
    }
    cb(null, uploadDir);
  },
  // filename: Nombre del archivo guardado
  filename: (req, file, cb) => {
    // Generar nombre único: avatar-timestamp-random.ext
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, 'avatar-' + uniqueSuffix + path.extname(file.originalname));
  }
});

// fileFilter: Validar tipo de archivo
const fileFilter = (req, file, cb) => {
  // Solo permitir imágenes PNG y JPEG
  if (config.upload.allowedTypes.includes(file.mimetype)) {
    cb(null, true);
  } else {
    cb(new Error('Invalid file type. Only PNG and JPEG are allowed.'), false);
  }
};

// Configuración final de multer
const upload = multer({
  storage,
  limits: { fileSize: config.upload.maxSize }, // Máximo 2MB
  fileFilter
});

// =====================================================
// VALIDACIÓN DE PETICIONES
// =====================================================
// Middleware que verifica si hay errores de validación
// Si los hay, retorna 400 con los errores
const validateRequest = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }
  next();
};

// =====================================================
// VALIDACIÓN DE CONTRASEÑA SEGURA
// =====================================================
// passwordStrong: Verifica que la contraseña tenga:
// - Mínimo 8 caracteres
// - Al menos 1 mayúscula
// - Al menos 1 minúscula
// - Al menos 1 número
// - Al menos 1 carácter especial
const passwordStrong = check('password')
  .isLength({ min: 8 }).withMessage('Password must be at least 8 characters')
  .matches(/[A-Z]/).withMessage('Password must contain at least 1 uppercase letter')
  .matches(/[a-z]/).withMessage('Password must contain at least 1 lowercase letter')
  .matches(/[0-9]/).withMessage('Password must contain at least 1 number')
  .matches(/[!@#$%^&*(),.?":{}|<>]/).withMessage('Password must contain at least 1 special character');


// =====================================================
// POST /register - Registrar nuevo usuario
// =====================================================
// Body (form-data):
//   - name: string (2-50 chars)
//   - email: string (debe ser @.com)
//   - password: string (mín 8 chars, mayús, minús, número, special)
//   - confirm_password: string
//   - role: optional ('user', 'editor', 'admin')
//   - avatar: file (opcional)
//
// Respuesta (201):
//   - message: "User registered successfully"
//   - user: { id, name, email, role, avatar }
router.post('/register',
  upload.single('avatar'), // Middleware de multer para subir archivo
  [
    // Validaciones con express-validator
    body('email').isEmail().withMessage('Valid email is required')
      .matches(/@.+\.com$/).withMessage('Email must end with .com'),
    passwordStrong, // Validación de contraseña fuerte
    body('confirm_password').notEmpty().withMessage('Confirm password is required'),
    body('name').isLength({ min: 2, max: 50 }).withMessage('Name must be between 2 and 50 characters'),
    body('role').optional().isIn(['user', 'editor', 'admin']).withMessage('Invalid role')
  ],
  validateRequest, // Verificar validaciones
  async (req, res) => {
    // Debug: Ver qué llega del frontend
    console.log('=== REGISTER DEBUG ===');
    console.log('req.body:', req.body);
    console.log('req.file:', req.file);
    
    try {
      // Extraer datos del body
      const { email, password, confirm_password, name, role } = req.body;
      
      // Validar que todos los campos obrigatorios existan
      if (!email || !password || !confirm_password || !name) {
        return res.status(400).json({ message: 'All fields are required' });
      }
      
      // Verificar que password y confirm_password coincidan
      if (password !== confirm_password) {
        return res.status(400).json({ message: 'Passwords do not match' });
      }
      
      // Verificar si el email ya existe en la base de datos
      const existingUser = await User.findOne({ email: email.toLowerCase() });
      if (existingUser) {
        return res.status(409).json({ message: 'Email already exists' });
      }
      
      // Si hay archivo de avatar, guardar la ruta
      let avatarPath = '';
      if (req.file) {
        avatarPath = '/uploads/' + req.file.filename;
      }
      
      // Crear nuevo usuario
      const user = new User({
        email: email.toLowerCase(),
        password, // Se hasheará automáticamente en el pre-save
        name,
        avatar: avatarPath,
        role: role || 'user', // Por defecto 'user'
        provider: 'local',
        failedAttempts: 0, // Iniciar en 0
        locked: false // Cuenta no bloqueada
      });
      
      // Guardar en MongoDB
      await user.save();
      
      // Generar tokens JWT
      const token = generateToken(user);
      const refreshToken = generateRefreshToken(user);
      
      // Guardar refreshToken en la base de datos
      user.refreshToken = refreshToken;
      await user.save();
      
      // Convertir a JSON (limpia campos sensibles automáticamente)
      const userData = user.toJSON();
      
      // Responder con éxito
      res.status(201).json({
        message: 'User registered successfully',
        user: userData
      });
    } catch (error) {
      console.error('Register error:', error);
      res.status(500).json({ message: 'Server error' });
    }
  }
);


// =====================================================
// POST /login - Iniciar sesión
// =====================================================
// Body (JSON):
//   - email: string
//   - password: string
//
// Respuesta (200):
//   - message: "Login successful"
//   - token: JWT token
//   - user: { id, name, email, role, avatar }
router.post('/login',
  [
    body('email').isEmail().withMessage('Valid email is required')
      .matches(/@.+\.com$/).withMessage('Email must end with .com'),
    body('password').notEmpty().withMessage('Password is required')
  ],
  validateRequest,
  async (req, res) => {
    try {
      const { email, password } = req.body;
      
      // Buscar usuario por email
      const user = await User.findOne({ email: email.toLowerCase() });
      if (!user) {
        return res.status(401).json({ message: 'Invalid credentials' });
      }
      
      // Verificar si la cuenta está bloqueada
      if (user.locked && user.lockedUntil && new Date(user.lockedUntil) > new Date()) {
        return res.status(423).json({ message: 'Account locked. Try again later.' });
      }
      
      // Verificar si el usuario se registró con Google
      if (user.provider === 'google') {
        return res.status(401).json({ message: 'Please login with Google' });
      }
      
      // Comparar contraseña
      const isMatch = await user.comparePassword(password);
      if (!isMatch) {
        // Incrementar contador de intentos fallidos
        user.failedAttempts = (user.failedAttempts || 0) + 1;
        
        // Si reach 5 intentos, bloquear por 15 minutos
        if (user.failedAttempts >= 5) {
          user.locked = true;
          user.lockedUntil = new Date(Date.now() + 15 * 60 * 1000); // 15 minutos
          await user.save();
          return res.status(423).json({ message: 'Account locked for 15 minutes due to too many failed attempts' });
        }
        
        await user.save();
        return res.status(401).json({ message: 'Invalid credentials' });
      }
      
      // Login exitoso - reiniciar contadores
      user.failedAttempts = 0;
      user.locked = false;
      user.lockedUntil = null;
      
      // Generar tokens
      const token = generateToken(user);
      const refreshToken = generateRefreshToken(user);
      
      // Guardar refreshToken
      user.refreshToken = refreshToken;
      await user.save();
      
      // Responder con tokens y datos del usuario
      res.json({
        message: 'Login successful',
        token,
        user: user.toJSON()
      });
    } catch (error) {
      console.error('Login error:', error);
      res.status(500).json({ message: 'Server error' });
    }
  }
);


// =====================================================
// POST /google - Login con Google OAuth
// =====================================================
// Body (JSON):
//   - credential: string (token de Google desde el frontend)
//
// Flujo:
// 1. Verificar el token de Google
// 2. Buscar usuario por googleId o email
// 3. Crear usuario si no existe
// 4. Generar tokens JWT
router.post('/google',
  [
    body('credential').notEmpty().withMessage('Google credential is required')
  ],
  validateRequest,
  async (req, res) => {
    try {
      const { credential } = req.body;
      
      // Debug: Verificar que el Client ID está configurado
      const clientId = process.env.GOOGLE_CLIENT_ID;
      console.log('🔍 Google Client ID:', clientId);
      console.log('🔍 Credential received:', credential ? 'Yes' : 'No');
      console.log('🔍 Credential length:', credential ? credential.length : 0);
      
      if (!clientId) {
        return res.status(500).json({ message: 'Google Client ID not configured' });
      }
      
      if (!credential) {
        return res.status(400).json({ message: 'Credential is required' });
      }
      
      // Importar Google Auth Library
      const { OAuth2Client } = require('google-auth-library');
      const client = new OAuth2Client(clientId);
      
      // Verificar el token de Google con validaciones adicionales
      const ticket = await client.verifyIdToken({
        idToken: credential,
        audience: clientId,
        issuer: 'https://accounts.google.com'
      });
      
      // Obtener datos del usuario de Google
      const payload = ticket.getPayload();
      const { sub: googleId, email, name, picture } = payload;
      
      // Buscar usuario por googleId
      let user = await User.findOne({ googleId });
      
      // Si no existe, buscar por email (podría existir cuenta local)
      if (!user) {
        user = await User.findOne({ email: email.toLowerCase() });
        
        if (user) {
          // Vincular cuenta existente con Google
          user.googleId = googleId;
          user.provider = 'google';
          // Usar imagen de Google si no tiene avatar
          if (!user.avatar && picture) {
            user.avatar = picture;
          }
          await user.save();
        } else {
          // Crear nuevo usuario con datos de Google
          user = new User({
            email: email.toLowerCase(),
            googleId,
            name,
            avatar: picture || '',
            provider: 'google',
            role: 'user',
            failedAttempts: 0,
            locked: false
          });
          await user.save();
        }
      }
      
      // Reiniciar contadores de seguridad
      user.failedAttempts = 0;
      user.locked = false;
      
      // Generar tokens
      const token = generateToken(user);
      const refreshToken = generateRefreshToken(user);
      
      user.refreshToken = refreshToken;
      await user.save();
      
      res.json({
        message: 'Google login successful',
        token,
        user: user.toJSON()
      });
    } catch (error) {
      console.error('Google login error:', error);
      res.status(401).json({ message: 'Invalid Google token' });
    }
  }
);


// =====================================================
// POST /logout - Cerrar sesión
// =====================================================
// Headers: Authorization: Bearer <token>
//
// Acciones:
// 1. Agregar token a blacklist (invalidar token actual)
// 2. Limpiar refreshToken en la base de datos
router.post('/logout', require('../middleware/auth'), async (req, res) => {
  try {
    const token = req.token;
    // Agregar a blacklist para invalidar el token actual
    tokenBlacklist.add(token);
    
    // Limpiar refreshToken de la base de datos
    req.user.refreshToken = null;
    await req.user.save();
    
    res.json({ message: 'Logout successful' });
  } catch (error) {
    console.error('Logout error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});


// =====================================================
// GET /me - Obtener usuario actual
// =====================================================
// Headers: Authorization: Bearer <token>
//
// Respuesta (200):
//   - user: { id, name, email, role, avatar }
router.get('/me', require('../middleware/auth'), async (req, res) => {
  // req.user viene del middleware de autenticación
  res.json({ user: req.user.toJSON() });
});

module.exports = router;
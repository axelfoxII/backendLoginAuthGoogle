/**
 * =====================================================
 * RUTAS DE USUARIOS - /api/users/*
 * =====================================================
 * CRUD completo de usuarios:
 * - Listar usuarios
 * - Ver usuario específico
 * - Actualizar usuario
 * - Eliminar usuario
 * - Subir avatar
 * 
 * IMPORTANTE: Todas las rutas requieren autenticación (excepto login/register)
 */

const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const User = require('../models/User');
const auth = require('../middleware/auth');
const role = require('../middleware/role');
const config = require('../config');
const { body, validationResult } = require('express-validator');

const router = express.Router();

// =====================================================
// CONFIGURACIÓN DE MULTER (igual que en auth.js)
// =====================================================
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadDir = path.join(__dirname, '../../uploads');
    if (!fs.existsSync(uploadDir)) {
      fs.mkdirSync(uploadDir, { recursive: true });
    }
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, 'avatar-' + uniqueSuffix + path.extname(file.originalname));
  }
});

const fileFilter = (req, file, cb) => {
  if (config.upload.allowedTypes.includes(file.mimetype)) {
    cb(null, true);
  } else {
    cb(new Error('Invalid file type. Only PNG and JPEG are allowed.'), false);
  }
};

const upload = multer({
  storage,
  limits: { fileSize: config.upload.maxSize },
  fileFilter
});


// =====================================================
// =====================================================
// POST /users - Crear nuevo usuario
// =====================================================
// Requiere: autenticación
// Roles permitidos: solo admin
// Body (form-data):
//   - name: string
//   - email: string
//   - password: string
//   - role: optional ('user', 'editor', 'admin')
//   - image: optional (avatar)
router.post('/',
  auth,
  role('admin'),
  upload.single('image'),
  async (req, res) => {
    try {
      const { name, email, password, role: newRole } = req.body;

      if (!name || !email || !password) {
        return res.status(400).json({ message: 'Name, email and password are required' });
      }

      const existingUser = await User.findOne({ email: email.toLowerCase() });
      if (existingUser) {
        return res.status(409).json({ message: 'Email already exists' });
      }

      let avatarPath = '';
      if (req.file) {
        avatarPath = '/uploads/' + req.file.filename;
      }

      const user = new User({
        name,
        email: email.toLowerCase(),
        password,
        avatar: avatarPath,
        role: newRole || 'user',
        provider: 'local',
        failedAttempts: 0,
        locked: false
      });

      await user.save();

      res.status(201).json({
        message: 'User created successfully',
        user: user.toJSON()
      });
    } catch (error) {
      console.error('Create user error:', error);
      res.status(500).json({ message: 'Server error' });
    }
  }
);


// GET /users - Listar todos los usuarios
// =====================================================
// Requiere: autenticación
// Roles permitidos: admin, editor
// 
// Respuesta: Array de usuarios (sin datos sensibles)
router.get('/', auth, async (req, res) => {
  try {
    // Seleccionar todos los usuarios excepto campos sensibles
    const users = await User.find()
      .select('-password -refreshToken -locked -lockedUntil -failedAttempts');
    res.json(users);
  } catch (error) {
    console.error('Get users error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});


// =====================================================
// GET /users/:id - Ver usuario por ID
// =====================================================
// Requiere: autenticación
// Roles permitidos: cualquier usuario autenticado
// 
// Parámetros: :id - ID del usuario en MongoDB
// Respuesta: Objeto usuario
router.get('/:id', auth, async (req, res) => {
  try {
    const user = await User.findById(req.params.id)
      .select('-password -refreshToken -locked -lockedUntil -failedAttempts');
    
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    
    res.json(user);
  } catch (error) {
    console.error('Get user error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});


// =====================================================
// PATCH /users/:id - Actualizar usuario
// =====================================================
// Requiere: autenticación
// Roles permitidos: 
//   - El propio usuario (puede editar su perfil)
//   - admin y editor (pueden editar cualquier usuario)
// 
// Body (form-data):
//   - name: string (opcional)
//   - email: string (opcional)
//   - password: string (opcional, mín 6 chars)
//   - role: string ('admin', 'editor', 'user') - solo admin puede cambiar rol
//   - image: file (opcional, para avatar)

// =====================================================
// PATCH /users/:id/avatar - Actualizar avatar de usuario
// IMPORTANTE: Esta ruta debe estar ANTES de PATCH /:id para evitar conflictos
// =====================================================
// Multer sin restricciones de campos para evitar "Unexpected field"
const uploadAvatar = multer({
  storage: multer.diskStorage({
    destination: (req, file, cb) => {
      const uploadDir = path.join(__dirname, '../../uploads');
      if (!fs.existsSync(uploadDir)) {
        fs.mkdirSync(uploadDir, { recursive: true });
      }
      cb(null, uploadDir);
    },
    filename: (req, file, cb) => {
      const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
      cb(null, 'avatar-' + uniqueSuffix + path.extname(file.originalname));
    }
  })
  // SIN fileFilter para aceptar cualquier tipo de archivo
});

// PATCH /users/:id/avatar - Actualizar avatar
router.patch('/:id/avatar',
  auth,
  uploadAvatar.single('image'),
  async (req, res) => {
    console.log('=== PATCH /:id/avatar ===');
    console.log('req.params.id:', req.params.id);
    console.log('req.body:', req.body);
    console.log('req.file:', req.file);
    
    if (!req.file) {
      return res.status(400).json({ message: 'No file uploaded' });
    }

    try {
      const { id } = req.params;
      const { oldAvatar } = req.body;

      const targetUser = await User.findById(id);
      if (!targetUser) {
        return res.status(404).json({ message: 'User not found' });
      }

      const isAdminOrEditor = req.user.role === 'admin' || req.user.role === 'editor';
      const isOwnProfile = req.user._id.toString() === id;
      
      if (!isAdminOrEditor && !isOwnProfile) {
        return res.status(403).json({ message: 'Not authorized' });
      }

      if (targetUser.provider === 'google') {
        return res.status(403).json({ message: 'Cannot change avatar for Google users' });
      }

      const avatarPath = '/uploads/' + req.file.filename;
      
      const avatarToDelete = oldAvatar || targetUser.avatar;
      if (avatarToDelete && avatarToDelete.startsWith('/uploads/')) {
        const oldAvatarPath = path.join(__dirname, '../../', avatarToDelete);
        if (fs.existsSync(oldAvatarPath)) {
          fs.unlinkSync(oldAvatarPath);
        }
      }

      targetUser.avatar = avatarPath;
      await targetUser.save();

      res.json({ message: 'Avatar updated successfully', avatar: avatarPath });
    } catch (error) {
      console.error('Avatar update error:', error);
      res.status(500).json({ message: 'Server error' });
    }
  }
);

//
// Reglas:
// - Un admin no puede eliminarse a sí mismo
// - Se elimina la imagen de perfil asociada
router.delete('/:id', auth, role('admin'), async (req, res) => {
  try {
    const { id } = req.params;
    
    // Un admin no puede eliminarse a sí mismo
    if (req.user._id.toString() === id) {
      return res.status(403).json({ message: 'You cannot delete yourself' });
    }
    
    const user = await User.findById(id);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    
    // Eliminar imagen de perfil si existe
    if (user.avatar && user.avatar.startsWith('/uploads/')) {
      const avatarPath = path.join(__dirname, '../../', user.avatar);
      if (fs.existsSync(avatarPath)) {
        fs.unlinkSync(avatarPath);
      }
    }
    
    // Eliminar usuario de la base de datos
    await User.findByIdAndDelete(id);
    
    res.json({ message: 'User deleted successfully' });
  } catch (error) {
    console.error('Delete user error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});


// =====================================================
// POST /users/avatar - Subir avatar (ruta alternativa)
// =====================================================
// Requiere: autenticación
// Body (form-data):
//   - image: archivo de imagen
router.post('/avatar',
  auth,
  upload.single('image'),
  async (req, res) => {
    try {
      if (!req.file) {
        return res.status(400).json({ message: 'No file uploaded' });
      }

      // No permitir cambio de avatar para usuarios de Google
      if (req.user.provider === 'google') {
        return res.status(403).json({ message: 'Cannot change avatar for Google users' });
      }

      const avatarPath = '/uploads/' + req.file.filename;
      
      // Eliminar avatar anterior si existe
      if (req.user.avatar && req.user.avatar.startsWith('/uploads/')) {
        const oldAvatarPath = path.join(__dirname, '../../', req.user.avatar);
        if (fs.existsSync(oldAvatarPath)) {
          fs.unlinkSync(oldAvatarPath);
        }
      }

      req.user.avatar = avatarPath;
      await req.user.save();

      res.json({
        message: 'Avatar uploaded successfully',
        avatar: avatarPath
      });
    } catch (error) {
      console.error('Avatar upload error:', error);
      res.status(500).json({ message: 'Server error' });
    }
  }
);


// =====================================================
// PATCH /users/:id/avatar - Actualizar avatar de usuario
// =====================================================
// Endpoint agregado para permitir cambio de avatar desde el perfil
module.exports = router;
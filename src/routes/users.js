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
router.patch('/:id',
  auth,
  upload.single('image'),
  async (req, res) => {
    try {
      const { id } = req.params;
      const { name, email, password, role: newRole } = req.body;
      
      // Buscar usuario a actualizar
      const targetUser = await User.findById(id);
      if (!targetUser) {
        return res.status(404).json({ message: 'User not found' });
      }
      
      // Verificar permisos
      // Admin/Editor pueden editar cualquier usuario
      // Usuarios normales solo pueden editar su propio perfil
      const isAdminOrEditor = req.user.role === 'admin' || req.user.role === 'editor';
      const isOwnProfile = req.user._id.toString() === id;
      
      if (!isAdminOrEditor && !isOwnProfile) {
        return res.status(403).json({ message: 'Not authorized to update this user' });
      }
      
      // Actualizar campos si se proporcionan
      if (name) targetUser.name = name;
      if (email) targetUser.email = email.toLowerCase();
      if (password && password.length >= 6) targetUser.password = password;
      
      // Solo el admin puede cambiar el rol de otros usuarios
      // Un admin no puede cambiar su propio rol
      if (req.user.role === 'admin' && newRole && !isOwnProfile) {
        targetUser.role = newRole;
      }
      
      // Si hay nuevo archivo de imagen, actualizar avatar
      if (req.file) {
        const avatarPath = '/uploads/' + req.file.filename;
        
        // Eliminar avatar anterior si existe
        if (targetUser.avatar && targetUser.avatar.startsWith('/uploads/')) {
          const oldAvatarPath = path.join(__dirname, '../../', targetUser.avatar);
          if (fs.existsSync(oldAvatarPath)) {
            fs.unlinkSync(oldAvatarPath);
          }
        }
        
        targetUser.avatar = avatarPath;
      }
      
      // Guardar cambios
      await targetUser.save();
      
      res.json({
        message: 'User updated successfully',
        user: targetUser.toJSON()
      });
    } catch (error) {
      console.error('Update user error:', error);
      res.status(500).json({ message: 'Server error' });
    }
  }
);


// =====================================================
// DELETE /users/:id - Eliminar usuario
// =====================================================
// Requiere: autenticación
// Roles permitidos: solo admin
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

module.exports = router;
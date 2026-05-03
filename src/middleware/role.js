/**
 * =====================================================
 * MIDDLEWARE DE VERIFICACIÓN DE ROLES
 * =====================================================
 * Protege rutas permitiendo solo ciertos roles de usuario
 * 
 * USO:
 * router.delete('/ruta', auth, role('admin'), handler)
 * 
 * Ejemplos:
 * - role('admin') - Solo admin puede acceder
 * - role('admin', 'editor') - Admin y editor pueden acceder
 */

const role = (...allowedRoles) => {
  /**
   * Middleware que verifica el rol del usuario
   * @param {Object} req - Request de Express (debe tener req.user del auth middleware)
   * @param {Object} res - Response de Express
   * @param {Function} next - Función para continuar
   */
  return (req, res, next) => {
    // 1. Verificar que el usuario esté autenticado (auth middleware debe ejecutarse antes)
    if (!req.user) {
      return res.status(401).json({ message: 'Not authenticated' });
    }
    
    // 2. Verificar si el rol del usuario está en la lista de roles permitidos
    if (!allowedRoles.includes(req.user.role)) {
      return res.status(403).json({ message: 'Insufficient permissions' });
    }
    
    // 3. El usuario tiene el rol correcto, continuar
    next();
  };
};

module.exports = role;
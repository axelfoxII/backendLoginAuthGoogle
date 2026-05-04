# Auth System - Sistema de Autenticación JWT

## 📋 Descripción

Sistema completo de autenticación con JWT, roles, login tradicional y Google OAuth, incluyendo gestión de usuarios y avatares.

## 🛠️ Tecnologías

- **Backend**: Node.js + Express
- **Base de datos**: MongoDB
- **Autenticación**: JWT + Google OAuth
- **Seguridad**: bcryptjs, helmet, rate limiting

## 📁 Estructura del Proyecto

```
src/
├── config/                 # Configuraciones
│   ├── index.js           # Variables de entorno y constantes
│   └── database.js        # Conexión a MongoDB
│
├── middleware/            # Middlewares de Express
│   ├── auth.js           # Verificación de JWT
│   └── role.js           # Verificación de roles
│
├── models/                # Modelos de MongoDB
│   └── User.js           # Esquema de usuario
│
├── routes/                # Rutas de la API
│   ├── auth.js           # Endpoints de autenticación
│   └── users.js          # Endpoints de usuarios
│
├── services/              # Servicios auxiliares
│   └── tokenService.js   # Generación de tokens JWT
│
└── index.js              # Servidor principal
```

## 🔧 Variables de Entorno (.env)

| Variable | Descripción | Ejemplo |
|----------|-------------|---------|
| `JWT_SECRET` | Clave secreta para firmar JWT (CAMBIAR EN PRODUCCIÓN!) | `clave-secreta-muy-larga` |
| `GOOGLE_CLIENT_ID` | Client ID de Google Cloud Console | `xxx.apps.googleusercontent.com` |
| `GOOGLE_CLIENT_SECRET` | Client Secret de Google | `xxx` |
| `MONGO_URI` | URI de conexión MongoDB | `mongodb://admin:123456@localhost:27017/?authSource=admin` |
| `PORT` | Puerto del servidor | `3000` |
| `NODE_ENV` | Entorno (development/production) | `development` |
| `ALLOWED_ORIGINS` | Origins permitidos para CORS | `http://localhost:4200` |

## 📡 Endpoints de la API

### Autenticación

| Método | Endpoint | Descripción | Auth |
|--------|----------|-------------|------|
| POST | `/api/auth/register` | Registrar nuevo usuario | ❌ |
| POST | `/api/auth/login` | Iniciar sesión | ❌ |
| POST | `/api/auth/google` | Login con Google | ❌ |
| POST | `/api/auth/logout` | Cerrar sesión | ✅ |
| GET | `/api/auth/me` | Obtener usuario actual | ✅ |

### Usuarios

| Método | Endpoint | Descripción | Auth | Rol |
|--------|----------|-------------|------|-----|
| GET | `/api/users` | Listar todos los usuarios | ✅ | admin/editor |
| GET | `/api/users/:id` | Ver usuario por ID | ✅ | cualquier |
| PATCH | `/api/users/:id` | Actualizar usuario | ✅ | any |
| DELETE | `/api/users/:id` | Eliminar usuario | ✅ | admin |

### Imágenes

| Método | Endpoint | Descripción |
|--------|----------|-------------|
| GET | `/uploads/:filename` | Ver imagen de perfil |

## 🔐 Roles de Usuario

| Rol | Descripción |
|-----|-------------|
| `user` | Usuario regular (por defecto) |
| `editor` | Puede ver y editar usuarios |
| `admin` | Acceso completo, puede eliminar |

## 📝 Validaciones

### Registro
- **Email**: Debe ser válido y terminar en `.com`
- **Password**: Mínimo 8 caracteres, 1 mayúscula, 1 minúscula, 1 número, 1 carácter especial
- **Name**: Entre 2 y 50 caracteres

### Login
- Máximo 5 intentos fallidos = bloqueo por 15 minutos
- Rate limit: 10 peticiones cada 15 minutos

## 🔄 Flujos de Autenticación

### 1. Registro con Email/Password
```
Frontend → POST /auth/register (form-data) → Backend
                                              ↓
                                    Validar datos
                                              ↓
                                    Hashear password (bcrypt)
                                              ↓
                                    Guardar en MongoDB
                                              ↓
                                    Generar JWT token
                                              ↓
Frontend ← { token, user } ← Backend
```

### 2. Login
```
Frontend → POST /auth/login (JSON) → Backend
                                        ↓
                              Buscar usuario por email
                                        ↓
                              Verificar contraseña (bcrypt)
                                        ↓
                              Generar JWT + refresh token
                                        ↓
Frontend ← { token, user } ← Backend
```

### 3. Google OAuth
```
Frontend → Click "Login with Google" → Google Popup
                                            ↓
                    Usuario acepta → Google retorna credential
                                            ↓
Frontend → POST /auth/google { credential } → Backend
                                                 ↓
                                    Verificar token con Google
                                                 ↓
                                    Buscar/crear usuario
                                                 ↓
                                    Generar JWT token
                                                 ↓
Frontend ← { token, user } ← Backend
```

### 4. Logout
```
Frontend → POST /auth/logout → Backend
                                 ↓
                    Agregar token a blacklist
                                 ↓
                    Limpiar refreshToken en BD
                                 ↓
Frontend ← { message } ← Backend
```

## 🚀 Iniciar el Proyecto

### 1. Instalar dependencias
```bash
npm install
```

### 2. Configurar variables de entorno
```bash
# Editar .env con tus valores
```

### 3. Asegurar que MongoDB esté corriendo
```bash
# MongoDB local o conexión a Atlas
```

### 4. Iniciar servidor
```bash
npm start
# Servidor en http://localhost:3000
```

## 🔒 Medidas de Seguridad Implementadas

1. **Helmet** - Headers de seguridad HTTP
2. **CORS** - Control de accesos cruzados
3. **Rate Limiting** - Limitación de peticiones
4. **bcryptjs** - Hash de contraseñas
5. **JWT** - Tokens firmados con expiración
6. **Blacklist** - Invalidar tokens al logout
7. **Validación de inputs** - express-validator
8. **Límite de body** - 10KB máximo
9. **Bloqueo por intentos fallidos** - 5 intentos = 15 min

## 📱 Uso con Frontend

### Configurar Google OAuth

1. Ir a [Google Cloud Console](https://console.cloud.google.com/)
2. Crear proyecto
3. Habilitar "Google Identity Services API"
4. Crear OAuth Client ID
5. Agregar origins autorizados:
   - `http://localhost:3000`
   - `http://127.0.0.1:3000`
   - `http://localhost:4200`
   - `http://127.0.0.1:4200`
   - `http://localhost:5173` (Mongo)
6. Obtener CLIENT_ID y CLIENT_SECRET

### Configurar Proxy (Angular)

En `proxy.conf.json`:
```json
{
  "/api": { "target": "http://localhost:3000", "secure": false },
  "/uploads": { "target": "http://localhost:3000", "secure": false }
}
```

## ✅ testing con Postman

### Registro
```
POST http://localhost:3000/api/auth/register
Body (form-data):
  - name: "Juan"
  - email: "juan@test.com"
  - password: "Password1!"
  - confirm_password: "Password1!"
  - role: "user"
  - avatar: [archivo]
```

### Login
```
POST http://localhost:3000/api/auth/login
Body (JSON):
{
  "email": "juan@test.com",
  "password": "Password1!"
}
```

### Ver usuario actual
```
GET http://localhost:3000/api/auth/me
Headers:
  Authorization: Bearer <TOKEN>
```

---

Desarrollado con ❤️
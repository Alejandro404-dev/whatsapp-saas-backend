import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import bcrypt from 'bcryptjs';
import { prisma } from './prisma'; // Importamos nuestra conexión a la BD

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

// ==========================================
// ENDPOINT DE REGISTRO REAL (MULTITENANT + SUPERADMIN)
// ==========================================
app.post('/api/auth/register', async (req, res) => {
    try {
        const { companyName, email, password } = req.body;
        const hashedPassword = await bcrypt.hash(password, 10);

        // Usamos una Transacción: Si algo falla, se cancela todo (no quedan empresas huérfanas)
        const nuevoUsuario = await prisma.$transaction(async (tx) => {
            // 1. Creamos la Empresa (Tenant)
            const tenant = await tx.tenant.create({
                data: { name: companyName }
            });

            // 2. Creamos el Rol intocable del sistema para esta empresa
            const rolSuperAdmin = await tx.role.create({
                data: {
                    name: 'SuperAdmin',
                    description: 'Dueño absoluto del sistema',
                    permissions: ['ALL'], // Palabra clave de poder absoluto
                    isSystem: true,       // Nadie lo puede borrar o editar
                    tenantId: tenant.id
                }
            });

            // 3. Creamos al usuario y le damos las llaves
            const user = await tx.user.create({
                data: {
                    email: email,
                    password: hashedPassword,
                    tenantId: tenant.id,
                    roleId: rolSuperAdmin.id
                },
                include: { tenant: true, role: true }
            });

            return user;
        });

        res.json({
            existe: true,
            usuario: {
                id: nuevoUsuario.id,
                email: nuevoUsuario.email,
                role: nuevoUsuario.role.name,
                accesos: nuevoUsuario.role.permissions,
                tenantId: nuevoUsuario.tenantId,
                nombreEmpresa: nuevoUsuario.tenant.name
            },
            token: "jwt-real-pendiente-de-configurar"
        });

    } catch (error) {
        console.error("Error en registro:", error);
        res.status(500).json({ error: "Hubo un problema al registrar la cuenta" });
    }
});

// ==========================================
// ENDPOINT DE LOGIN REAL (CON VERIFICACIÓN)
// ==========================================
app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        const usuarioEncontrado = await prisma.user.findUnique({
            where: { email: email },
            include: {
                tenant: true,
                role: true
            }
        });

        if (!usuarioEncontrado) {
            return res.status(401).json({ error: "El correo o contraseña está mal, verificar los datos ingresados" });
        }

        // 3. Comparamos la contraseña que escribió el usuario con el hash guardado en PostgreSQL
        const isPasswordValid = await bcrypt.compare(password, usuarioEncontrado.password);

        if (!isPasswordValid) { // <-- Usamos la validación segura aquí
            return res.status(401).json({ error: "El correo o contraseña está mal, verificar los datos ingresados" });
        }

        res.json({
            existe: true,
            usuario: {
                id: usuarioEncontrado.id,
                email: usuarioEncontrado.email,
                role: usuarioEncontrado.role.name,
                accesos: usuarioEncontrado.role.permissions || [],
                tenantId: usuarioEncontrado.tenantId,
                nombreEmpresa: usuarioEncontrado.tenant.name
            },
            token: "jwt-real-pendiente-de-configurar"
        });

    } catch (error) {
        console.error("Error en login:", error);
        res.status(500).json({ error: "Error interno del servidor" });
    }
});

// Listar usuarios filtrados por Empresa (Tenant)
app.get('/api/users/:tenantId', async (req, res) => {
    try {
        const { tenantId } = req.params;
        const usuarios = await prisma.user.findMany({
            where: { tenantId: tenantId },
            include: { role: true }
        });

        const usuariosLimpios = usuarios.map(u => ({
            id: u.id,
            email: u.email,
            role: u.role.name,
            accesos: u.role.permissions,
            createdAt: u.createdAt
        }));

        res.json(usuariosLimpios);
    } catch (error) {
        res.status(500).json({ error: "No se pudieron obtener los usuarios" });
    }
});

// ==========================================
// ENDPOINT: CREAR NUEVO USUARIO EN UN TENANT
// ==========================================
app.post('/api/users', async (req, res) => {
    try {
        const { email, password, roleName, tenantId } = req.body;

        // 1. Validamos que el tenant exista
        const tenantExiste = await prisma.tenant.findUnique({ where: { id: tenantId } });
        if (!tenantExiste) {
            return res.status(404).json({ error: "La empresa no existe" });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        // 2. Buscamos o creamos el Rol usando la Llave Compuesta (nombre + empresa)
        const rolAsignado = await prisma.role.upsert({
            where: {
                name_tenantId: {
                    name: roleName,
                    tenantId: tenantId
                }
            },
            update: {}, // Si existe, no le hacemos nada
            create: {
                name: roleName,
                description: `Rol de ${roleName}`,
                tenantId: tenantId
            }
        });

        // 3. Creamos al usuario pasándole directamente los IDs
        const nuevoEmpleado = await prisma.user.create({
            data: {
                email: email,
                password: hashedPassword,
                tenantId: tenantId,
                roleId: rolAsignado.id // Usamos el ID del rol que acabamos de asegurar
            },
            include: { role: true }
        });

        res.json({
            id: nuevoEmpleado.id,
            email: nuevoEmpleado.email,
            role: nuevoEmpleado.role.name,
            accesos: nuevoEmpleado.role.permissions,
            createdAt: nuevoEmpleado.createdAt
        });

    } catch (error) {
        console.error("Error al crear empleado:", error);
        res.status(400).json({ error: "El correo ya está en uso o hubo un error en los datos." });
    }
});

// ==========================================
// ENDPOINT: ELIMINAR USUARIO
// ==========================================
app.delete('/api/users/:id', async (req, res) => {
    try {
        const { id } = req.params;
        console.log(`[DELETE] Intentando eliminar usuario con ID: ${id}`);

        // 1. Verificamos que el usuario realmente exista antes de intentar borrarlo
        const usuarioExiste = await prisma.user.findUnique({ where: { id } });
        
        if (!usuarioExiste) {
            console.log("Error: El usuario no existe en la BD.");
            return res.status(404).json({ error: "El usuario no existe o ya fue eliminado." });
        }

        // 2. Ejecutamos la eliminación
        await prisma.user.delete({
            where: { id: id }
        });

        console.log("Usuario eliminado con éxito de la BD.");
        res.json({ message: "Usuario eliminado correctamente" });

    } catch (error) {
        console.error("Error interno al eliminar en BD:", error);
        res.status(500).json({ error: "No se pudo eliminar el usuario por un error en el servidor." });
    }
});

// ==========================================
// ENDPOINT: EDITAR USUARIO (La 'U' del CRUD)
// ==========================================
app.put('/api/users/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const { email, password, roleName } = req.body;

        // 1. Sacamos los datos actuales del usuario para saber en qué empresa está
        const usuarioActual = await prisma.user.findUnique({ where: { id } });
        if (!usuarioActual) return res.status(404).json({ error: "Usuario no encontrado" });

        // 2. Buscamos o creamos el nuevo Rol en su misma empresa
        const rolAsignado = await prisma.role.upsert({
            where: {
                name_tenantId: {
                    name: roleName,
                    tenantId: usuarioActual.tenantId
                }
            },
            update: {},
            create: {
                name: roleName,
                description: `Rol de ${roleName}`,
                tenantId: usuarioActual.tenantId
            }
        });

        // 3. Preparamos los datos básicos a actualizar
        const datosActualizados: any = {
            email: email,
            roleId: rolAsignado.id // Actualizamos su rol
        };

        // 4. Solo encriptamos si nos mandaron una contraseña nueva
        if (password && password.trim() !== "") {
            datosActualizados.password = await bcrypt.hash(password, 10);
        }

        // 5. Ejecutamos la actualización
        const usuarioEditado = await prisma.user.update({
            where: { id: id },
            data: datosActualizados,
            include: { role: true }
        });

        res.json({
            id: usuarioEditado.id,
            email: usuarioEditado.email,
            role: usuarioEditado.role.name,
            accesos: usuarioEditado.role.permissions, // <--- AGREGAR ESTA LÍNEA
            createdAt: usuarioEditado.createdAt
        });


    } catch (error) {
        console.error("Error al editar:", error);
        res.status(500).json({ error: "No se pudo actualizar el usuario." });
    }
});

// ==========================================
// ENDPOINTS: GESTIÓN DE ROLES Y PERMISOS
// ==========================================

// Obtener todos los roles de una Empresa
app.get('/api/roles/:tenantId', async (req, res) => {
    try {
        const { tenantId } = req.params;
        const roles = await prisma.role.findMany({
            where: { tenantId: tenantId },
            include: { _count: { select: { users: true } } }
        });

        // Formateamos para el frontend
        const rolesMapeados = roles.map(r => ({
            id: r.id,
            nombre: r.name,
            descripcion: r.description,
            permisos: r.permissions,
            usuariosActivos: r._count.users,
            protegido: r.isSystem
        }));

        res.json(rolesMapeados);
    } catch (error) {
        res.status(500).json({ error: "Error al obtener los roles" });
    }
});

// Crear un nuevo Rol (Solo Admins)
app.post('/api/roles', async (req, res) => {
    try {
        const { nombre, permisos, tenantId } = req.body;

        const nuevoRol = await prisma.role.create({
            data: {
                name: nombre,
                permissions: permisos,
                isSystem: false, // Los creados a mano nunca son protegidos
                tenantId: tenantId
            }
        });
        res.json(nuevoRol);
    } catch (error) {
        res.status(400).json({ error: "Ya existe un rol con ese nombre en tu empresa." });
    }
});

// Editar un Rol
app.put('/api/roles/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const { nombre, permisos } = req.body;

        const rolActual = await prisma.role.findUnique({ where: { id } });

        if (!rolActual) return res.status(404).json({ error: "Rol no encontrado" });
        if (rolActual.isSystem) {
            return res.status(403).json({ error: "Seguridad: No puedes alterar los permisos de un rol del sistema." });
        }

        const rolEditado = await prisma.role.update({
            where: { id },
            data: { name: nombre, permissions: permisos }
        });

        res.json(rolEditado);
    } catch (error) {
        res.status(500).json({ error: "Error al actualizar el rol" });
    }
});

// Eliminar un Rol
app.delete('/api/roles/:id', async (req, res) => {
    try {
        const { id } = req.params;

        const rolActual = await prisma.role.findUnique({
            where: { id },
            include: { _count: { select: { users: true } } }
        });

        if (!rolActual) return res.status(404).json({ error: "Rol no encontrado" });
        if (rolActual.isSystem) return res.status(403).json({ error: "Seguridad: No puedes borrar un rol del sistema." });
        if (rolActual._count.users > 0) return res.status(400).json({ error: "No puedes borrar un rol que está siendo usado por empleados." });

        await prisma.role.delete({ where: { id } });
        res.json({ message: "Rol eliminado correctamente" });
    } catch (error) {
        res.status(500).json({ error: "Error al eliminar el rol" });
    }
});




app.listen(PORT, () => {
    console.log(`Servidor API corriendo en http://localhost:${PORT}`);
});
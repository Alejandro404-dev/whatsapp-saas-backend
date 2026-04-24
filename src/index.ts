import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import bcrypt from 'bcryptjs';
import { prisma } from './prisma';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

// ==========================================
// 1. ENDPOINT DE REGISTRO
// ==========================================
app.post('/api/auth/register', async (req, res) => {
    try {
        const { companyName, email, password } = req.body;
        const hashedPassword = await bcrypt.hash(password, 10);

        const nuevoUsuario = await prisma.$transaction(async (tx) => {
            const tenant = await tx.tenant.create({ data: { name: companyName } });
            const rolSuperAdmin = await tx.role.create({
                data: {
                    name: 'SuperAdmin',
                    description: 'Dueño absoluto del sistema',
                    permissions: ['ALL'],
                    isSystem: true,
                    tenantId: tenant.id
                }
            });

            const user = await tx.user.create({
                data: {
                    email: email,
                    password: hashedPassword,
                    tenantId: tenant.id,
                    roleId: rolSuperAdmin.id,
                    requirePasswordChange: false // El dueño no necesita cambiarla
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
                nombreEmpresa: nuevoUsuario.tenant.name,
                requirePasswordChange: nuevoUsuario.requirePasswordChange
            },
            token: "jwt-real-pendiente-de-configurar"
        });
    } catch (error) {
        console.error("Error en registro:", error);
        res.status(500).json({ error: "Hubo un problema al registrar la cuenta" });
    }
});

// ==========================================
// 2. ENDPOINT DE LOGIN
// ==========================================
app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const usuarioEncontrado = await prisma.user.findUnique({
            where: { email: email },
            include: { tenant: true, role: true }
        });

        if (!usuarioEncontrado) return res.status(401).json({ error: "El correo o contraseña está mal" });

        const isPasswordValid = await bcrypt.compare(password, usuarioEncontrado.password);
        if (!isPasswordValid) return res.status(401).json({ error: "El correo o contraseña está mal" });

        if (!usuarioEncontrado.isActive) return res.status(403).json({ error: "Tu cuenta ha sido bloqueada." });

        res.json({
            existe: true,
            usuario: {
                id: usuarioEncontrado.id,
                email: usuarioEncontrado.email,
                role: usuarioEncontrado.role.name,
                accesos: usuarioEncontrado.role.permissions || [],
                tenantId: usuarioEncontrado.tenantId,
                nombreEmpresa: usuarioEncontrado.tenant.name,
                requirePasswordChange: usuarioEncontrado.requirePasswordChange
            },
            token: "jwt-real-pendiente-de-configurar"
        });
    } catch (error) {
        console.error("Error en login:", error);
        res.status(500).json({ error: "Error interno del servidor" });
    }
});

// ==========================================
// 3. ENDPOINT: CAMBIAR CONTRASEÑA OBLIGATORIA
// ==========================================
app.patch('/api/auth/change-password', async (req, res) => {
    try {
        const { userId, newPassword } = req.body;
        if (!userId || !newPassword) return res.status(400).json({ error: "Faltan datos requeridos." });

        const hashedPassword = await bcrypt.hash(newPassword, 10);
        const usuarioActualizado = await prisma.user.update({
            where: { id: userId },
            data: { password: hashedPassword, requirePasswordChange: false },
            include: { tenant: true, role: true }
        });

        res.json({
            mensaje: "Contraseña actualizada con éxito",
            usuario: {
                id: usuarioActualizado.id,
                email: usuarioActualizado.email,
                role: usuarioActualizado.role.name,
                accesos: usuarioActualizado.role.permissions || [],
                tenantId: usuarioActualizado.tenantId,
                nombreEmpresa: usuarioActualizado.tenant.name,
                requirePasswordChange: usuarioActualizado.requirePasswordChange
            }
        });
    } catch (error) {
        res.status(500).json({ error: "No se pudo actualizar la contraseña." });
    }
});

// ==========================================
// 4. ENDPOINTS: GESTIÓN DE USUARIOS
// ==========================================

// -> ESTE ERA EL QUE SE HABÍA BORRADO <-
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
            createdAt: u.createdAt,
            isActive: u.isActive
        }));

        res.json(usuariosLimpios);
    } catch (error) {
        res.status(500).json({ error: "No se pudieron obtener los usuarios" });
    }
});

app.post('/api/users', async (req, res) => {
    try {
        const { email, password, roleName, tenantId } = req.body;
        const tenantExiste = await prisma.tenant.findUnique({ where: { id: tenantId } });
        if (!tenantExiste) return res.status(404).json({ error: "La empresa no existe" });

        const hashedPassword = await bcrypt.hash(password, 10);
        const rolAsignado = await prisma.role.upsert({
            where: { name_tenantId: { name: roleName, tenantId: tenantId } },
            update: {},
            create: { name: roleName, description: `Rol de ${roleName}`, tenantId: tenantId }
        });

        const nuevoEmpleado = await prisma.user.create({
            data: {
                email: email,
                password: hashedPassword,
                tenantId: tenantId,
                roleId: rolAsignado.id,
                requirePasswordChange: true // Obligatorio para invitados
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
        res.status(400).json({ error: "El correo ya está en uso o hubo un error." });
    }
});

app.put('/api/users/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const { email, password, roleName } = req.body;
        const usuarioActual = await prisma.user.findUnique({ where: { id } });
        if (!usuarioActual) return res.status(404).json({ error: "Usuario no encontrado" });

        const rolAsignado = await prisma.role.upsert({
            where: { name_tenantId: { name: roleName, tenantId: usuarioActual.tenantId } },
            update: {},
            create: { name: roleName, description: `Rol de ${roleName}`, tenantId: usuarioActual.tenantId }
        });

        const datosActualizados: any = { email: email, roleId: rolAsignado.id };
        if (password && password.trim() !== "") {
            datosActualizados.password = await bcrypt.hash(password, 10);
        }

        const usuarioEditado = await prisma.user.update({
            where: { id: id },
            data: datosActualizados,
            include: { role: true }
        });

        res.json({
            id: usuarioEditado.id,
            email: usuarioEditado.email,
            role: usuarioEditado.role.name,
            accesos: usuarioEditado.role.permissions,
            isActive: usuarioEditado.isActive,
            createdAt: usuarioEditado.createdAt
        });
    } catch (error) {
        res.status(500).json({ error: "No se pudo actualizar el usuario." });
    }
});

app.patch('/api/users/:id/toggle-status', async (req, res) => {
    try {
        const { id } = req.params;
        const usuario = await prisma.user.findUnique({ where: { id } });
        if (!usuario) return res.status(404).json({ error: "Usuario no encontrado" });

        const usuarioActualizado = await prisma.user.update({
            where: { id },
            data: { isActive: !usuario.isActive }
        });

        res.json({ id: usuarioActualizado.id, isActive: usuarioActualizado.isActive });
    } catch (error) {
        res.status(500).json({ error: "No se pudo cambiar el estado del usuario" });
    }
});

app.delete('/api/users/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const usuarioExiste = await prisma.user.findUnique({ where: { id } });
        if (!usuarioExiste) return res.status(404).json({ error: "El usuario no existe." });

        await prisma.user.delete({ where: { id: id } });
        res.json({ message: "Usuario eliminado correctamente" });
    } catch (error) {
        res.status(500).json({ error: "No se pudo eliminar el usuario." });
    }
});

// ==========================================
// 5. ENDPOINTS: GESTIÓN DE ROLES
// ==========================================
app.get('/api/roles/:tenantId', async (req, res) => {
    try {
        const { tenantId } = req.params;
        const roles = await prisma.role.findMany({
            where: { tenantId: tenantId },
            include: { _count: { select: { users: true } } }
        });

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

app.post('/api/roles', async (req, res) => {
    try {
        const { nombre, permisos, tenantId } = req.body;
        const nuevoRol = await prisma.role.create({
            data: { name: nombre, permissions: permisos, isSystem: false, tenantId: tenantId }
        });
        res.json(nuevoRol);
    } catch (error) {
        res.status(400).json({ error: "Ya existe un rol con ese nombre." });
    }
});

app.put('/api/roles/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const { nombre, permisos } = req.body;
        const rolActual = await prisma.role.findUnique({ where: { id } });

        if (!rolActual) return res.status(404).json({ error: "Rol no encontrado" });
        if (rolActual.isSystem) return res.status(403).json({ error: "No puedes alterar un rol del sistema." });

        const rolEditado = await prisma.role.update({
            where: { id },
            data: { name: nombre, permissions: permisos }
        });
        res.json(rolEditado);
    } catch (error) {
        res.status(500).json({ error: "Error al actualizar el rol" });
    }
});

app.delete('/api/roles/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const rolActual = await prisma.role.findUnique({
            where: { id },
            include: { _count: { select: { users: true } } }
        });

        if (!rolActual) return res.status(404).json({ error: "Rol no encontrado" });
        if (rolActual.isSystem) return res.status(403).json({ error: "No puedes borrar un rol del sistema." });
        if (rolActual._count.users > 0) return res.status(400).json({ error: "No puedes borrar un rol en uso." });

        await prisma.role.delete({ where: { id } });
        res.json({ message: "Rol eliminado correctamente" });
    } catch (error) {
        res.status(500).json({ error: "Error al eliminar el rol" });
    }
});

app.listen(PORT, () => {
    console.log(`Servidor API corriendo en http://localhost:${PORT}`);
});
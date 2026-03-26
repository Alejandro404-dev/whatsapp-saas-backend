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
// ENDPOINT DE REGISTRO REAL (CON ENCRIPTACIÓN)
// ==========================================
app.post('/api/auth/register', async (req, res) => {
    try {
        const { companyName, email, password } = req.body;

        // 2. Encriptamos la contraseña antes de guardarla
        // El "10" es el nivel de seguridad (saltos). Es el estándar de la industria.
        const hashedPassword = await bcrypt.hash(password, 10);

        const nuevoUsuario = await prisma.user.create({
            data: {
                email: email,
                password: hashedPassword, 
                tenant: {
                    create: { name: companyName } 
                },
                role: {
                    connectOrCreate: { 
                        where: { name: 'Admin' },
                        create: { name: 'Admin', description: 'Dueño del sistema' }
                    }
                }
            },
            include: {
                tenant: true,
                role: true
            }
        });

        res.json({
            existe: true,
            usuario: {
                id: nuevoUsuario.id,
                email: nuevoUsuario.email,
                rol: nuevoUsuario.role.name,
                tenantId: nuevoUsuario.tenantId,
                nombreEmpresa: nuevoUsuario.tenant.name
            },
            token: "jwt-real-pendiente-de-configurar" 
        });

    } catch (error) {
        console.error("Error en registro:", error);
        res.status(500).json({ error: "Hubo un problema al registrar la cuenta en la base de datos" });
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
                rol: usuarioEncontrado.role.name,
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
            include: { role: true } // Traemos el nombre del rol también
        });

        // Limpiamos los datos sensibles antes de enviarlos al front
        const usuariosLimpios = usuarios.map(u => ({
            id: u.id,
            email: u.email,
            role: u.role.name,
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

        // 1. Validamos que el tenant exista por seguridad
        const tenantExiste = await prisma.tenant.findUnique({ where: { id: tenantId } });
        if (!tenantExiste) {
            return res.status(404).json({ error: "La empresa no existe" });
        }

        // 2. Encriptamos la contraseña del nuevo empleado
        const hashedPassword = await bcrypt.hash(password, 10);

        // 3. Creamos al usuario amarrado a la Empresa y buscando o creando su Rol
        const nuevoEmpleado = await prisma.user.create({
            data: {
                email: email,
                password: hashedPassword,
                tenant: { connect: { id: tenantId } }, // Lo conectamos a la empresa actual
                role: {
                    connectOrCreate: {
                        where: { name: roleName },
                        create: { name: roleName, description: `Rol de ${roleName}` }
                    }
                }
            },
            include: { role: true }
        });

        // 4. Devolvemos el usuario sin la contraseña por seguridad
        res.json({
            id: nuevoEmpleado.id,
            email: nuevoEmpleado.email,
            role: nuevoEmpleado.role.name,
            createdAt: nuevoEmpleado.createdAt
        });

    } catch (error) {
        console.error("Error al crear empleado:", error);
        // Si Prisma lanza error porque el correo ya existe (Unique constraint)
        res.status(400).json({ error: "El correo ya está en uso o hubo un error en los datos." });
    }
});

// ==========================================
// ENDPOINT: ELIMINAR USUARIO
// ==========================================
app.delete('/api/users/:id', async (req, res) => {
    try {
        const { id } = req.params;

        // Le decimos a Prisma que borre la fila que coincida con ese ID
        await prisma.user.delete({
            where: { id: id }
        });

        res.json({ message: "Usuario eliminado correctamente" });
    } catch (error) {
        console.error("Error al eliminar:", error);
        res.status(500).json({ error: "No se pudo eliminar el usuario" });
    }
});

// ==========================================
// ENDPOINT: EDITAR USUARIO (La 'U' del CRUD)
// ==========================================
app.put('/api/users/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const { email, password, roleName } = req.body;

        // 1. Preparamos los datos básicos a actualizar
        const datosActualizados: any = {
            email: email,
            role: {
                connectOrCreate: {
                    where: { name: roleName },
                    create: { name: roleName, description: `Rol de ${roleName}` }
                }
            }
        };

        // 2. Solo encriptamos y cambiamos la contraseña si el administrador escribió una nueva
        if (password && password.trim() !== "") {
            datosActualizados.password = await bcrypt.hash(password, 10);
        }

        // 3. Ejecutamos la actualización en PostgreSQL
        const usuarioEditado = await prisma.user.update({
            where: { id: id },
            data: datosActualizados,
            include: { role: true }
        });

        // 4. Devolvemos los datos frescos a React
        res.json({
            id: usuarioEditado.id,
            email: usuarioEditado.email,
            role: usuarioEditado.role.name,
            createdAt: usuarioEditado.createdAt
        });

    } catch (error) {
        console.error("Error al editar:", error);
        res.status(500).json({ error: "No se pudo actualizar el usuario." });
    }
});




app.listen(PORT, () => {
    console.log(`Servidor API corriendo en http://localhost:${PORT}`);
});
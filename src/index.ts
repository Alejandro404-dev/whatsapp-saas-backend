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
                password: hashedPassword, // <-- Guardamos la versión encriptada, NUNCA la original
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

app.listen(PORT, () => {
    console.log(`Servidor API corriendo en http://localhost:${PORT}`);
});
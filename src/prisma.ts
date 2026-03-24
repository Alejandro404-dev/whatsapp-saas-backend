import { PrismaClient } from '@prisma/client';

// Exportamos una única instancia para todo el proyecto
export const prisma = new PrismaClient();
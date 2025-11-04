// ============== SERVIDOR BACKEND VINTEX CLINIC (v3.1 - ENDPOINT UNIFICADO) =============
//
// ARQUITECTURA:
// - FASE A: Modular (Compatible con frontend modular)
// - FASE B: Endpoint /api/citas unificado (maneja 'all' y 'range')
// - FASE C: Storage (4 endpoints) y Real-time (hooks)
// - ESQUEMA: Validado para IDs BIGINT/SERIAL (z.number())
// - FIX 2: Usa la Clave de Servicio (SERVICE_KEY) para bypassear RLS
// - FIX 3: Corregido el nombre de columna 'fecha_cita' a 'fecha_hora'
// - FIX 4: Añadidos logs de diagnóstico para variables de entorno
//
// =======================================================================================

// 1. IMPORTACIÓN DE MÓDULOS
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { createClient } = require('@supabase/supabase-js');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { z } = require('zod');
const rateLimit = require('express-rate-limit');

// 2. CONFIGURACIÓN INICIAL Y DIAGNÓSTICO
const app = express();
app.set('trust proxy', 1); 
const port = process.env.PORT || 80; 

console.log("--- INICIANDO SERVIDOR VINTEX (v3.1) ---");

// Diagnóstico de variables de entorno
if (!process.env.SUPABASE_URL || !process.env.SUPABASE_SERVICE_KEY) {
    console.error("ERROR CRÍTICO: SUPABASE_URL o SUPABASE_SERVICE_KEY no están definidas.");
    console.log("Asegúrate de que el archivo .env esté presente y configurado.");
} else {
    console.log("✅ Variables de entorno cargadas (URL existe).");
}
if (!process.env.JWT_SECRET) console.warn("ADVERTENCIA: JWT_SECRET no definida. Usando valor inseguro.");

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_KEY = process.env.SUPABASE_SERVICE_KEY; // Clave de SERVICIO
const JWT_SECRET = process.env.JWT_SECRET || 'tu_secreto_jwt_inseguro_por_defecto';

// 3. INICIALIZACIÓN DE SUPABASE (CON CLAVE DE SERVICIO)
const supabase = createClient(SUPABASE_URL, SUPABASE_KEY);
console.log("✅ Cliente de Supabase (Service Role) inicializado.");

// 4. MIDDLEWARES GENERALES
app.use(cors());
app.use(express.json());

// 5. MIDDLEWARE DE SEGURIDAD (Rate Limiting)
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutos
    max: 10, // Límite de 10 intentos por IP
    message: 'Demasiados intentos de inicio de sesión. Intente de nuevo en 15 minutos.',
    standardHeaders: true, 
    legacyHeaders: false, 
});

const apiLimiter = rateLimit({
    windowMs: 1 * 60 * 1000, // 1 minuto
    max: 100, // Límite de 100 peticiones por minuto por IP
    message: 'Demasiadas peticiones a la API. Intente más tarde.',
    standardHeaders: true,
    legacyHeaders: false,
});

app.use('/api/', apiLimiter); // Aplicar a todas las rutas de la API
console.log("✅ Middlewares (CORS, JSON, Rate Limit) configurados.");

// 6. MIDDLEWARE DE AUTENTICACIÓN (JWT)
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // "Bearer TOKEN"

    if (token == null) {
        return res.status(401).json({ error: 'Acceso denegado: No se proporcionó token.' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            console.warn(`Token JWT inválido: ${err.message}`);
            // Manejo de errores específicos
            if (err.name === 'TokenExpiredError') {
                return res.status(401).json({ error: 'Token expirado.', code: 'TOKEN_EXPIRED' });
            }
            return res.status(403).json({ error: 'Token inválido.' });
        }
        req.user = user;
        next();
    });
}

// 7. ESQUEMAS DE VALIDACIÓN (ZOD)
const idSchema = z.number().int().positive();
const loginSchema = z.object({
    email: z.string().email(),
    password: z.string().min(6),
}).strict();

// <-- CAMBIO CLAVE: Esquema para validar el rango (si se provee) -->
const citasRangeSchema = z.object({
    start: z.string().datetime(), // ISO 8601
    end: z.string().datetime(),   // ISO 8601
}).strict();

const citaBaseSchema = z.object({
    doctor_id: idSchema,
    fecha_hora: z.string().datetime(),
    timezone: z.string(),
    descripcion: z.string().optional(),
    duracion_minutos: z.number().int().positive(),
    estado: z.enum(['programada', 'confirmada', 'cancelada', 'completada', 'no_asistio']),
});

const nuevaCitaSchema = citaBaseSchema.extend({
    cliente_id: idSchema.optional(),
    new_client_name: z.string().optional(),
    new_client_dni: z.string().optional(),
    new_client_telefono: z.string().optional(),
}).strict();

const updateCitaSchema = citaBaseSchema.partial(); // Todos los campos son opcionales

const clienteSchema = z.object({
    activo: z.boolean().optional(),
    solicitud_de_secretaría: z.boolean().optional(),
}).partial().strict(); // Solo permite actualizar estos campos

const doctorSchema = z.object({
    nombre: z.string().min(3).optional(),
    especialidad: z.string().optional().nullable(),
    activo: z.boolean().optional(),
    horario_inicio: z.string().regex(/^\d{2}:\d{2}(:\d{2})?$/).optional().nullable(), // Formato HH:MM o HH:MM:SS
    horario_fin: z.string().regex(/^\d{2}:\d{2}(:\d{2})?$/).optional().nullable(),
}).strict();

const updateDoctorSchema = doctorSchema.partial(); // Todos opcionales


// =======================================================================================
// 8. ENDPOINTS DE LA API
// =======================================================================================

// --- HEALTH CHECK (Para EasyPanel) ---
app.get('/', (req, res) => {
    res.status(200).send('Vintex Clinic Backend (v3.1) [Endpoint Unificado] - ¡Operativo!');
});

// --- AUTENTICACIÓN ---
app.post('/api/login', loginLimiter, async (req, res) => {
    console.log("-> Recibida petición en /api/login");
    try {
        const { email, password } = loginSchema.parse(req.body);

        const { data: user, error } = await supabase
            .from('usuarios')
            .select('id, email, password_hash, rol')
            .eq('email', email)
            .single();

        if (error || !user) {
            return res.status(401).json({ error: 'Credenciales inválidas.' });
        }

        const isValid = await bcrypt.compare(password, user.password_hash);
        if (!isValid) {
            return res.status(401).json({ error: 'Credenciales inválidas.' });
        }

        const token = jwt.sign(
            { id: user.id, email: user.email, rol: user.rol },
            JWT_SECRET,
            { expiresIn: '8h' } // Duración del token
        );

        console.log(`✅ Login exitoso para ${user.email}`);
        res.status(200).json({ token, user: { id: user.id, email: user.email, rol: user.rol } });

    } catch (error) {
        if (error instanceof z.ZodError) return res.status(400).json({ error: 'Datos de login inválidos', details: error.errors });
        console.error("Error en login:", error.message);
        res.status(500).json({ error: 'Error interno del servidor.', details: error.message });
    }
});

// --- DATOS INICIALES (Carga la App) ---
app.get('/api/initial-data', authenticateToken, async (req, res) => {
    console.log("-> Recibida petición en /api/initial-data");
    try {
        const [doctores, clientes, chatHistory] = await Promise.all([
            supabase.from('doctores').select('*').order('nombre', { ascending: true }),
            supabase.from('clientes').select('*').order('nombre', { ascending: true }),
            supabase.from('n8n_chat_histories').select('*').order('id', { ascending: false }).limit(500)
        ]);

        if (doctores.error) throw doctores.error;
        if (clientes.error) throw clientes.error;
        if (chatHistory.error) throw chatHistory.error;

        console.log(`✅ /api/initial-data: Doctores: ${doctores.data.length}, Clientes: ${clientes.data.length}, Chat: ${chatHistory.data.length}`);
        res.status(200).json({
            doctors: doctores.data,
            clients: clientes.data,
            chatHistory: chatHistory.data
        });
    } catch (error) {
        console.error("Error al obtener datos iniciales:", error.message);
        res.status(500).json({ error: 'No se pudieron cargar los datos iniciales.', details: error.message });
    }
});

// =======================================================================================
// --- GESTIÓN DE CITAS (CRUD) ---
// =======================================================================================

// <-- CAMBIO CLAVE: Endpoint GET /api/citas UNIFICADO -->
// Si se proveen 'start' y 'end' en la query, filtra por rango.
// Si no, devuelve todas las citas.
app.get('/api/citas', authenticateToken, async (req, res) => {
    const { start, end } = req.query;

    try {
        // Construcción base de la consulta
        let query = supabase
            .from('citas')
            .select(`
                id, fecha_hora, descripcion, estado, duracion_minutos, timezone,
                cliente:clientes (id, nombre, dni),
                doctor:doctores (id, nombre, especialidad, activo, horario_inicio, horario_fin)
            `)
            .order('fecha_hora', { ascending: true });

        // CAMBIO CLAVE: Si 'start' y 'end' están presentes, aplicamos el filtro de rango
        if (start && end) {
            // Validamos los parámetros de la query
            const validatedQuery = citasRangeSchema.parse({ start, end });
            
            console.log(`-> /api/citas (RANGO): ${validatedQuery.start} a ${validatedQuery.end}`);
            
            // Aplicamos los filtros a la consulta de Supabase
            query = query.gte('fecha_hora', validatedQuery.start)
                         .lte('fecha_hora', validatedQuery.end);
        } else {
            console.log("-> /api/citas (TODAS)");
        }

        // Ejecutamos la consulta (con o sin filtros)
        const { data, error } = await query;

        if (error) throw error;
        
        console.log(`✅ /api/citas: Citas encontradas: ${data.length}`);
        res.status(200).json(data);

    } catch (error) {
        if (error instanceof z.ZodError) {
            return res.status(400).json({ error: 'Parámetros de rango (start/end) inválidos', details: error.errors });
        }
        console.error("Error al obtener citas:", error.message);
        res.status(500).json({ error: 'No se pudieron obtener las citas.', details: error.message });
    }
});

// <-- AVISO: El endpoint /api/citas-range ya no es necesario y ha sido eliminado -->

// POST (Crear nueva cita)
app.post('/api/citas', authenticateToken, async (req, res) => {
    console.log("-> Recibida petición en POST /api/citas");
    try {
        const citaData = nuevaCitaSchema.parse(req.body);
        let clienteId = citaData.cliente_id;

        // Lógica para crear nuevo cliente si es necesario
        if (citaData.new_client_name && citaData.new_client_dni) {
            console.log("Creando nuevo cliente...");
            const { data: newClient, error: clientError } = await supabase
                .from('clientes')
                .insert({
                    nombre: citaData.new_client_name,
                    dni: citaData.new_client_dni,
                    telefono: citaData.new_client_telefono || null,
                    activo: true, // Bot activado por defecto
                    solicitud_de_secretaría: false
                })
                .select('id')
                .single();
            
            if (clientError) throw clientError;
            clienteId = newClient.id;
        } else if (!clienteId) {
            return res.status(400).json({ error: 'Debe proporcionar un cliente_id o datos de nuevo cliente.' });
        }

        // Crear la cita
        const { data: nuevaCita, error: citaError } = await supabase
            .from('citas')
            .insert({
                cliente_id: clienteId,
                doctor_id: citaData.doctor_id,
                fecha_hora: citaData.fecha_hora,
                timezone: citaData.timezone,
                descripcion: citaData.descripcion,
                duracion_minutos: citaData.duracion_minutos,
                estado: citaData.estado
            })
            .select(`
                id, fecha_hora, descripcion, estado, duracion_minutos, timezone,
                cliente:clientes (id, nombre, dni),
                doctor:doctores (id, nombre, especialidad, activo, horario_inicio, horario_fin)
            `)
            .single();

        if (citaError) throw citaError;

        console.log(`✅ Nueva cita creada con ID: ${nuevaCita.id}`);
        res.status(201).json(nuevaCita);

    } catch (error) {
        if (error instanceof z.ZodError) return res.status(400).json({ error: 'Datos de cita inválidos', details: error.errors });
        if (error.code === '23505') return res.status(409).json({ error: 'Conflicto: Ya existe un cliente con ese DNI.', details: error.message });
        console.error("Error al crear la cita:", error.message);
        res.status(500).json({ error: 'No se pudo crear la cita.', details: error.message });
    }
});

// PATCH (Actualizar cita)
app.patch('/api/citas/:id', authenticateToken, async (req, res) => {
    const { id } = req.params;
    console.log(`-> Recibida petición en PATCH /api/citas/${id}`);
    try {
        const validatedId = idSchema.parse(Number(id));
        const dataToUpdate = updateCitaSchema.parse(req.body);

        const { data, error } = await supabase
            .from('citas')
            .update(dataToUpdate)
            .eq('id', validatedId)
            .select(`
                id, fecha_hora, descripcion, estado, duracion_minutos, timezone,
                cliente:clientes (id, nombre, dni),
                doctor:doctores (id, nombre, especialidad, activo, horario_inicio, horario_fin)
            `)
            .single();
            
        if (error) throw error;
        if (!data) return res.status(404).json({ error: 'Cita no encontrada.' });
        
        console.log(`✅ Cita ${id} actualizada.`);
        res.status(200).json(data);
    } catch (error) {
        if (error instanceof z.ZodError) return res.status(400).json({ error: 'Datos de actualización inválidos', details: error.errors });
        console.error("Error al actualizar la cita:", error.message);
        res.status(500).json({ error: 'No se pudo actualizar la cita.', details: error.message });
    }
});

// DELETE (Eliminar cita)
app.delete('/api/citas/:id', authenticateToken, async (req, res) => {
    const { id } = req.params;
    console.log(`-> Recibida petición en DELETE /api/citas/${id}`);
    try {
        const validatedId = idSchema.parse(Number(id));
        const { error } = await supabase.from('citas').delete().eq('id', validatedId);
        if (error) throw error;
        
        console.log(`✅ Cita ${id} eliminada.`);
        res.status(204).send();
    } catch (error) {
        if (error instanceof z.ZodError) return res.status(400).json({ error: 'ID de cita inválido', details: error.errors });
        console.error("Error al eliminar la cita:", error.message);
        res.status(500).json({ error: 'No se pudo eliminar la cita.', details: error.message });
    }
});

// =======================================================================================
// --- GESTIÓN DE CLIENTES Y DOCTORES ---
// =======================================================================================

// PATCH (Actualizar Cliente - Bot/Secretaría)
app.patch('/api/clientes/:id', authenticateToken, async (req, res) => {
    const { id } = req.params;
    console.log(`-> Recibida petición en PATCH /api/clientes/${id}`);
    try {
        const validatedId = idSchema.parse(Number(id));
        const dataToUpdate = clienteSchema.parse(req.body);

        const { data, error } = await supabase
            .from('clientes')
            .update(dataToUpdate)
            .eq('id', validatedId)
            .select()
            .single();
        
        if (error) throw error;
        if (!data) return res.status(404).json({ error: 'Cliente no encontrado.' });
        
        console.log(`✅ Cliente ${id} actualizado.`);
        res.status(200).json(data);
    } catch (error) {
        if (error instanceof z.ZodError) return res.status(400).json({ error: 'Datos de actualización inválidos', details: error.errors });
        console.error("Error al actualizar cliente:", error.message);
        res.status(500).json({ error: 'No se pudo actualizar el cliente.', details: error.message });
    }
});

// POST (Crear Doctor)
app.post('/api/doctores', authenticateToken, async (req, res) => {
    console.log("-> Recibida petición en POST /api/doctores");
    try {
        const dataToInsert = doctorSchema.parse(req.body);
        
        const { data, error } = await supabase
            .from('doctores')
            .insert(dataToInsert)
            .select()
            .single();

        if (error) throw error;
        
        console.log(`✅ Doctor creado con ID: ${data.id}`);
        res.status(201).json(data);
    } catch (error) {
        if (error instanceof z.ZodError) return res.status(400).json({ error: 'Datos de doctor inválidos', details: error.errors });
        console.error("Error al crear doctor:", error.message);
        res.status(500).json({ error: 'No se pudo crear el doctor.', details: error.message });
    }
});

// PATCH (Actualizar Doctor)
app.patch('/api/doctores/:id', authenticateToken, async (req, res) => {
    const { id } = req.params;
    console.log(`-> Recibida petición en PATCH /api/doctores/${id}`);
    try {
        const validatedId = idSchema.parse(Number(id));
        const dataToUpdate = updateDoctorSchema.parse(req.body);

        const { data, error } = await supabase
            .from('doctores')
            .update(dataToUpdate)
            .eq('id', validatedId)
            .select()
            .single();

        if (error) throw error;
        if (!data) return res.status(404).json({ error: 'Doctor no encontrado.' });
        
        console.log(`✅ Doctor ${id} actualizado.`);
        res.status(200).json(data);
    } catch (error) {
        if (error instanceof z.ZodError) return res.status(400).json({ error: 'Datos de actualización inválidos', details: error.errors });
        console.error("Error al actualizar doctor:", error.message);
        res.status(500).json({ error: 'No se pudo actualizar el doctor.', details: error.message });
    }
});

// =======================================================================================
// --- FASE C: ENDPOINTS DE STORAGE (A implementar) ---
// =======================================================================================
// POST /api/files/generate-upload-url
// POST /api/files/confirm-upload
// GET /api/files/:clienteId
// POST /api/files/generate-download-url


// =======================================================================================
// 9. INICIO DEL SERVIDOR
// =======================================================================================
app.listen(port, () => {
    console.log(`\n🚀 Servidor Vintex Clinic v3.1 escuchando en http://localhost:${port}`);
});
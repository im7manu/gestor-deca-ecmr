const express = require('express');
const PDFDocument = require('pdfkit');
const QR = require('qrcode');
const { DatabaseSync } = require('node:sqlite');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const PORT = Number(process.env.PORT || 9000);
const BASE = (process.env.BASE_URL || `http://localhost:${PORT}`).replace(/\/$/, '');
const DATA = path.join(__dirname, 'data');
fs.mkdirSync(DATA, { recursive: true });
fs.mkdirSync(path.join(DATA, 'pdf'), { recursive: true });

const db = new DatabaseSync(path.join(DATA, 'app.db'));

// Esquema de base de datos con tablas relacionales y tabla de auditoría de seguridad
db.exec(`
CREATE TABLE IF NOT EXISTS clientes(
  id INTEGER PRIMARY KEY, nombre TEXT, nif TEXT, direccion TEXT, cp TEXT, ciudad TEXT, email TEXT, tel TEXT
);
CREATE TABLE IF NOT EXISTS ajustes(id INTEGER PRIMARY KEY CHECK(id=1), datos TEXT);
CREATE TABLE IF NOT EXISTS docs(
  id INTEGER PRIMARY KEY, tipo TEXT, token TEXT UNIQUE, creado TEXT, datos TEXT, usuario TEXT, modificado TEXT, estado TEXT DEFAULT 'emitido'
);
CREATE TABLE IF NOT EXISTS usuarios(
  id INTEGER PRIMARY KEY,
  usuario TEXT UNIQUE COLLATE NOCASE,
  nombre TEXT NOT NULL,
  email TEXT DEFAULT '',
  hash TEXT NOT NULL,
  rol TEXT NOT NULL DEFAULT 'usuario',
  permisos TEXT NOT NULL DEFAULT '[]',
  activo INTEGER DEFAULT 1,
  creado_en TEXT,
  ultimo_login TEXT,
  ultimo_login_ip TEXT,
  intentos_fallidos INTEGER DEFAULT 0,
  bloqueado_hasta INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS sesiones(
  sid TEXT PRIMARY KEY,
  uid INTEGER NOT NULL,
  expira INTEGER NOT NULL,
  ip TEXT DEFAULT '',
  creado INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS empresas(
  id INTEGER PRIMARY KEY, nombre TEXT NOT NULL, nif TEXT NOT NULL UNIQUE, direccion TEXT DEFAULT '', cp TEXT DEFAULT '', ciudad TEXT DEFAULT '', email TEXT DEFAULT '', tel TEXT DEFAULT '', tipo TEXT DEFAULT 'Cliente', cliente_id INTEGER
);
CREATE TABLE IF NOT EXISTS vehiculos(
  id INTEGER PRIMARY KEY, matricula TEXT NOT NULL UNIQUE, tipo TEXT NOT NULL, modelo TEXT DEFAULT '', estado TEXT DEFAULT 'Disponible', itv TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS conductores(
  id INTEGER PRIMARY KEY, nombre TEXT NOT NULL, dni TEXT NOT NULL UNIQUE, telefono TEXT DEFAULT '', email TEXT DEFAULT '', activo INTEGER DEFAULT 1
);
CREATE TABLE IF NOT EXISTS mercancias(
  id INTEGER PRIMARY KEY, nombre TEXT NOT NULL UNIQUE, codigo TEXT DEFAULT '', unidad TEXT DEFAULT 'kg'
);
CREATE TABLE IF NOT EXISTS ubicaciones(
  id INTEGER PRIMARY KEY, nombre TEXT NOT NULL UNIQUE, tipo TEXT DEFAULT 'Punto de carga', direccion TEXT DEFAULT '', cp TEXT DEFAULT '', ciudad TEXT DEFAULT '', provincia TEXT DEFAULT '', empresa TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS audit_logs(
  id INTEGER PRIMARY KEY,
  fecha TEXT NOT NULL,
  usuario TEXT,
  ip TEXT,
  accion TEXT NOT NULL,
  detalle TEXT,
  severidad TEXT DEFAULT 'info'
);
`);

// Migraciones de versiones anteriores
for (const sql of [
  'ALTER TABLE docs ADD COLUMN usuario TEXT',
  'ALTER TABLE docs ADD COLUMN modificado TEXT',
  "ALTER TABLE docs ADD COLUMN estado TEXT DEFAULT 'emitido'",
  'ALTER TABLE usuarios ADD COLUMN email TEXT DEFAULT ""',
  'ALTER TABLE usuarios ADD COLUMN creado_en TEXT',
  'ALTER TABLE usuarios ADD COLUMN ultimo_login TEXT',
  'ALTER TABLE usuarios ADD COLUMN ultimo_login_ip TEXT',
  'ALTER TABLE usuarios ADD COLUMN intentos_fallidos INTEGER DEFAULT 0',
  'ALTER TABLE usuarios ADD COLUMN bloqueado_hasta INTEGER DEFAULT 0',
  'ALTER TABLE sesiones ADD COLUMN ip TEXT DEFAULT ""',
  'ALTER TABLE sesiones ADD COLUMN creado INTEGER DEFAULT 0',
]) { try { db.exec(sql); } catch {} }

// Semilla para directorio de empresas si proviene de versión previa con clientes
const seed = () => {
  if (!db.prepare('SELECT 1 FROM empresas LIMIT 1').get()) {
    const legacy = db.prepare('SELECT * FROM clientes ORDER BY nombre').all();
    const insert = db.prepare('INSERT OR IGNORE INTO empresas(nombre,nif,direccion,cp,ciudad,email,tel,tipo,cliente_id) VALUES(?,?,?,?,?,?,?,?,?)');
    for (const c of legacy) insert.run(c.nombre, c.nif, c.direccion || '', c.cp || '', c.ciudad || '', c.email || '', c.tel || '', 'Cliente', c.id);
  }
};
seed();

// Catálogo de permisos
const PERMISOS = {
  deca_ver: 'Ver DeCA',
  deca_crear: 'Crear DeCA (incluye ver)',
  ecmr_ver: 'Ver eCMR',
  ecmr_crear: 'Crear eCMR (incluye ver)',
  clientes: 'Gestionar clientes',
  empresa: 'Editar datos del transportista / Mi entidad',
  empresas: 'Gestionar empresas',
  transporte: 'Gestionar medios de transporte',
  mercancias: 'Gestionar mercancías',
  ubicaciones: 'Gestionar ubicaciones frecuentes',
};

// ----------------------------------------------------
// SEGURIDAD CRIPTOGRÁFICA Y REGISTRO DE AUDITORÍA
// ----------------------------------------------------
const SCRYPT_OPTS = { N: 16384, r: 8, p: 1, maxmem: 64 * 1024 * 1024 };

const hash = (pw, salt = crypto.randomBytes(32).toString('hex')) =>
  salt + ':' + crypto.scryptSync(pw, salt, 64, SCRYPT_OPTS).toString('hex');

const okPw = (pw, h) => {
  const [salt, stored] = String(h || '').split(':');
  if (!salt || !stored) return false;
  try {
    const keyLen = Buffer.from(stored, 'hex').length;
    const derived = crypto.scryptSync(pw, salt, keyLen || 64, keyLen === 32 ? undefined : SCRYPT_OPTS);
    const expected = Buffer.from(stored, 'hex');
    return derived.length === expected.length && crypto.timingSafeEqual(derived, expected);
  } catch {
    return false;
  }
};

// Hash ficticio para comparación constante en intentos con usuarios inexistentes (defensa contra timing attack)
const DUMMY_SALT = crypto.randomBytes(32).toString('hex');
const DUMMY_HASH = DUMMY_SALT + ':' + crypto.scryptSync('DummyDefPasswordTiming123!', DUMMY_SALT, 64, SCRYPT_OPTS).toString('hex');
const dummyVerify = pw => { try { okPw(pw, DUMMY_HASH); } catch {} };

// Política estricta de contraseñas
function validatePassword(pw) {
  if (typeof pw !== 'string' || pw.length < 10) {
    return 'La contraseña debe tener al menos 10 caracteres.';
  }
  if (!/[A-Z]/.test(pw)) {
    return 'La contraseña debe contener al menos una letra mayúscula (A-Z).';
  }
  if (!/[a-z]/.test(pw)) {
    return 'La contraseña debe contener al menos una letra minúscula (a-z).';
  }
  if (!/[0-9]/.test(pw)) {
    return 'La contraseña debe contener al menos un número (0-9).';
  }
  if (!/[^A-Za-z0-9]/.test(pw)) {
    return 'La contraseña debe contener al menos un símbolo especial (!@#$%^&*...).';
  }
  return null;
}

// Registro de eventos de seguridad
function logAudit(usuario, ip, accion, detalle, severidad = 'info') {
  try {
    db.prepare('INSERT INTO audit_logs(fecha, usuario, ip, accion, detalle, severidad) VALUES(?,?,?,?,?,?)')
      .run(new Date().toISOString(), usuario || 'anónimo', ip || '', accion, detalle || '', severidad);
  } catch (err) {
    console.error('Error al registrar log de auditoría:', err);
  }
}

// Rate limiting en memoria por dirección IP
const ipAttempts = new Map();
function checkIpRateLimit(ip, maxAttempts = 10, windowMs = 15 * 60 * 1000, blockDurationMs = 15 * 60 * 1000) {
  const now = Date.now();
  let record = ipAttempts.get(ip);
  if (!record || (now - record.lastTime > windowMs && now > record.blockedUntil)) {
    record = { count: 0, lastTime: now, blockedUntil: 0 };
    ipAttempts.set(ip, record);
  }
  if (record.blockedUntil > now) {
    const waitSec = Math.ceil((record.blockedUntil - now) / 1000);
    return `Demasiados intentos desde esta dirección IP. Acceso bloqueado durante ${waitSec} segundos.`;
  }
  return null;
}
function recordIpFailure(ip, maxAttempts = 10, blockDurationMs = 15 * 60 * 1000) {
  const now = Date.now();
  let record = ipAttempts.get(ip) || { count: 0, lastTime: now, blockedUntil: 0 };
  record.count++;
  record.lastTime = now;
  if (record.count >= maxAttempts) {
    record.blockedUntil = now + blockDurationMs;
  }
  ipAttempts.set(ip, record);
}
function resetIpAttempts(ip) {
  ipAttempts.delete(ip);
}
setInterval(() => {
  const now = Date.now();
  for (const [ip, rec] of ipAttempts.entries()) {
    if (now - rec.lastTime > 3600000 && now > rec.blockedUntil) {
      ipAttempts.delete(ip);
    }
  }
}, 3600000).unref();

function isSetupNeeded() {
  const row = db.prepare('SELECT count(*) as c FROM usuarios').get();
  return Number(row?.c || 0) === 0;
}

// ----------------------------------------------------
// CAMPOS Y MODELO DOCUMENTAL
// ----------------------------------------------------
const EMPRESA = [
  ['nombre', 'Razón social (transportista efectivo)'], ['nif', 'NIF'], ['domicilio', 'Domicilio'],
  ['cp', 'Código postal'], ['ciudad', 'Municipio'], ['provincia', 'Provincia'], ['telefono', 'Teléfono'],
  ['email', 'Correo electrónico'], ['web', 'Web'], ['codigo_nima', 'Código NIMA'],
  ['aut_tipo', 'Tipo de autorización (p. ej. MDPE)'], ['aut_num', 'Nº de autorización'],
];
const CAMPOS = {
  deca: [
    ['cliente', 'Cargador contractual', 'cliente'], ['destinatario', 'Destinatario'],
    ['matricula', 'Matrícula del vehículo'], ['remolque', 'Matrícula del remolque'],
    ['conductor', 'Conductor (nombre y NIF)'], ['origen', 'Lugar de carga'],
    ['f_carga', 'Fecha de realización del transporte', 'date'], ['destino', 'Lugar de descarga'],
    ['mercancia', 'Naturaleza de la mercancía'], ['peso', 'Peso (kg)', 'number'],
    ['autorizacion', 'Autorización especial de circulación (si procede)'], ['obs', 'Observaciones'],
  ],
  ecmr: [
    ['cliente', 'Remitente (cliente)', 'cliente'], ['destinatario', 'Destinatario'],
    ['origen', 'Lugar de toma de la mercancía'], ['f_carga', 'Fecha de toma', 'date'],
    ['destino', 'Lugar de entrega'], ['mercancia', 'Designación de la mercancía'],
    ['bultos', 'Nº de bultos', 'number'], ['peso', 'Peso bruto (kg)', 'number'],
    ['matricula', 'Matrícula del vehículo'], ['instrucciones', 'Instrucciones del remitente'],
    ['reservas', 'Reservas del porteador'],
  ],
};
const REQ = {
  deca: ['cliente', 'origen', 'destino', 'mercancia', 'peso', 'f_carga', 'matricula'],
  ecmr: ['cliente', 'destinatario', 'origen', 'destino', 'f_carga', 'mercancia'],
};
const TITULO = {
  deca: 'Documento electrónico de Control Administrativo (DeCA)',
  ecmr: 'Carta de porte por carretera (eCMR)',
};
const ESTADOS = ['borrador', 'emitido', 'anulado', 'cerrado'];

const ajustes = () => JSON.parse(db.prepare('SELECT datos FROM ajustes WHERE id=1').get()?.datos || '{}');
const num = d => `${d.tipo.toUpperCase()}-${d.creado.slice(0, 4)}-${String(d.id).padStart(5, '0')}`;
const url = d => `${BASE}/d/${d.token}`;
const pdfPath = d => path.join(DATA, 'pdf', d.token + '.pdf');

async function generarPdf(d) {
  const datos = JSON.parse(d.datos), emp = datos._emp || {}, link = url(d), hist = datos._hist || [];
  const qr = await QR.toBuffer(link, { margin: 1, width: 240 });
  const estado = d.estado || 'emitido';
  const p = new PDFDocument({ size: 'A4', margin: 40, info: {
    Title: `${TITULO[d.tipo]} ${num(d)}`,
    Author: emp.nombre || '', Creator: 'DeCA y eCMR', CreationDate: new Date(d.creado), ModDate: new Date(d.modificado || d.creado),
  }});
  const chunks = [], fin = new Promise(r => p.on('end', r));
  const fh = t => String(t || '').slice(0, 16).replace('T', ' ') + ' UTC';
  p.on('data', c => chunks.push(c));
  const h = t => p.moveDown(.8).font('Helvetica-Bold').fontSize(11).fillColor('#0f6cbd').text(t).moveDown(.3);
  const fila = (k, v) => p.font('Helvetica-Bold').fontSize(9).fillColor('#000').text(k + ': ', { continued: true }).font('Helvetica').text(String(v || '-')).moveDown(.2);
  p.image(qr, 455, 40, { width: 100 });
  p.font('Helvetica-Bold').fontSize(15).fillColor('#000').text(TITULO[d.tipo], 40, 40, { width: 400 });
  p.font('Helvetica').fontSize(9).fillColor('#555')
    .text(`Nº ${num(d)} - Estado: ${estadoLabel(estado)} - Creado ${fh(d.creado)}${hist.length ? ' - Modificado ' + fh(d.modificado) : ''}`, { width: 400 })
    .text(link, { width: 400 });
  p.x = 40; p.y = Math.max(p.y, 150);

  // Determinar quién es transportista y quién es cargador según mi_papel
  const miPapel = datos.mi_papel || 'transportista'; // compatibilidad retroactiva
  if (miPapel === 'transportista') {
    h('Transportista efectivo (art. 6.b ROTT)'); EMPRESA.forEach(([k, l]) => fila(l, emp[k]));
    h('Cargador contractual (art. 6.a ROTT)');
    fila('Razón social', datos.contraparte_nombre || datos.cliente || '-');
    fila('NIF/CIF', datos.contraparte_nif || '-');
    fila('Dirección', datos.contraparte_direccion || '-');
  } else {
    h('Cargador contractual (art. 6.a ROTT)'); EMPRESA.forEach(([k, l]) => fila(l, emp[k]));
    h('Transportista efectivo (art. 6.b ROTT)');
    fila('Razón social', datos.contraparte_nombre || '-');
    fila('NIF/CIF', datos.contraparte_nif || '-');
    fila('Dirección', datos.contraparte_direccion || '-');
  }

  h('Datos del servicio');
  // Filtrar campos que ahora se gestionan aparte (contraparte)
  const skipKeys = new Set(['cliente','contraparte_id','contraparte_nombre','contraparte_nif','contraparte_direccion','mi_papel','_emp','_hist']);
  CAMPOS[d.tipo].filter(([k]) => !skipKeys.has(k)).forEach(([k, l]) => fila(l, datos[k]));
  if (datos.obs_transportista) fila('Observaciones del transportista efectivo', datos.obs_transportista);
  if (d.tipo === 'ecmr') p.moveDown().font('Helvetica-Oblique').fontSize(8).fillColor('#555')
    .text('Este transporte queda sometido al Convenio CMR, cualquiera que sea la cláusula en contrario.');
  if (hist.length) {
    h('Modificaciones durante el servicio');
    hist.forEach(x => {
      fila(`${fh(x.fecha)}, ${x.por}`, `motivo: ${x.motivo}`);
      x.cambios.forEach(c => p.font('Helvetica').fontSize(8).fillColor('#333')
        .text(`   ${c.campo}: de «${c.antes || '-'}» a «${c.despues || '-'}»`).moveDown(.1));
    });
  }
  p.end(); await fin;
  const buf = Buffer.concat(chunks);
  if (buf.length > 5 * 1024 * 1024) throw new Error('El PDF supera los 5 MB que permite la Resolución');
  fs.writeFileSync(pdfPath(d), buf);
}

function estadoLabel(s) { return ({ borrador: 'Borrador', emitido: 'Emitido', anulado: 'Anulado', cerrado: 'Cerrado' })[s] || s; }

// ----------------------------------------------------
// APLICACIÓN EXPRESS Y CABECERAS DE SEGURIDAD
// ----------------------------------------------------
const app = express();

// Eliminar cabecera de fingerprint de tecnología
app.disable('x-powered-by');

// Cabeceras HTTP de protección integral (estilo Helmet)
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=()');
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; frame-src 'self' blob:; frame-ancestors 'self'; base-uri 'self'; form-action 'self'; connect-src 'self';"
  );
  if (req.secure || req.headers['x-forwarded-proto'] === 'https' || BASE.startsWith('https://')) {
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  }
  next();
});

// Protección contra CSRF en peticiones mutantes (comprobación de origen)
app.use((req, res, next) => {
  if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method)) {
    const origin = req.headers.origin;
    const host = req.headers.host;
    if (origin) {
      try {
        const originHost = new URL(origin).host;
        if (originHost !== host) {
          logAudit(req.u?.usuario, req.ip, 'CSRF_BLOCKED', `Petición desde origen no autorizado: ${origin}`, 'alerta');
          return res.status(403).json({ error: 'Petición bloqueada por seguridad (origen no coincide).' });
        }
      } catch {
        return res.status(403).json({ error: 'Origen inválido' });
      }
    }
  }
  next();
});

// Limite estricto del cuerpo de petición para mitigar ataques DoS
app.use(express.json({ limit: '300kb' }));

// ----------------------------------------------------
// RECURSOS PÚBLICOS
// ----------------------------------------------------

// Visor público del documento escaneado vía QR (con protección estricta contra Path Traversal)
app.get('/d/:token', (req, res) => {
  const token = String(req.params.token || '');
  if (!/^[a-f0-9]{32,64}$/.test(token)) {
    return res.status(400).send('Identificador de documento no válido.');
  }
  const d = db.prepare('SELECT * FROM docs WHERE token=?').get(token);
  if (!d) return res.status(404).send('Documento no encontrado.');

  const file = pdfPath(d);
  const realPdfDir = path.resolve(DATA, 'pdf');
  const realFile = path.resolve(file);
  if (!realFile.startsWith(realPdfDir + path.sep) || !fs.existsSync(realFile)) {
    return res.status(404).send('Archivo de documento no disponible.');
  }
  res.set('Content-Disposition', `inline; filename="${num(d)}.pdf"`).type('pdf').sendFile(realFile);
});

// Generador de QR restringido a URLs internas del sistema
app.get('/api/qr', (req, res) => {
  const target = String(req.query.u || '').trim();
  if (!target || (!target.startsWith(BASE) && !target.startsWith('/d/'))) {
    return res.status(400).send('URL no permitida para generación de código QR.');
  }
  QR.toBuffer(target, { margin: 2, width: 300 })
    .then(b => res.type('png').send(b))
    .catch(() => res.sendStatus(400));
});

// Comprobación de estado de instalación inicial (Setup)
app.get('/api/setup-status', (_, res) => {
  res.json({ needsSetup: isSetupNeeded() });
});

// Registro inicial y configuración de primer arranque (Wizard)
app.post('/api/setup', (req, res) => {
  const ip = req.ip || req.socket.remoteAddress || '';
  const ipCheck = checkIpRateLimit(ip, 5, 15 * 60 * 1000, 15 * 60 * 1000);
  if (ipCheck) return res.status(429).json({ error: ipCheck });

  if (!isSetupNeeded()) {
    return res.status(403).json({ error: 'La instalación inicial ya ha sido completada.' });
  }

  const b = req.body || {};
  const usuario = String(b.usuario || '').trim().toLowerCase();
  const nombre = String(b.nombre || '').trim();
  const email = String(b.email || '').trim().toLowerCase();
  const clave = String(b.clave || '');
  const claveConfirm = String(b.claveConfirm || '');

  if (!usuario || !nombre) {
    return res.status(400).json({ error: 'El nombre completo y el usuario son obligatorios.' });
  }
  if (!/^[a-z0-9_-]{3,30}$/.test(usuario)) {
    return res.status(400).json({ error: 'El usuario debe tener entre 3 y 30 caracteres alfanuméricos (letras, números, guión o guión bajo).' });
  }
  if (clave !== claveConfirm) {
    return res.status(400).json({ error: 'Las contraseñas indicadas no coinciden.' });
  }
  const pwErr = validatePassword(clave);
  if (pwErr) {
    return res.status(400).json({ error: pwErr });
  }

  const emp = {
    nombre: String(b.empresa_nombre || '').trim(),
    nif: String(b.empresa_nif || '').trim().toUpperCase(),
    domicilio: String(b.empresa_domicilio || '').trim(),
    cp: String(b.empresa_cp || '').trim(),
    ciudad: String(b.empresa_ciudad || '').trim(),
    provincia: String(b.empresa_provincia || '').trim(),
    telefono: String(b.empresa_telefono || '').trim(),
    email: String(b.empresa_email || '').trim(),
    web: String(b.empresa_web || '').trim(),
    codigo_nima: String(b.empresa_codigo_nima || '').trim(),
    aut_tipo: String(b.empresa_aut_tipo || 'MDPE').trim(),
    aut_num: String(b.empresa_aut_num || '').trim(),
  };

  db.exec('BEGIN IMMEDIATE');
  try {
    const count = db.prepare('SELECT count(*) as c FROM usuarios').get().c;
    if (count > 0) {
      db.exec('ROLLBACK');
      return res.status(403).json({ error: 'El sistema ya fue inicializado por otro proceso.' });
    }

    const ahora = new Date().toISOString();
    const adminHash = hash(clave);
    const permisosAdmin = Object.keys(PERMISOS);

    const r = db.prepare(`
      INSERT INTO usuarios(usuario, nombre, email, hash, rol, permisos, activo, creado_en, ultimo_login, ultimo_login_ip)
      VALUES(?,?,?,?,?,?,?, ?,?,?)
    `).run(usuario, nombre, email, adminHash, 'admin', JSON.stringify(permisosAdmin), 1, ahora, ahora, ip);

    const adminId = Number(r.lastInsertRowid);

    if (emp.nombre || emp.nif) {
      db.prepare('INSERT INTO ajustes(id, datos) VALUES(1, ?) ON CONFLICT(id) DO UPDATE SET datos=excluded.datos')
        .run(JSON.stringify(emp));
    }

    const sid = crypto.randomBytes(32).toString('hex');
    const expira = Date.now() + 12 * 36e5;
    db.prepare('INSERT INTO sesiones(sid, uid, expira, ip, creado) VALUES(?,?,?,?,?)')
      .run(sid, adminId, expira, ip, Date.now());

    logAudit(usuario, ip, 'SETUP_COMPLETADO', 'Registro inicial del superadministrador y puesta en marcha del sistema.', 'critico');

    db.exec('COMMIT');

    const isSecure = req.secure || req.headers['x-forwarded-proto'] === 'https' || BASE.startsWith('https://');
    res.set('Set-Cookie', `sid=${sid}; HttpOnly; SameSite=Lax; Path=/; Max-Age=43200${isSecure ? '; Secure' : ''}`);
    res.json({ ok: 1, usuario, nombre, rol: 'admin' });
  } catch (err) {
    try { db.exec('ROLLBACK'); } catch {}
    console.error('Error durante setup inicial:', err);
    recordIpFailure(ip, 5);
    res.status(500).json({ error: 'Ocurrió un error interno al inicializar el sistema.' });
  }
});

// Servir cliente SPA estático
app.use(express.static(path.join(__dirname, 'public'), { extensions: ['html'] }));

// ----------------------------------------------------
// AUTENTICACIÓN Y SESIONES
// ----------------------------------------------------
const cookie = req => Object.fromEntries((req.headers.cookie || '').split(';').map(c => c.trim().split('=')).filter(c => c[0]));
const can = (u, p) => !!u && (u.rol === 'admin' || u.permisos.includes(p));
const need = p => (req, res, next) => can(req.u, p) ? next() : res.status(403).json({ error: 'No tienes permiso para esta acción.' });
const adm = (req, res, next) => req.u?.rol === 'admin' ? next() : res.status(403).json({ error: 'Acceso restringido a administradores.' });

// Middleware de identificación de usuario por cookie de sesión HttpOnly
app.use((req, res, next) => {
  const sid = cookie(req).sid || '';
  if (!sid) return next();
  const r = db.prepare(`
    SELECT u.* FROM sesiones s
    JOIN usuarios u ON u.id=s.uid
    WHERE s.sid=? AND s.expira>? AND u.activo=1
  `).get(sid, Date.now());
  if (r) {
    req.u = { ...r, permisos: JSON.parse(r.permisos || '[]') };
  }
  next();
});

// Endpoint de Inicio de Sesión
app.post('/api/login', (req, res) => {
  const ip = req.ip || req.socket.remoteAddress || '';
  const ipCheck = checkIpRateLimit(ip, 10, 15 * 60 * 1000, 15 * 60 * 1000);
  if (ipCheck) return res.status(429).json({ error: ipCheck });

  if (isSetupNeeded()) {
    return res.status(403).json({ error: 'El sistema requiere configuración inicial antes de iniciar sesión.', needsSetup: true });
  }

  const usuario = String(req.body.usuario || '').trim().toLowerCase();
  const clave = String(req.body.clave || '');

  if (!usuario || !clave) {
    return res.status(400).json({ error: 'Indica tu usuario y contraseña.' });
  }

  const u = db.prepare('SELECT * FROM usuarios WHERE usuario=?').get(usuario);
  const now = Date.now();

  if (!u) {
    // Protección contra timing attack / enumeración de usuarios
    dummyVerify(clave);
    recordIpFailure(ip);
    logAudit(usuario, ip, 'LOGIN_FALLIDO', 'Usuario no encontrado en la base de datos', 'aviso');
    return res.status(401).json({ error: 'Usuario o contraseña incorrectos.' });
  }

  if (!u.activo) {
    dummyVerify(clave);
    logAudit(usuario, ip, 'LOGIN_BLOQUEADO', 'Intento de acceso a cuenta inactiva', 'alerta');
    return res.status(403).json({ error: 'Esta cuenta de usuario ha sido desactivada por el administrador.' });
  }

  // Comprobar bloqueo temporal de la cuenta por intentos fallidos reiterados
  if (u.bloqueado_hasta && u.bloqueado_hasta > now) {
    dummyVerify(clave);
    const minRestantes = Math.ceil((u.bloqueado_hasta - now) / 60000);
    logAudit(usuario, ip, 'LOGIN_BLOQUEADO_TEMPORAL', `Cuenta bloqueada temporalmente (${minRestantes} min restantes)`, 'alerta');
    return res.status(429).json({ error: `Cuenta bloqueada temporalmente por intentos fallidos. Inténtalo de nuevo en ${minRestantes} minuto(s).` });
  }

  // Verificación de contraseña
  if (!okPw(clave, u.hash)) {
    const intentos = (u.intentos_fallidos || 0) + 1;
    let bloqueadoHasta = 0;
    if (intentos >= 5) {
      bloqueadoHasta = now + 15 * 60 * 1000;
      logAudit(usuario, ip, 'CUENTA_BLOQUEADA', 'Cuenta bloqueada 15 minutos tras 5 intentos fallidos', 'alerta');
    } else {
      logAudit(usuario, ip, 'LOGIN_FALLIDO', `Contraseña incorrecta (intento ${intentos}/5)`, 'aviso');
    }
    db.prepare('UPDATE usuarios SET intentos_fallidos=?, bloqueado_hasta=? WHERE id=?').run(intentos, bloqueadoHasta, u.id);
    recordIpFailure(ip);
    return res.status(401).json({ error: 'Usuario o contraseña incorrectos.' });
  }

  // Éxito: restablecer contadores y registrar auditoría
  db.prepare('UPDATE usuarios SET intentos_fallidos=0, bloqueado_hasta=0, ultimo_login=?, ultimo_login_ip=? WHERE id=?')
    .run(new Date().toISOString(), ip, u.id);
  resetIpAttempts(ip);

  // Limpieza de sesiones expiradas
  db.prepare('DELETE FROM sesiones WHERE expira<?').run(now);

  // Creación de identificador de sesión seguro (256 bits)
  const sid = crypto.randomBytes(32).toString('hex');
  db.prepare('INSERT INTO sesiones(sid, uid, expira, ip, creado) VALUES(?,?,?,?,?)')
    .run(sid, u.id, now + 12 * 36e5, ip, now);

  logAudit(usuario, ip, 'LOGIN_EXITOSO', 'Inicio de sesión correcto en la plataforma');

  const isSecure = req.secure || req.headers['x-forwarded-proto'] === 'https' || BASE.startsWith('https://');
  res.set('Set-Cookie', `sid=${sid}; HttpOnly; SameSite=Lax; Path=/; Max-Age=43200${isSecure ? '; Secure' : ''}`).json({ ok: 1 });
});

// Cierre de Sesión
app.post('/api/logout', (req, res) => {
  const sid = cookie(req).sid || '';
  if (sid) {
    db.prepare('DELETE FROM sesiones WHERE sid=?').run(sid);
  }
  if (req.u) {
    logAudit(req.u.usuario, req.ip, 'LOGOUT', 'Cierre de sesión voluntario');
  }
  res.set('Set-Cookie', 'sid=; Path=/; Max-Age=0').json({ ok: 1 });
});

// ----------------------------------------------------
// RUTAS PROTEGIDAS (REQUIEREN AUTENTICACIÓN)
// ----------------------------------------------------
app.use('/api', (req, res, next) => req.u ? next() : res.status(401).json({ error: 'Sesión expirada o no iniciada.' }));

// Perfil del usuario conectado
app.get('/api/yo', (req, res) => res.json({
  usuario: req.u.usuario,
  nombre: req.u.nombre,
  email: req.u.email || '',
  rol: req.u.rol,
  permisos: Object.keys(PERMISOS).filter(p => can(req.u, p)),
  PERMISOS,
}));

// Logs de Auditoría de Seguridad (solo administradores)
app.get('/api/audit-logs', adm, (req, res) => {
  const limit = Math.min(Number(req.query.limit) || 100, 500);
  const logs = db.prepare('SELECT * FROM audit_logs ORDER BY id DESC LIMIT ?').all(limit);
  res.json(logs);
});

// Metadatos y Ajustes
app.get('/api/campos', (_, res) => res.json({ CAMPOS, EMPRESA, REQ, ESTADOS }));
app.get('/api/ajustes', (_, res) => res.json(ajustes()));
app.put('/api/ajustes', need('empresa'), (req, res) => {
  const next = Object.fromEntries(EMPRESA.map(([k]) => [k, String(req.body?.[k] ?? '')]));
  db.prepare('INSERT INTO ajustes VALUES(1,?) ON CONFLICT(id) DO UPDATE SET datos=excluded.datos').run(JSON.stringify(next));
  logAudit(req.u.usuario, req.ip, 'AJUSTES_MODIFICADOS', 'Actualización de datos fiscales en Mi entidad');
  res.json(next);
});

// Gestión de Usuarios (Administrador)
const limpio = u => ({
  id: u.id,
  usuario: u.usuario,
  nombre: u.nombre,
  email: u.email || '',
  rol: u.rol,
  permisos: JSON.parse(u.permisos || '[]'),
  activo: !!u.activo,
  creado_en: u.creado_en || '',
  ultimo_login: u.ultimo_login || '',
  ultimo_login_ip: u.ultimo_login_ip || '',
});
const otroAdmin = id => db.prepare("SELECT 1 FROM usuarios WHERE rol='admin' AND activo=1 AND id<>?").get(id);

app.get('/api/usuarios', adm, (_, res) => res.json(db.prepare('SELECT * FROM usuarios ORDER BY usuario').all().map(limpio)));

app.post('/api/usuarios', adm, (req, res) => {
  const b = req.body || {}, id = Number(b.id) || 0;
  const usuario = String(b.usuario || '').trim().toLowerCase();
  const nombre = String(b.nombre || '').trim();
  const email = String(b.email || '').trim().toLowerCase();
  const clave = String(b.clave || '');
  const rol = b.rol === 'admin' ? 'admin' : 'usuario';
  const activo = b.activo === false ? 0 : 1;
  const permisos = JSON.stringify((b.permisos || []).filter(p => PERMISOS[p]));

  if (!usuario || !nombre) return res.status(400).json({ error: 'Faltan el usuario y el nombre completo.' });
  if (!/^[a-z0-9_-]{3,30}$/.test(usuario)) {
    return res.status(400).json({ error: 'El usuario debe tener entre 3 y 30 caracteres alfanuméricos.' });
  }

  // Si es alta o se desea cambiar la contraseña, validar la política de seguridad
  if (!id || clave) {
    const pwErr = validatePassword(clave);
    if (pwErr) return res.status(400).json({ error: pwErr });
  }

  try {
    if (id) {
      if ((rol !== 'admin' || !activo) && !otroAdmin(id)) {
        return res.status(400).json({ error: 'Debe quedar al menos un administrador activo en el sistema.' });
      }
      db.prepare('UPDATE usuarios SET usuario=?,nombre=?,email=?,rol=?,permisos=?,activo=? WHERE id=?')
        .run(usuario, nombre, email, rol, permisos, activo, id);

      if (clave) {
        db.prepare('UPDATE usuarios SET hash=? WHERE id=?').run(hash(clave), id);
      }
      if (!activo || clave) {
        db.prepare('DELETE FROM sesiones WHERE uid=?').run(id);
      }
      logAudit(req.u.usuario, req.ip, 'USUARIO_MODIFICADO', `Modificación del usuario ${usuario} (ID ${id})`);
    } else {
      const ahora = new Date().toISOString();
      db.prepare(`
        INSERT INTO usuarios(usuario,nombre,email,hash,rol,permisos,activo,creado_en)
        VALUES(?,?,?,?,?,?,?,?)
      `).run(usuario, nombre, email, hash(clave), rol, permisos, activo, ahora);
      logAudit(req.u.usuario, req.ip, 'USUARIO_CREADO', `Alta del usuario ${usuario} con rol ${rol}`);
    }
    res.json({ ok: 1 });
  } catch (err) {
    res.status(400).json({ error: 'No se pudo guardar el usuario (¿nombre de usuario ya en uso?).' });
  }
});

app.delete('/api/usuarios/:id', adm, (req, res) => {
  const id = Number(req.params.id);
  if (id === req.u.id) return res.status(400).json({ error: 'No puedes eliminar tu propia cuenta de usuario en uso.' });
  if (!otroAdmin(id)) return res.status(400).json({ error: 'Debe quedar al menos un administrador activo en el sistema.' });

  const u = db.prepare('SELECT usuario FROM usuarios WHERE id=?').get(id);
  db.prepare('DELETE FROM sesiones WHERE uid=?').run(id);
  db.prepare('DELETE FROM usuarios WHERE id=?').run(id);
  logAudit(req.u.usuario, req.ip, 'USUARIO_ELIMINADO', `Eliminación del usuario ${u?.usuario || id}`);
  res.json({ ok: 1 });
});

// Clientes (compatibilidad)
app.get('/api/clientes', (_, res) => res.json(db.prepare('SELECT * FROM clientes ORDER BY nombre').all()));
app.post('/api/clientes', need('clientes'), (req, res) => {
  const c = req.body || {}, v = ['nombre','nif','direccion','cp','ciudad','email','tel'].map(k => String(c[k] || ''));
  if (!v[0] || !v[1] || !v[2]) return res.status(400).json({ error: 'Nombre, NIF y dirección son obligatorios (el DeCA los exige).' });
  if (c.id) {
    db.prepare('UPDATE clientes SET nombre=?,nif=?,direccion=?,cp=?,ciudad=?,email=?,tel=? WHERE id=?').run(...v, c.id);
    db.prepare('UPDATE empresas SET nombre=?,nif=?,direccion=?,cp=?,ciudad=?,email=?,tel=? WHERE cliente_id=?').run(...v, c.id);
  } else {
    const r = db.prepare('INSERT INTO clientes(nombre,nif,direccion,cp,ciudad,email,tel) VALUES(?,?,?,?,?,?,?)').run(...v);
    db.prepare('INSERT OR IGNORE INTO empresas(nombre,nif,direccion,cp,ciudad,email,tel,tipo,cliente_id) VALUES(?,?,?,?,?,?,?,?,?)')
      .run(...v, 'Cliente', Number(r.lastInsertRowid));
  }
  res.json({ ok: 1 });
});
app.delete('/api/clientes/:id', need('clientes'), (req, res) => {
  db.prepare('DELETE FROM clientes WHERE id=?').run(req.params.id);
  db.prepare('DELETE FROM empresas WHERE cliente_id=?').run(req.params.id);
  res.json({ ok: 1 });
});

// Empresas / Directorio
app.get('/api/empresas', need('empresas'), (_, res) => {
  res.json(db.prepare('SELECT * FROM empresas ORDER BY nombre').all());
});
app.post('/api/empresas', need('empresas'), (req, res) => {
  const b = req.body || {};
  const id = Number(b.id) || 0;
  const nombre = String(b.nombre || '').trim(), nif = String(b.nif || '').trim();
  const tipo = ['Cliente','Cargador','Transportista'].includes(b.tipo) ? b.tipo : 'Cliente';
  if (!nombre || !nif) return res.status(400).json({ error: 'Nombre y NIF/CIF son obligatorios.' });
  const vals = [nombre,nif,String(b.direccion||''),String(b.cp||''),String(b.ciudad||''),String(b.email||''),String(b.tel||''),tipo];
  try {
    let clienteId = Number(b.cliente_id) || 0;
    if (tipo === 'Cliente') {
      if (clienteId) db.prepare('UPDATE clientes SET nombre=?,nif=?,direccion=?,cp=?,ciudad=?,email=?,tel=? WHERE id=?').run(...vals.slice(0,7), clienteId);
      else {
        const existing = db.prepare('SELECT id FROM clientes WHERE nif=?').get(nif);
        if (existing) { clienteId = existing.id; db.prepare('UPDATE clientes SET nombre=?,nif=?,direccion=?,cp=?,ciudad=?,email=?,tel=? WHERE id=?').run(...vals.slice(0,7), clienteId); }
        else clienteId = Number(db.prepare('INSERT INTO clientes(nombre,nif,direccion,cp,ciudad,email,tel) VALUES(?,?,?,?,?,?,?)').run(...vals.slice(0,7)).lastInsertRowid);
      }
    }
    let savedId = id;
    if (id) {
      db.prepare('UPDATE empresas SET nombre=?,nif=?,direccion=?,cp=?,ciudad=?,email=?,tel=?,tipo=?,cliente_id=? WHERE id=?').run(...vals, clienteId || null, id);
    } else {
      const ins = db.prepare('INSERT INTO empresas(nombre,nif,direccion,cp,ciudad,email,tel,tipo,cliente_id) VALUES(?,?,?,?,?,?,?,?,?)').run(...vals, clienteId || null);
      savedId = Number(ins.lastInsertRowid);
    }
    res.json({ ok: 1, id: savedId });
  } catch (e) { res.status(400).json({ error: 'No se pudo guardar (¿ya existe ese NIF/CIF?)' }); }
});
app.delete('/api/empresas/:id', need('empresas'), (req, res) => {
  const row = db.prepare('SELECT cliente_id FROM empresas WHERE id=?').get(req.params.id);
  if (row?.cliente_id) db.prepare('DELETE FROM clientes WHERE id=?').run(row.cliente_id);
  db.prepare('DELETE FROM empresas WHERE id=?').run(req.params.id);
  res.json({ ok: 1 });
});

// Medios de transporte
app.get('/api/vehiculos', need('transporte'), (_, res) => res.json(db.prepare('SELECT * FROM vehiculos ORDER BY matricula').all()));
app.post('/api/vehiculos', need('transporte'), (req, res) => {
  const b = req.body || {}, id = Number(b.id) || 0, matricula = String(b.matricula||'').trim().toUpperCase();
  if (!matricula || !String(b.tipo||'').trim()) return res.status(400).json({ error: 'Matrícula y tipo son obligatorios.' });
  try {
    const vals = [matricula,String(b.tipo),String(b.modelo||''),String(b.estado||'Disponible'),String(b.itv||'')];
    if (id) db.prepare('UPDATE vehiculos SET matricula=?,tipo=?,modelo=?,estado=?,itv=? WHERE id=?').run(...vals,id);
    else db.prepare('INSERT INTO vehiculos(matricula,tipo,modelo,estado,itv) VALUES(?,?,?,?,?)').run(...vals);
    res.json({ ok: 1 });
  } catch { res.status(400).json({ error: 'No se pudo guardar (¿ya existe esa matrícula?)' }); }
});
app.delete('/api/vehiculos/:id', need('transporte'), (req, res) => { db.prepare('DELETE FROM vehiculos WHERE id=?').run(req.params.id); res.json({ok:1}); });

app.get('/api/conductores', need('transporte'), (_, res) => res.json(db.prepare('SELECT id,nombre,dni,telefono,email,activo FROM conductores ORDER BY nombre').all().map(c => ({...c, activo: !!c.activo}))));
app.post('/api/conductores', need('transporte'), (req, res) => {
  const b=req.body||{}, id=Number(b.id)||0, nombre=String(b.nombre||'').trim(), dni=String(b.dni||'').trim().toUpperCase();
  if (!nombre || !dni) return res.status(400).json({ error: 'Nombre y DNI/NIE son obligatorios.' });
  try {
    const vals=[nombre,dni,String(b.telefono||''),String(b.email||''),b.activo===false?0:1];
    if (id) db.prepare('UPDATE conductores SET nombre=?,dni=?,telefono=?,email=?,activo=? WHERE id=?').run(...vals,id);
    else db.prepare('INSERT INTO conductores(nombre,dni,telefono,email,activo) VALUES(?,?,?,?,?)').run(...vals);
    res.json({ok:1});
  } catch { res.status(400).json({ error: 'No se pudo guardar (¿ya existe ese DNI/NIE?)' }); }
});
app.delete('/api/conductores/:id', need('transporte'), (req,res)=>{ db.prepare('DELETE FROM conductores WHERE id=?').run(req.params.id); res.json({ok:1}); });

// Mercancías
app.get('/api/mercancias', need('mercancias'), (_, res) => res.json(db.prepare('SELECT * FROM mercancias ORDER BY nombre').all()));
app.post('/api/mercancias', need('mercancias'), (req,res)=>{
  const b=req.body||{}, id=Number(b.id)||0, nombre=String(b.nombre||'').trim();
  if(!nombre) return res.status(400).json({error:'El nombre de la mercancía es obligatorio.'});
  try {
    const vals=[nombre,String(b.codigo||''),String(b.unidad||'kg')];
    if(id) db.prepare('UPDATE mercancias SET nombre=?,codigo=?,unidad=? WHERE id=?').run(...vals,id);
    else db.prepare('INSERT INTO mercancias(nombre,codigo,unidad) VALUES(?,?,?)').run(...vals);
    res.json({ok:1});
  } catch { res.status(400).json({error:'No se pudo guardar (¿ya existe ese nombre?)'}); }
});
app.delete('/api/mercancias/:id', need('mercancias'), (req,res)=>{db.prepare('DELETE FROM mercancias WHERE id=?').run(req.params.id);res.json({ok:1});});

// Ubicaciones frecuentes
app.get('/api/ubicaciones', need('ubicaciones'), (_,res)=>res.json(db.prepare('SELECT * FROM ubicaciones ORDER BY nombre').all()));
app.post('/api/ubicaciones', need('ubicaciones'), (req,res)=>{
  const b=req.body||{}, id=Number(b.id)||0, nombre=String(b.nombre||'').trim();
  if(!nombre) return res.status(400).json({error:'El nombre de la ubicación es obligatorio.'});
  try {
    const vals=[nombre,String(b.tipo||'Punto de carga'),String(b.direccion||''),String(b.cp||''),String(b.ciudad||''),String(b.provincia||''),String(b.empresa||'')];
    if(id) db.prepare('UPDATE ubicaciones SET nombre=?,tipo=?,direccion=?,cp=?,ciudad=?,provincia=?,empresa=? WHERE id=?').run(...vals,id);
    else db.prepare('INSERT INTO ubicaciones(nombre,tipo,direccion,cp,ciudad,provincia,empresa) VALUES(?,?,?,?,?,?,?)').run(...vals);
    res.json({ok:1});
  } catch { res.status(400).json({error:'No se pudo guardar (¿ya existe ese nombre?)'}); }
});
app.delete('/api/ubicaciones/:id', need('ubicaciones'), (req,res)=>{db.prepare('DELETE FROM ubicaciones WHERE id=?').run(req.params.id);res.json({ok:1});});

// Documentos DeCA y eCMR
app.get('/api/docs', (req,res)=>{
  const tipo = String(req.query.tipo || '');
  if (!CAMPOS[tipo] || !(can(req.u,tipo+'_ver') || can(req.u,tipo+'_crear'))) return res.status(403).json({error:'No tienes permiso para ver estos documentos'});
  res.json(db.prepare(`SELECT id,tipo,token,creado,modificado,datos,usuario,COALESCE(estado,'emitido') AS estado
    FROM docs WHERE tipo=? ORDER BY id DESC LIMIT 500`).all(tipo).map(d=>({
      id:d.id,num:num(d),url:url(d),creado:d.creado,mod:d.modificado,por:d.usuario,estado:d.estado,datos:JSON.parse(d.datos)
  })));
});
app.get('/api/docs-todos', (req,res)=>{
  const canSee = can(req.u,'deca_ver')||can(req.u,'deca_crear')||can(req.u,'ecmr_ver')||can(req.u,'ecmr_crear');
  if(!canSee) return res.status(403).json({error:'No tienes permiso para ver documentos'});
  res.json(db.prepare(`SELECT id,tipo,token,creado,modificado,datos,usuario,COALESCE(estado,'emitido') AS estado
    FROM docs ORDER BY id DESC LIMIT 500`).all().filter(d=>can(req.u,d.tipo+'_ver')||can(req.u,d.tipo+'_crear')).map(d=>({id:d.id,num:num(d),url:url(d),creado:d.creado,mod:d.modificado,por:d.usuario,estado:d.estado,datos:JSON.parse(d.datos)})));
});

const faltan = (tipo, datos) => {
  const reqKeys = REQ[tipo].filter(k => k !== 'cliente'); // 'cliente' ya no es FK, se valida aparte
  const f = reqKeys.filter(k => !String(datos[k]||'').trim()).map(k => {
    const campo = CAMPOS[tipo].find(([ck]) => ck === k);
    return campo ? campo[1] : k;
  });
  const e = ajustes();
  if (!e.nombre || !e.nif) f.push('Datos del transportista (pestaña Mi entidad)');
  // Validar contraparte
  const tieneContraparteId = datos.contraparte_id && String(datos.contraparte_id).trim();
  const tieneContraparteManual = datos.contraparte_nombre && datos.contraparte_nif && datos.contraparte_direccion;
  if (!tieneContraparteId && !tieneContraparteManual) {
    f.push('Empresa contraparte (nombre, NIF y dirección obligatorios)');
  }
  return f.length ? `Faltan datos obligatorios: ${f.join(', ')}.` : '';
};

app.post('/api/docs', async (req,res)=>{
  try {
    const {tipo,datos:payload={},estado:requestedEstado} = req.body||{};
    const datos={...payload};
    if(!CAMPOS[tipo]) return res.status(400).json({error:'Tipo de documento no válido'});
    if(!can(req.u,tipo+'_crear')) return res.status(403).json({error:'No tienes permiso para crear este documento'});

    // Resolver contraparte: por ID de empresa o por datos manuales
    if (datos.contraparte_id && String(datos.contraparte_id).trim()) {
      const empresa = db.prepare('SELECT * FROM empresas WHERE id=?').get(datos.contraparte_id);
      if (empresa) {
        datos.contraparte_nombre = empresa.nombre;
        datos.contraparte_nif = empresa.nif;
        datos.contraparte_direccion = [empresa.direccion, empresa.cp, empresa.ciudad].filter(Boolean).join(', ');
      }
    }

    const e = faltan(tipo, datos); if(e) return res.status(400).json({error:e});

    // Compatibilidad retroactiva: rellenar campo 'cliente' para vistas antiguas
    const miPapel = datos.mi_papel || 'transportista';
    const cpStr = `${datos.contraparte_nombre} (NIF ${datos.contraparte_nif}), ${datos.contraparte_direccion}`;
    datos.cliente = cpStr; // mantiene campo 'cliente' para listados y modal antiguo

    datos._emp = ajustes();
    const estado=ESTADOS.includes(requestedEstado) ? requestedEstado : 'emitido';
    const token=crypto.randomBytes(24).toString('hex'), creado=new Date().toISOString();
    const r=db.prepare('INSERT INTO docs(tipo,token,creado,modificado,datos,usuario,estado) VALUES(?,?,?,?,?,?,?)')
      .run(tipo,token,creado,creado,JSON.stringify(datos),req.u.nombre,estado);
    const d={id:Number(r.lastInsertRowid),tipo,token,creado,modificado:creado,datos:JSON.stringify(datos),estado};
    await generarPdf(d);
    logAudit(req.u.usuario, req.ip, 'DOC_CREADO', `Creación de ${num(d)} en estado ${estado}`);
    res.json({num:num(d),url:url(d),id:d.id,estado});
  }catch(x){console.error(x);res.status(500).json({error:'No se pudo generar el PDF'});}
});

app.put('/api/docs/:id', async (req,res)=>{
  try{
    const d=db.prepare('SELECT * FROM docs WHERE id=?').get(req.params.id);
    if(!d)return res.status(404).json({error:'Documento no encontrado'});
    if(!can(req.u,d.tipo+'_crear'))return res.status(403).json({error:'No tienes permiso para modificar este documento'});
    const {motivo='',...nuevo}=req.body||{},datos=JSON.parse(d.datos);
    if(!String(motivo).trim())return res.status(400).json({error:'Indica el motivo de la modificación'});
    const cambios=CAMPOS[d.tipo].filter(([k,,t])=>t!=='cliente' && String(nuevo[k]??'')!==String(datos[k]??''))
      .map(([k,l])=>({k,campo:l,antes:datos[k]||'',despues:String(nuevo[k]??'')}));
    if(!cambios.length)return res.status(400).json({error:'No hay cambios que guardar'});
    const e=faltan(d.tipo,{...datos,...nuevo});if(e)return res.status(400).json({error:e});
    const ahora=new Date().toISOString();
    cambios.forEach(c=>{datos[c.k]=c.despues;});
    (datos._hist ||= []).push({fecha:ahora,por:req.u.nombre,motivo:String(motivo).trim(),cambios});
    d.datos=JSON.stringify(datos);d.modificado=ahora;
    db.prepare('UPDATE docs SET datos=?,modificado=? WHERE id=?').run(d.datos,ahora,d.id);
    await generarPdf({...d,datos:d.datos});
    logAudit(req.u.usuario, req.ip, 'DOC_MODIFICADO', `Modificación de ${num(d)}: ${motivo}`);
    res.json({num:num(d),url:url(d),estado:d.estado||'emitido'});
  }catch(x){console.error(x);res.status(500).json({error:'No se pudo modificar el documento'});}
});

app.patch('/api/docs/:id/estado', async (req,res)=>{
  try{
    const d=db.prepare('SELECT * FROM docs WHERE id=?').get(req.params.id); if(!d)return res.status(404).json({error:'Documento no encontrado'});
    if(!can(req.u,d.tipo+'_crear')) return res.status(403).json({error:'No tienes permiso para cambiar el estado'});
    const estado=String(req.body?.estado||''); if(!ESTADOS.includes(estado)) return res.status(400).json({error:'Estado no válido'});
    const motivo=String(req.body?.motivo||'').trim();
    if(['anulado','cerrado'].includes(estado) && !motivo) return res.status(400).json({error:'Indica el motivo'});
    const datos=JSON.parse(d.datos), ahora=new Date().toISOString();
    (datos._hist ||= []).push({fecha:ahora,por:req.u.nombre,motivo:motivo||`Cambio de estado a ${estadoLabel(estado)}`,cambios:[{k:'estado',campo:'Estado',antes:d.estado||'emitido',despues:estado}]});
    db.prepare('UPDATE docs SET estado=?,datos=?,modificado=? WHERE id=?').run(estado,JSON.stringify(datos),ahora,d.id);
    const next={...d,estado,datos:JSON.stringify(datos),modificado:ahora}; await generarPdf(next);
    logAudit(req.u.usuario, req.ip, 'DOC_ESTADO', `Cambio de estado en ${num(d)} a ${estado}: ${motivo}`);
    res.json({ok:1,estado});
  }catch(x){console.error(x);res.status(500).json({error:'No se pudo cambiar el estado'});}
});

// Manejador global de errores para no filtrar trazas ni información interna
app.use((err, req, res, next) => {
  console.error('Error no capturado:', err);
  if (res.headersSent) return next(err);
  res.status(500).json({ error: 'Ha ocurrido un error interno en el servidor.' });
});

if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`DeCA y eCMR activo en http://localhost:${PORT}`);
    console.log(`URL base para códigos QR: ${BASE}`);
    if (isSetupNeeded()) {
      console.log('--------------------------------------------------------------------------');
      console.log('*** PRIMER ARRANQUE DETECTADO: SISTEMA EN MODO CONFIGURACIÓN INICIAL ***');
      console.log(`Abre en tu navegador ${BASE} para registrar la cuenta del administrador.`);
      console.log('--------------------------------------------------------------------------');
    }
    (async () => {
      for (const d of db.prepare('SELECT * FROM docs').all()) {
        if (!fs.existsSync(pdfPath(d))) await generarPdf(d);
      }
    })().catch(console.error);
  });
}

module.exports = { app, db, hash, okPw, validatePassword, isSetupNeeded, logAudit };


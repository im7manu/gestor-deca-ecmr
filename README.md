# Gestor DeCA y eCMR 

Plataforma integral para la emisión, gestión y trazabilidad documental de **DeCA** (Documento Electrónico de Control Administrativo) y **eCMR** (Carta de porte electrónica internacional), con interfaz moderna, backend en Node.js, base de datos nativa SQLite y arquitectura de seguridad blindada para despliegues en producción.

---
<img width="960" alt="Interfaz inicial de Gestor DeCA y eCMR" src="https://github.com/user-attachments/assets/1bf3c7a7-28a6-4056-b6eb-798301ed5f1b" />

## 🚀 Primer Arranque y Registro Inicial (Setup Wizard)

La aplicación **ya no contiene contraseñas maestras por defecto ni puertas traseras**.

La primera vez que se ejecuta la aplicación, el sistema detecta de forma automática que no existen usuarios registrados y activa el **Asistente de Configuración Inicial**:

1. Arranca la aplicación con Node (requiere Node >= 22.13):
   ```bash
   npm install
   npm start
   ```
2. Abre en tu navegador `http://localhost:9000` (o la IP/dominio configurado).
3. Aparecerá la pantalla de **Configuración Inicial y Registro**:
   - **Superadministrador**: Nombre completo, nombre de usuario alfanumérico, email de seguridad y contraseña robusta.
   - **Medidor de Seguridad en tiempo real**: Se exige una contraseña de al menos 10 caracteres que combine mayúsculas, minúsculas, números y caracteres especiales (`!@#$%...`).
   - **Datos de Mi Entidad**: Configura la razón social del transportista, NIF/CIF, domicilio y autorización de transporte (ej. MDPE).
4. Al pulsar **Finalizar instalación y entrar**, el sistema:
   - Aplica hashing criptográfico mediante `scrypt` con sal única de 32 bytes y clave de 64 bytes.
   - Bloquea de forma atómica y permanente el endpoint de instalación para evitar registros posteriores no autorizados.
   - Genera una sesión segura con token aleatorio de 256 bits y cookie `HttpOnly`.
   - Inicia sesión automáticamente en el cuadro de mando.

Para permitir el acceso a otros equipos de la red local o en producción:
```bash
BASE_URL=http://IP-DEL-SERVIDOR:9000 npm start
```

En producción, despliega siempre detrás de HTTPS con tu dominio:
```bash
BASE_URL=https://tudominio.com npm start
```

---

## 🛡️ Medidas de Seguridad Implementadas (Blindaje de Despliegue)

Para garantizar un entorno impenetrable en producción, se han incorporado las siguientes capas de seguridad:

| Capa de Seguridad | Implementación técnica | Protección frente a |
|---|---|---|
| **Criptografía de Contraseñas** | Algoritmo `scrypt` (coste de memoria y CPU `N: 16384, r: 8, p: 1`) con sal aleatoria de 32 bytes (`crypto.randomBytes(32)`) y clave derivada de 64 bytes. | Cracking por fuerza bruta, diccionarios, tablas arcoíris y aceleradores GPU/ASIC. |
| **Mitigación de Timing Attacks** | Verificación constante contra hash ficticio en intentos de login con usuarios inexistentes y comparación en tiempo constante con `crypto.timingSafeEqual`. | Enumeración de usuarios por análisis de tiempos de respuesta en red. |
| **Política Estricta de Contraseñas** | Mínimo 10 caracteres obligatorios con mayúsculas, minúsculas, dígitos y símbolos tanto en setup inicial como en creación/edición de usuarios. | Contraseñas triviales o fáciles de adivinar. |
| **Protección Anti-Fuerza Bruta** | Bloqueo temporal de cuentas tras 5 intentos fallidos (15 minutos) y limitación de tasa por dirección IP en memoria. | Ataques masivos de adivinación de contraseñas. |
| **Gestión de Sesiones** | Identificadores de sesión criptográficos de 256 bits (`crypto.randomBytes(32)`). Cookies marcadas con `HttpOnly`, `SameSite=Lax` y `Secure` condicional. | Robo de sesión por XSS, fijación de sesión y secuestro. |
| **Cabeceras HTTP Defensivas** | `Content-Security-Policy` restrictiva, `X-Frame-Options: SAMEORIGIN`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: strict-origin-when-cross-origin`, `Permissions-Policy`. Ocultación de cabecera `X-Powered-By`. | Clickjacking, inyección XSS, sniffing MIME y ataques de canal lateral. |
| **Defensa contra CSRF** | Validación estricta del origen (`Origin`/`Referer`) en todas las peticiones con métodos mutantes (`POST`, `PUT`, `PATCH`, `DELETE`). | Cross-Site Request Forgery desde páginas maliciosas externas. |
| **Protección Path Traversal** | Validación estricta del formato de tokens de documentos (`^[a-f0-9]{32,64}$`) y verificación de confinamiento en el directorio `data/pdf/` mediante `path.resolve`. | Lectura no autorizada de archivos del sistema operativo (`../../etc/passwd`). |
| **Auditoría de Seguridad** | Tabla interna `audit_logs` que registra todos los accesos, logins fallidos, bloqueos, modificaciones de usuarios y cambios de documentos con usuario, IP, fecha y nivel de severidad. | Trazabilidad forense y cumplimiento normativo de seguridad. |

---

## 📋 Estructura y Navegación del Sistema

| Pestaña | Función implementada | API Backend |
|---|---|---|
| **Inicio** | Cuadro de mando, envíos en curso, alertas de ITV caducada y borradores pendientes | `/api/docs-todos`, `/api/vehiculos` |
| **Envíos** | Gestión DeCA y eCMR, filtros por estado (`borrador`, `emitido`, `cerrado`, `anulado`), visor PDF integrado, QR público y trazabilidad de rectificaciones | `/api/docs-todos`, `/api/docs`, `/api/docs/:id`, `/api/docs/:id/estado`, `/api/qr` |
| **Empresas** | Directorio de clientes, cargadores y transportistas con sincronización de catálogo | `/api/empresas`, `/api/clientes` |
| **Medios de transporte** | Flota de vehículos (tractoras, rígidos, remolques) con ITV y conductores activos/inactivos | `/api/vehiculos`, `/api/conductores` |
| **Mercancías** | Catálogo habitual con códigos LER/NC y unidades de medida | `/api/mercancias` |
| **Ubicaciones** | Puntos de carga, descarga y almacenes para autocompletar trayectos | `/api/ubicaciones` |
| **Usuarios y Seguridad** | Gestión de usuarios, asignación de roles/permisos, y visor de **Auditoría de Seguridad** | `/api/usuarios`, `/api/audit-logs` |
| **Mi entidad** | Datos fiscales del transportista efectivo aplicados a nuevos documentos | `/api/ajustes` |

---

## 📦 Base de Datos y Persistencia

- Base de datos SQLite gestionada mediante la API nativa de Node.js `node:sqlite` en `data/app.db`.
- Los documentos PDF oficiales generados se almacenan en `data/pdf/<token>.pdf`.
- La URL pública accesible mediante QR `/d/<token>` permite la comprobación en carretera por las autoridades de tráfico e inspección de transportes sin necesidad de credenciales.

Creado con ❤️ por its7manu

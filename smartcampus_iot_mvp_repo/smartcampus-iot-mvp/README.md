# SmartCampus IoT — Prototipo Funcional MVP (Unidad 3 TI3043)

**Proyecto:** SmartCampus IoT – Ecosistema Inteligente de Control de Acceso Peatonal y Vehicular (LPR / NFC / QR)  
**Asignatura:** Cocreación, Patrones y Requerimientos del Software (`TI3043`) — INACAP Sede Maipú  
**Docente:** Manuel Esteban Rojas Villarroel  
**Integrantes:** Joaquín Elgueta – Howens Castro Sierra  

---

## 1. Arquitectura y Características del Prototipo (MVP)

1. **Autenticación Multifactor y Credenciales Dinámicas TOTP (`src/auth_totp.py`):**
   - Implementación del estándar **RFC 6238 (TOTP)** con renovación cada 30 segundos y ventana de tolerancia `valid_window=1` (`RF-02`).
   - Control de Acceso Basado en Roles (**RBAC** con tokens firmados HMAC-SHA256) para mitigar **OWASP A01:2021 (Broken Access Control)**.
   - Bloqueo automático de cuenta por 15 minutos tras 3 intentos fallidos para mitigar **OWASP A07:2021 (Identification and Authentication Failures)** y cumplir la **Ley N° 21.459 / Ley N° 19.223**.
2. **Persistencia Segura, Módulo 11 y Cifrado de Datos (`src/db_security.py`):**
   - Validación matemática de RUT chileno (Módulo 11), hashing de contraseñas con sal única (`PBKDF2-HMAC-SHA256` / `Argon2id-ready`), cifrado de campos sensibles y enmascaramiento de RUT en bitácora para cumplir la **Ley N° 19.628** y **OWASP A02:2021**.
   - Caché local en **SQLite** para continuidad operativa ante desconexiones WAN (`RNF-02`).
3. **Motor Edge LPR / OCR Anti-Inyección (`src/lpr_ocr_service.py`):**
   - Sanitización estricta mediante expresiones regulares (`^[A-Z]{2,4}[0-9]{2,4}$`) y consultas 100% parametrizadas para neutralizar **OWASP A03:2021 (Injection)** con latencia menor a 1,5 segundos (`RNF-01`).

---

## 2. Cómo Ejecutar el Prototipo y las Pruebas Automatizadas

### Opción A: Abrir la Interfaz Interactiva Directamente
Puedes abrir el archivo `templates/index.html` directamente en cualquier navegador web (Chrome, Edge, Firefox) para interactuar en vivo con el **Pase Móvil QR TOTP de 30s** y el **Dashboard del Guardia LPR**.

### Opción B: Ejecutar el Servidor Backend Flask y la Suite de Pruebas
```bash
# 1. Ejecutar los 6 Casos de Prueba del Plan de Pruebas Integral (CP-01 a CP-06)
python -m unittest tests/test_suite_mvp.py -v

# 2. Iniciar el servidor web y API REST en http://127.0.0.1:5000
python app.py
```

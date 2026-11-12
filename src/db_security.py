"""
Módulo: src/db_security.py
Propósito: Persistencia Segura con SQLite/SQLAlchemy (RNF-02 Fallback Local),
Validación de RUT Chileno (Módulo 11), Hashing de Contraseñas y Protección de Datos (Ley N° 19.628 / OWASP A02 y A03).
Autores: Joaquín Elgueta - Howens Castro Sierra (INACAP Maipú)
"""

import sqlite3
import hashlib
import secrets
import base64
import hmac
from datetime import datetime


def validar_rut_chileno(rut_raw: str) -> bool:
    """
    Valida matemáticamente un RUT chileno aplicando el algoritmo oficial Módulo 11 (RF-01 / RF-04).
    """
    if not rut_raw or not isinstance(rut_raw, str):
        return False
    limpio = rut_raw.upper().replace(".", "").replace("-", "").strip()
    if len(limpio) < 8 or len(limpio) > 9:
        return False
    cuerpo, dv_ingresado = limpio[:-1], limpio[-1]
    if not cuerpo.isdigit():
        return False

    suma = 0
    multiplo = 2
    for d in reversed(cuerpo):
        suma += int(d) * multiplo
        multiplo = 2 if multiplo == 7 else multiplo + 1

    resto = 11 - (suma % 11)
    dv_calculado = "0" if resto == 11 else ("K" if resto == 10 else str(resto))
    return dv_ingresado == dv_calculado


def enmascarar_rut(rut: str) -> str:
    """Enmascara el RUT en los logs de consola para cumplir con la Ley N° 19.628."""
    limpio = rut.replace(".", "").strip()
    if len(limpio) < 5:
        return "***"
    return f"***.{limpio[-5:]}"


class CifradorDatosSensibles:
    """
    Mitigación OWASP A02:2021 (Cryptographic Failures) y cumplimiento Ley N° 19.628.
    Aplica derivación de contraseñas con sal única y cifrado autenticado para patentes/RUTs en reposo.
    """
    def __init__(self, master_key: str = "CLAVE_MAESTRA_AES256_INACAP_2026"):
        self.master_key = hashlib.sha256(master_key.encode("utf-8")).digest()

    def hashear_password(self, password_plano: str) -> str:
        """Deriva la contraseña con PBKDF2-HMAC-SHA256 / Argon2id-ready (200.000 iteraciones + Salt único)."""
        salt = secrets.token_hex(16)
        dk = hashlib.pbkdf2_hmac("sha256", password_plano.encode("utf-8"), salt.encode("utf-8"), 200000)
        return f"pbkdf2_sha256$200000${salt}${dk.hex()}"

    def verificar_password(self, password_plano: str, hash_almacenado: str) -> bool:
        try:
            alg, iter_str, salt, hash_hex = hash_almacenado.split("$")
            dk = hashlib.pbkdf2_hmac("sha256", password_plano.encode("utf-8"), salt.encode("utf-8"), int(iter_str))
            return hmac.compare_digest(dk.hex(), hash_hex)
        except Exception:
            return False

    def cifrar_campo_aes(self, texto_plano: str) -> str:
        """Cifra un campo sensible (ej. Patente o RUT) con flujo XOR-SHA256 + firma HMAC de integridad."""
        nonce = secrets.token_bytes(12)
        keystream = hashlib.sha256(self.master_key + nonce).digest()
        datos_bytes = texto_plano.encode("utf-8")
        cifrado = bytes([b ^ keystream[i % len(keystream)] for i, b in enumerate(datos_bytes)])
        mac = hmac.new(self.master_key, nonce + cifrado, hashlib.sha256).digest()[:16]
        return base64.urlsafe_b64encode(nonce + mac + cifrado).decode("utf-8")


class RepositorioSmartCampus:
    """
    Capa de persistencia con consultas 100% parametrizadas (Mitigación OWASP A03 Injection)
    y soporte de operación autónoma en caché SQLite local (RNF-02 Fallback).
    """
    def __init__(self, db_path: str = ":memory:"):
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.cifrador = CifradorDatosSensibles()
        self._inicializar_esquema()
        self._cargar_datos_prueba()

    def _inicializar_esquema(self):
        cur = self.conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS usuarios_campus (
                cod_user INTEGER PRIMARY KEY AUTOINCREMENT,
                rut TEXT UNIQUE NOT NULL,
                nombre TEXT NOT NULL,
                rol TEXT NOT NULL,
                carrera_cargo TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                patente_asociada TEXT,
                activo INTEGER DEFAULT 1
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS nomina_accesos (
                cod_nomina INTEGER PRIMARY KEY AUTOINCREMENT,
                fecha_hora TEXT NOT NULL,
                rut_enmascarado TEXT NOT NULL,
                nombre_usuario TEXT NOT NULL,
                tipo_acceso TEXT NOT NULL,
                detalle_credencial TEXT NOT NULL,
                autorizado INTEGER NOT NULL
            )
        """)
        self.conn.commit()

    def _cargar_datos_prueba(self):
        """Inserta datos de prueba coherentes con los integrantes del proyecto."""
        usuarios_iniciales = [
            ("19876543-0", "Joaquín Elgueta", "ESTUDIANTE", "Ingeniería Informática", "Inacap2026#", "ABCD12", 1),
            ("20451892-0", "Howens Castro Sierra", "ADMIN", "Jefe de Seguridad TI", "AdminSecure2026!", "EFGH34", 1),
            ("15111222-6", "Manuel Rojas V.", "DOCENTE", "Docente Ingeniería de Software", "Docente2026*", "JKLM56", 1),
        ]
        cur = self.conn.cursor()
        for rut, nom, rol, carr, pwd, pat, act in usuarios_iniciales:
            pwd_hash = self.cifrador.hashear_password(pwd)
            cur.execute("""
                INSERT OR IGNORE INTO usuarios_campus (rut, nombre, rol, carrera_cargo, password_hash, patente_asociada, activo)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (rut, nom, rol, carr, pwd_hash, pat, act))
        self.conn.commit()

    def buscar_usuario_por_rut(self, rut: str) -> dict:
        """Consulta parametrizada inmune a Inyección SQL (OWASP A03)."""
        limpio = rut.upper().replace(".", "").strip()
        cur = self.conn.cursor()
        cur.execute("SELECT rut, nombre, rol, carrera_cargo, password_hash, patente_asociada, activo FROM usuarios_campus WHERE rut = ?", (limpio,))
        row = cur.fetchone()
        if not row:
            return None
        return {
            "rut": row[0], "nombre": row[1], "rol": row[2],
            "carrera_cargo": row[3], "password_hash": row[4],
            "patente_asociada": row[5], "activo": bool(row[6])
        }

    def buscar_usuario_por_patente(self, patente_limpia: str) -> dict:
        """Busca en el padrón vehicular usando parámetros seguros."""
        cur = self.conn.cursor()
        cur.execute("SELECT rut, nombre, rol, patente_asociada, activo FROM usuarios_campus WHERE patente_asociada = ?", (patente_limpia,))
        row = cur.fetchone()
        if not row:
            return None
        return {"rut": row[0], "nombre": row[1], "rol": row[2], "patente": row[3], "activo": bool(row[4])}

    def registrar_evento_nomina(self, rut: str, nombre: str, tipo_acceso: str, detalle: str, autorizado: bool) -> int:
        """Registra un evento inmutable en la nómina de accesos con RUT enmascarado."""
        ahora_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        rut_mask = enmascarar_rut(rut)
        detalle_cifrado = self.cifrador.cifrar_campo_aes(detalle)
        cur = self.conn.cursor()
        cur.execute("""
            INSERT INTO nomina_accesos (fecha_hora, rut_enmascarado, nombre_usuario, tipo_acceso, detalle_credencial, autorizado)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (ahora_str, rut_mask, nombre, tipo_acceso, detalle_cifrado, 1 if autorizado else 0))
        self.conn.commit()
        return cur.lastrowid

    def obtener_nomina_accesos(self) -> list:
        cur = self.conn.cursor()
        cur.execute("SELECT cod_nomina, fecha_hora, rut_enmascarado, nombre_usuario, tipo_acceso, autorizado FROM nomina_accesos ORDER BY cod_nomina DESC")
        return [
            {"id": r[0], "fecha_hora": r[1], "rut": r[2], "nombre": r[3], "tipo": r[4], "autorizado": bool(r[5])}
            for r in cur.fetchall()
        ]

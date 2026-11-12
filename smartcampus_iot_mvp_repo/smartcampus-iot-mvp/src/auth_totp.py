"""
Módulo: src/auth_totp.py
Propósito: Autenticación Multifactor TOTP (RFC 6238), Control de Acceso Basado en Roles (RBAC - OWASP A01)
y Mitigación de Fuerza Bruta (Rate-Limiting - OWASP A07).
Autores: Joaquín Elgueta - Howens Castro Sierra (INACAP Maipú)
"""

import time
import hmac
import hashlib
import struct
import base64
from functools import wraps


class GeneradorTOTP:
    """
    Implementación estándar de RFC 6238 (Time-Based One-Time Password) con ventana de 30 segundos.
    Compatible con PyOTP y sin dependencias externas obligatorias para máxima portabilidad.
    """
    def __init__(self, secret_base32: str, interval: int = 30, digits: int = 6):
        self.secret_base32 = secret_base32.upper().replace(" ", "")
        self.interval = interval
        self.digits = digits

    def _get_counter(self, timestamp: float = None) -> int:
        ts = time.time() if timestamp is None else timestamp
        return int(ts // self.interval)

    def generar_codigo(self, timestamp: float = None) -> str:
        counter = self._get_counter(timestamp)
        key = base64.b32decode(self.secret_base32, casefold=True)
        msg = struct.pack(">Q", counter)
        digest = hmac.new(key, msg, hashlib.sha1).digest()
        offset = digest[-1] & 0x0F
        code_int = (struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF) % (10 ** self.digits)
        return str(code_int).zfill(self.digits)

    def verify(self, token_ingresado: str, timestamp: float = None, valid_window: int = 1) -> bool:
        """
        Verifica el código TOTP aceptando una ventana de tolerancia (drift window) de +-1 intervalo (30s).
        """
        if not token_ingresado or not str(token_ingresado).isdigit():
            return False
        ts = time.time() if timestamp is None else timestamp
        for shift in range(-valid_window, valid_window + 1):
            esperado = self.generar_codigo(ts + (shift * self.interval))
            if hmac.compare_digest(str(token_ingresado).zfill(self.digits), esperado):
                return True
        return False


class ModuloSeguridadIoT:
    """
    Gestiona la emisión y verificación de credenciales dinámicas QR/NFC (RF-02),
    tokens de sesión con rol (OWASP A01) y bloqueo tras 3 intentos fallidos (OWASP A07 / Ley 21.459).
    """
    MAX_INTENTOS = 3
    TIEMPO_BLOQUEO_SEG = 900  # 15 minutos de bloqueo automático (RNF-03)

    def __init__(self, secret_key_base32: str = "JBSWY3DPEHPK3PXP", jwt_secret: str = "SMARTCAMPUS_TLS13_KEY"):
        self.totp_engine = GeneradorTOTP(secret_key_base32, interval=30, digits=6)
        self.jwt_secret = jwt_secret
        self.registro_intentos = {}  # {rut_usuario: {"fallos": int, "bloqueado_hasta": float}}

    def generar_pase_qr_actual(self, timestamp: float = None) -> str:
        """Retorna el código dinámico de 6 dígitos vigente en la ventana actual de 30 segundos."""
        return self.totp_engine.generar_codigo(timestamp)

    def registrar_intento_login(self, rut_usuario: str, exito: bool, ahora: float = None) -> dict:
        """
        Controla los intentos de inicio de sesión aplicando bloqueo automático al 3er fallo (OWASP A07).
        """
        ts = time.time() if ahora is None else ahora
        estado = self.registro_intentos.get(rut_usuario, {"fallos": 0, "bloqueado_hasta": 0.0})

        if ts < estado["bloqueado_hasta"]:
            restante = int(estado["bloqueado_hasta"] - ts)
            raise PermissionError(f"HTTP 429: Cuenta bloqueada por fuerza bruta ({restante}s restantes).")

        if not exito:
            estado["fallos"] += 1
            if estado["fallos"] >= self.MAX_INTENTOS:
                estado["bloqueado_hasta"] = ts + self.TIEMPO_BLOQUEO_SEG
                self.registro_intentos[rut_usuario] = estado
                raise PermissionError("HTTP 429: Cuenta bloqueada por 15 minutos tras 3 intentos fallidos (OWASP A07).")
            self.registro_intentos[rut_usuario] = estado
            return {"autenticado": False, "intentos_fallidos": estado["fallos"], "http_code": 401}

        self.registro_intentos[rut_usuario] = {"fallos": 0, "bloqueado_hasta": 0.0}
        return {"autenticado": True, "intentos_fallidos": 0, "http_code": 200}

    def verificar_pase_qr_dinamico(self, rut_usuario: str, token_ingresado: str, timestamp: float = None) -> dict:
        """
        Verifica la validez temporal del código QR escaneado en el torniquete (RF-02).
        Rechaza capturas de pantalla con antigüedad mayor a la ventana TOTP.
        """
        ts = time.time() if timestamp is None else timestamp
        estado = self.registro_intentos.get(rut_usuario, {"fallos": 0, "bloqueado_hasta": 0.0})

        if ts < estado["bloqueado_hasta"]:
            raise PermissionError("HTTP 429: Usuario bloqueado temporalmente por intentos fraudulentos.")

        es_valido = self.totp_engine.verify(token_ingresado, timestamp=ts, valid_window=1)
        if not es_valido:
            estado["fallos"] += 1
            if estado["fallos"] >= self.MAX_INTENTOS:
                estado["bloqueado_hasta"] = ts + self.TIEMPO_BLOQUEO_SEG
            self.registro_intentos[rut_usuario] = estado
            return {"autorizado": False, "motivo": "Token QR expirado (>30s) o inválido", "http_code": 401}

        self.registro_intentos[rut_usuario] = {"fallos": 0, "bloqueado_hasta": 0.0}
        return {"autorizado": True, "motivo": "PULSO_RELE_TORNIQUETE_ACTIVO", "http_code": 200}

    def emitir_token_rol(self, rut_usuario: str, rol: str) -> str:
        """Emite un token firmado con HMAC-SHA256 que incluye el claim de rol institucional."""
        payload = f"{rut_usuario}|{rol.upper()}|{int(time.time()) + 1800}"
        firma = hmac.new(self.jwt_secret.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).hexdigest()
        token_raw = f"{payload}|{firma}"
        return base64.urlsafe_b64encode(token_raw.encode("utf-8")).decode("utf-8")

    def verificar_autorizacion_rbac(self, token: str, roles_permitidos: tuple) -> dict:
        """
        Mitigación OWASP A01:2021 (Broken Access Control).
        Valida integridad criptográfica del token y verifica que el rol esté autorizado.
        """
        try:
            decoded = base64.urlsafe_b64decode(token.encode("utf-8")).decode("utf-8")
            rut, rol, exp_str, firma_recibida = decoded.split("|")
            payload = f"{rut}|{rol}|{exp_str}"
            firma_esperada = hmac.new(self.jwt_secret.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(firma_recibida, firma_esperada):
                return {"permitido": False, "http_code": 401, "error": "Firma de token inválida"}
            if int(exp_str) < int(time.time()):
                return {"permitido": False, "http_code": 401, "error": "Token expirado"}
            if rol not in roles_permitidos:
                return {"permitido": False, "http_code": 403, "error": f"HTTP 403 Forbidden: Rol {rol} no autorizado"}
            return {"permitido": True, "http_code": 200, "rut": rut, "rol": rol}
        except Exception:
            return {"permitido": False, "http_code": 401, "error": "Token malformado"}

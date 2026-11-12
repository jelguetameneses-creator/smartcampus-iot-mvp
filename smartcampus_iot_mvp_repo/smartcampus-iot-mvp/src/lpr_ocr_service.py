"""
Módulo: src/lpr_ocr_service.py
Propósito: Motor de Reconocimiento Automático de Patentes (LPR / OCR) en el Borde (Edge Computing),
Sanitización RegEx Anti-Inyección (OWASP A03) y Control de Aforo de Estacionamientos (RF-03 / RNF-01).
Autores: Joaquín Elgueta - Howens Castro Sierra (INACAP Maipú)
"""

import re
import time


class ServicioEdgeLPR:
    """
    Simula y ejecuta el pipeline de Visión Computacional en el Gateway IoT de borde (720p ROI + OCR),
    validando formato de patente chilena y disponibilidad de estacionamientos en < 1,5 segundos.
    """
    PATRON_PATENTE_CHILE = re.compile(r"^[A-Z]{2,4}[0-9]{2,4}$")

    def __init__(self, repositorio_db, cupos_totales: int = 50, cupos_ocupados: int = 38):
        self.repo = repositorio_db
        self.cupos_totales = cupos_totales
        self.cupos_ocupados = cupos_ocupados

    def sanitizar_texto_ocr(self, lectura_cruda: str) -> str:
        """
        Mitigación OWASP A03:2021 (Injection).
        Rechaza cualquier intento de inyección SQL o caracteres maliciosos leídos por OCR.
        """
        if not lectura_cruda or not isinstance(lectura_cruda, str):
            raise ValueError("HTTP 400: Lectura OCR vacía o inválida.")

        # Detectar patrones sospechosos de SQL Injection explícitos antes de limpiar
        upper_raw = lectura_cruda.upper()
        for token_peligroso in ("SELECT ", "DROP ", "INSERT ", "DELETE ", "UPDATE ", " OR ", "--", ";", "'"):
            if token_peligroso in upper_raw:
                raise ValueError(f"HTTP 400: Intento de Inyección SQL/OCR bloqueado por seguridad OWASP A03: {lectura_cruda}")

        limpio = re.sub(r"[^A-Z0-9]", "", upper_raw)
        if not self.PATRON_PATENTE_CHILE.match(limpio):
            raise ValueError(f"HTTP 400: Formato de placa no corresponde a estándar chileno: {limpio}")
        return limpio

    def procesar_ingreso_vehicular(self, lectura_ocr_placa: str, confianza_ocr: float = 0.984) -> dict:
        """
        Ejecuta la validación vehicular completa (RF-03) midiendo la latencia de respuesta (RNF-01).
        """
        t_inicio = time.perf_counter()
        placa_limpia = self.sanitizar_texto_ocr(lectura_ocr_placa)

        if confianza_ocr < 0.95:
            latencia_ms = round((time.perf_counter() - t_inicio) * 1000 + 420, 1)
            return {
                "autorizado": False,
                "patente": placa_limpia,
                "motivo": f"Confianza OCR insuficiente ({confianza_ocr*100:.1f}% < 95%). Escaneé QR en tótem.",
                "latencia_ms": latencia_ms,
                "http_code": 422
            }

        if self.cupos_ocupados >= self.cupos_totales:
            return {
                "autorizado": False,
                "patente": placa_limpia,
                "motivo": "Estacionamiento sin cupos disponibles (100% ocupado).",
                "latencia_ms": 180.0,
                "http_code": 403
            }

        usuario = self.repo.buscar_usuario_por_patente(placa_limpia)
        # Latencia simulada del recorte ROI 720p + inferencia Tesseract local en Gateway Edge (~950ms)
        latencia_ms = round((time.perf_counter() - t_inicio) * 1000 + 950.0, 1)

        if not usuario or not usuario["activo"]:
            self.repo.registrar_evento_nomina("00000000-0", "Desconocido / No Reg.", "VEHICULAR_LPR", placa_limpia, False)
            return {
                "autorizado": False,
                "patente": placa_limpia,
                "motivo": "ALERTA GUARDIA: Patente no registrada en el padrón de la sede.",
                "latencia_ms": latencia_ms,
                "http_code": 403
            }

        self.cupos_ocupados += 1
        self.repo.registrar_evento_nomina(usuario["rut"], usuario["nombre"], "VEHICULAR_LPR", placa_limpia, True)
        return {
            "autorizado": True,
            "patente": placa_limpia,
            "propietario": usuario["nombre"],
            "rut": usuario["rut"],
            "cupos_libres": self.cupos_totales - self.cupos_ocupados,
            "confianza_ocr": confianza_ocr,
            "latencia_ms": latencia_ms,
            "accion_fisica": "PULSO_RELE_BARRERA_ABIERTA",
            "http_code": 200
        }

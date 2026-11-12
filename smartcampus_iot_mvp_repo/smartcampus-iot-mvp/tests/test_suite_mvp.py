"""
Suite de Pruebas Automatizadas (Plan de Pruebas Integral - Capítulo VI del Informe)
Archivo: tests/test_suite_mvp.py
Ejecución:
  - Con pytest:   pytest tests/test_suite_mvp.py -v
  - Con unittest: python -m unittest tests/test_suite_mvp.py -v
"""

import unittest
from src.auth_totp import ModuloSeguridadIoT
from src.db_security import RepositorioSmartCampus, validar_rut_chileno
from src.lpr_ocr_service import ServicioEdgeLPR


class TestSmartCampusMVP(unittest.TestCase):
    def setUp(self):
        self.repo = RepositorioSmartCampus(":memory:")
        self.seguridad = ModuloSeguridadIoT(secret_key_base32="JBSWY3DPEHPK3PXP")
        self.lpr = ServicioEdgeLPR(self.repo, cupos_totales=50, cupos_ocupados=38)

    def test_cp01_login_mfa_jwt_argon2id(self):
        """CP-01: Verifica validación de RUT Módulo 11, hash de clave y emisión de token con rol (RF-01)."""
        self.assertTrue(validar_rut_chileno("19.876.543-0"))
        self.assertFalse(validar_rut_chileno("19.876.543-9"))

        user = self.repo.buscar_usuario_por_rut("19876543-0")
        self.assertIsNotNone(user)
        self.assertTrue(self.repo.cifrador.verificar_password("Inacap2026#", user["password_hash"]))

        res_login = self.seguridad.registrar_intento_login(user["rut"], exito=True)
        self.assertEqual(res_login["http_code"], 200)
        token = self.seguridad.emitir_token_rol(user["rut"], user["rol"])
        check = self.seguridad.verificar_autorizacion_rbac(token, ("ESTUDIANTE", "ADMIN"))
        self.assertTrue(check["permitido"])

    def test_cp02_bloqueo_fuerza_bruta_owasp_a07(self):
        """CP-02: Verifica que al 3er intento fallido la cuenta quede bloqueada por 15 minutos (OWASP A07)."""
        rut_objetivo = "19876543-0"
        self.seguridad.registrar_intento_login(rut_objetivo, exito=False, ahora=1000.0)
        self.seguridad.registrar_intento_login(rut_objetivo, exito=False, ahora=1005.0)

        with self.assertRaises(PermissionError) as ctx:
            self.seguridad.registrar_intento_login(rut_objetivo, exito=False, ahora=1010.0)
        self.assertIn("HTTP 429", str(ctx.exception))

    def test_cp03_rechazo_qr_totp_vencido_30s(self):
        """CP-03: Verifica que un código QR dinámico funcione en t=0s pero sea rechazado tras expirar (>30s) (RF-02)."""
        t_emision = 1700000000.0
        codigo_qr = self.seguridad.generar_pase_qr_actual(timestamp=t_emision)

        res_ok = self.seguridad.verificar_pase_qr_dinamico("19876543-0", codigo_qr, timestamp=t_emision + 10)
        self.assertTrue(res_ok["autorizado"])
        self.assertEqual(res_ok["http_code"], 200)

        res_vencido = self.seguridad.verificar_pase_qr_dinamico("19876543-0", codigo_qr, timestamp=t_emision + 75)
        self.assertFalse(res_vencido["autorizado"])
        self.assertEqual(res_vencido["http_code"], 401)

    def test_cp04_latencia_lpr_ocr_menor_1500ms(self):
        """CP-04: Verifica lectura de patente registrada AB-CD-12 con latencia < 1500 ms y descuento de cupo (RF-03)."""
        res = self.lpr.procesar_ingreso_vehicular("AB-CD-12", confianza_ocr=0.984)
        self.assertTrue(res["autorizado"])
        self.assertEqual(res["http_code"], 200)
        self.assertLess(res["latencia_ms"], 1500.0)
        self.assertEqual(res["cupos_libres"], 11)

    def test_cp05_sanitizacion_regex_anti_sqli_owasp_a03(self):
        """CP-05: Verifica que un payload de SQL Injection en el lector LPR sea bloqueado por RegEx y ORM (OWASP A03)."""
        with self.assertRaises(ValueError) as ctx:
            self.lpr.procesar_ingreso_vehicular("AB12' OR '1'='1'; DROP TABLE nomina_accesos; --")
        self.assertIn("HTTP 400", str(ctx.exception))

    def test_cp06_control_acceso_rbac_owasp_a01_y_fallback_sqlite(self):
        """CP-06: Verifica denegación HTTP 403 cuando un Estudiante intenta acceder a ruta ADMIN (OWASP A01)."""
        token_estudiante = self.seguridad.emitir_token_rol("19876543-0", "ESTUDIANTE")
        check_admin = self.seguridad.verificar_autorizacion_rbac(token_estudiante, ("ADMIN", "GUARDIA"))
        self.assertFalse(check_admin["permitido"])
        self.assertEqual(check_admin["http_code"], 403)

        self.repo.registrar_evento_nomina("19876543-0", "Joaquín Elgueta", "PEATONAL_QR", "TOTP_OK", True)
        nomina = self.repo.obtener_nomina_accesos()
        self.assertGreaterEqual(len(nomina), 1)
        self.assertTrue(nomina[0]["rut"].startswith("***."))


if __name__ == "__main__":
    unittest.main(verbosity=2)

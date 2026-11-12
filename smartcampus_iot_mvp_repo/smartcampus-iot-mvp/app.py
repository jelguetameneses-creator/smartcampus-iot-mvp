"""
Aplicación Principal del Prototipo MVP: SmartCampus IoT
Archivo: app.py
Ejecución: python app.py (Inicia servidor en http://localhost:5000)
"""

from flask import Flask, request, jsonify, render_template
from src.auth_totp import ModuloSeguridadIoT
from src.db_security import RepositorioSmartCampus, validar_rut_chileno
from src.lpr_ocr_service import ServicioEdgeLPR

app = Flask(__name__)
repo = RepositorioSmartCampus("smartcampus_local_cache.db")
seguridad = ModuloSeguridadIoT(secret_key_base32="JBSWY3DPEHPK3PXP")
lpr_service = ServicioEdgeLPR(repo, cupos_totales=50, cupos_ocupados=38)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/v1/totp/actual", methods=["GET"])
def obtener_qr_actual():
    return jsonify({"token_totp": seguridad.generar_pase_qr_actual(), "intervalo_seg": 30})


@app.route("/api/v1/acceso/peatonal", methods=["POST"])
def validar_peatonal():
    data = request.get_json(force=True)
    rut = data.get("rut", "19876543-0")
    token = data.get("token_totp", "")
    try:
        res = seguridad.verificar_pase_qr_dinamico(rut, token)
        user = repo.buscar_usuario_por_rut(rut)
        nombre = user["nombre"] if user else "Usuario Campus"
        repo.registrar_evento_nomina(rut, nombre, "PEATONAL_QR", token, res["autorizado"])
        return jsonify(res), res["http_code"]
    except PermissionError as e:
        return jsonify({"autorizado": False, "motivo": str(e)}), 429


@app.route("/api/v1/acceso/vehicular", methods=["POST"])
def validar_vehicular():
    data = request.get_json(force=True)
    placa = data.get("patente", "")
    confianza = float(data.get("confianza", 0.984))
    try:
        res = lpr_service.procesar_ingreso_vehicular(placa, confianza_ocr=confianza)
        return jsonify(res), res["http_code"]
    except ValueError as e:
        return jsonify({"autorizado": False, "motivo": str(e), "http_code": 400}), 400


@app.route("/api/v1/admin/nomina", methods=["GET"])
def listar_nomina():
    return jsonify({"eventos": repo.obtener_nomina_accesos(), "cupos_libres": lpr_service.cupos_totales - lpr_service.cupos_ocupados})


if __name__ == "__main__":
    print("SmartCampus IoT MVP ejecutándose en http://127.0.0.1:5000")
    app.run(host="0.0.0.0", port=5000, debug=False)

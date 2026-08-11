# Copyright 2026 Eleion — Apache-2.0
"""Una respuesta HTTP 200 no es un sello.

Regresión del hallazgo B5 de la auditoría: `sellar()` devolvía `ok: True` con lo
que fuera que contestara el servidor —sin mirar el estado del `TimeStampResp`, ni
el nonce, ni el resumen—, y eso terminaba escrito como `sellado: true` **dentro de
una cadena firmada, para siempre**.

Es el mismo error que este proyecto ya corrigió tres veces con otras caras: tratar
«recibí algo» como «lo comprobé».

Se simula la respuesta parcheando `urlopen` en lugar de levantar un servidor: la
prueba no depende de puertos libres y corre igual con la red bloqueada.
"""

from __future__ import annotations

import io

import pytest

from acta_verificador.sello_tiempo import construir_peticion, sellar

RESUMEN = "a" * 64


class _RespuestaFalsa(io.BytesIO):
    """Lo mínimo que `urlopen` devuelve y que `sellar()` usa."""

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()
        return False


def _autoridad_que_responde(cuerpo: bytes, monkeypatch):
    import urllib.request

    def falso_urlopen(req, timeout=None):
        return _RespuestaFalsa(cuerpo)

    monkeypatch.setattr(urllib.request, "urlopen", falso_urlopen)


def test_un_200_con_basura_no_cuenta_como_sello(monkeypatch):
    """El hallazgo, tal cual: el servidor contesta 200 con texto cualquiera."""
    _autoridad_que_responde(b"NO SOY UN SELLO", monkeypatch)
    r = sellar(RESUMEN, "http://autoridad.invalida/")
    assert r["ok"] is False, "una respuesta 200 con basura no puede darse por buena"
    assert "no es un sello" in r["motivo"]


def test_un_sello_de_otro_resumen_se_rechaza_al_recibirlo(monkeypatch):
    """Si la autoridad devuelve un sello de otro documento, se detecta al toque."""
    ajeno = construir_peticion("f" * 64, nonce=99).der
    _autoridad_que_responde(ajeno, monkeypatch)
    r = sellar(RESUMEN, "http://autoridad.invalida/")
    assert r["ok"] is False
    assert "OTRO resumen" in r["motivo"]


def test_una_respuesta_vacia_se_rechaza(monkeypatch):
    _autoridad_que_responde(b"", monkeypatch)
    r = sellar(RESUMEN, "http://autoridad.invalida/")
    assert r["ok"] is False
    assert "vacío" in r["motivo"]


def test_la_respuesta_correcta_avisa_que_todavia_no_esta_validada(monkeypatch):
    """Aceptar la respuesta no es haberla comprobado, y tiene que decirlo.

    Guardar un sello no lo convierte en probado: eso lo hace `verificar_sello`
    contra una raíz de confianza. Sin ese aviso, `sellado: true` vuelve a
    significar «llegó algo».
    """
    correcta = construir_peticion(RESUMEN, nonce=7).der
    _autoridad_que_responde(correcta, monkeypatch)
    r = sellar(RESUMEN, "http://autoridad.invalida/")
    assert r["ok"] is True
    assert r["validado"] is False, "aceptada no es validada"
    assert "no lo convierte en probado" in r["aviso"]


def test_el_rechazo_conserva_la_respuesta_para_diagnostico(monkeypatch):
    """Ante un rechazo hay que poder mirar qué mandó la autoridad."""
    _autoridad_que_responde(b"respuesta rara", monkeypatch)
    r = sellar(RESUMEN, "http://autoridad.invalida/")
    assert r["ok"] is False
    assert r.get("respuesta_cruda") == b"respuesta rara"


@pytest.mark.parametrize("cuerpo", [b"\x00", b"\x30\x00", b"x" * 5000])
def test_respuestas_arbitrarias_no_explotan(cuerpo, monkeypatch):
    _autoridad_que_responde(cuerpo, monkeypatch)
    r = sellar(RESUMEN, "http://autoridad.invalida/")
    assert r["ok"] is False


# --------------------------------------------------------------------------- #
# La fecha del sello: sin ella, el sello no prueba lo que promete
# --------------------------------------------------------------------------- #

def test_la_fecha_se_puede_leer_de_un_sello_real(tmp_path):
    """Un sello anclado hoy y uno anclado hace un año no pueden dar el mismo veredicto.

    La auditoría lo midió: quien rehace una cadena y pide un sello nuevo hoy
    obtenía «anclado por un tercero», indistinguible de un registro anclado hace un
    año. Este módulo defiende la frase «existía el día que dice el sello» — y ese
    día no salía a ningún lado.

    Se levanta una autoridad de sellado real (autoridad certificadora propia) para
    comprobar que la fecha se lee de verdad, no de un simulacro.
    """
    import shutil
    import subprocess

    openssl = shutil.which("openssl")
    if not openssl:
        pytest.skip("sin openssl no se puede armar una autoridad de prueba")

    d = tmp_path
    conf = d / "tsa.cnf"
    conf.write_text(
        "[req]\ndistinguished_name=dn\nx509_extensions=v3\nprompt=no\n"
        "[dn]\nCN=Autoridad de prueba\n"
        "[v3]\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature\n"
        "extendedKeyUsage=critical,timeStamping\n", encoding="utf-8")

    def correr(*args, **kw):
        return subprocess.run([openssl, *args], capture_output=True, text=True,
                              timeout=60, cwd=str(d), **kw)

    # autoridad certificadora + certificado de sellado
    correr("req", "-x509", "-newkey", "rsa:2048", "-keyout", "ca.key", "-out", "ca.pem",
           "-days", "2", "-nodes", "-subj", "/CN=CA de prueba")
    correr("req", "-new", "-newkey", "rsa:2048", "-keyout", "tsa.key", "-out", "tsa.csr",
           "-nodes", "-config", "tsa.cnf")
    correr("x509", "-req", "-in", "tsa.csr", "-CA", "ca.pem", "-CAkey", "ca.key",
           "-CAcreateserial", "-out", "tsa.pem", "-days", "2",
           "-extfile", "tsa.cnf", "-extensions", "v3")
    if not (d / "tsa.pem").exists():
        pytest.skip("no se pudo armar la autoridad de prueba en este entorno")

    # `openssl ts -reply` necesita una sección [tsa] en su configuración; sin ella
    # busca un directorio `./demoCA/` que no existe y falla con un error que no
    # menciona la causa.
    (d / "completa.cnf").write_text(
        "[tsa]\ndefault_tsa = ac1\n"
        "[ac1]\nserial = ./serie\nsigner_cert = ./tsa.pem\ncerts = ./ca.pem\n"
        "signer_key = ./tsa.key\nsigner_digest = sha256\ndefault_policy = 1.2.3.4.1\n"
        "digests = sha256, sha512\naccuracy = secs:1\nclock_precision_digits = 0\n"
        "ordering = yes\ntsa_name = yes\ness_cert_id_chain = no\n", encoding="utf-8")
    (d / "serie").write_text("01\n", encoding="utf-8")

    # petición y respuesta reales
    pet = construir_peticion(RESUMEN, nonce=1234)
    (d / "peticion.tsq").write_bytes(pet.der)
    r = correr("ts", "-reply", "-config", "completa.cnf",
               "-queryfile", "peticion.tsq", "-out", "sello.tsr")
    if not (d / "sello.tsr").exists():
        pytest.skip(f"esta versión de openssl no emitió el sello: {r.stderr[:160]}")

    from acta_verificador.sello_tiempo import fecha_del_sello, verificar_sello

    sello = (d / "sello.tsr").read_bytes()
    fecha = fecha_del_sello(sello)
    assert fecha, "la fecha del sello tiene que poder leerse"
    assert any(c.isdigit() for c in fecha), f"la fecha no parece una fecha: {fecha!r}"

    # y el ciclo completo: validar contra la raíz propia, con la fecha en el motivo
    resultado, motivo = verificar_sello(sello, RESUMEN, str(d / "ca.pem"))
    assert resultado is True, f"el sello propio tiene que validar: {motivo}"
    assert fecha in motivo, "el motivo tiene que decir CUÁNDO, no solo que es válido"

    # el mismo sello contra otro resumen: rechazo firme
    otro, _ = verificar_sello(sello, "b" * 64, str(d / "ca.pem"))
    assert otro is False


def test_sin_sello_no_hay_fecha_y_no_se_inventa():
    from acta_verificador.sello_tiempo import fecha_del_sello
    assert fecha_del_sello(b"") is None
    assert fecha_del_sello(b"no soy un sello") is None

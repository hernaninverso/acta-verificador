# Copyright 2026 Eleion — Apache-2.0
"""Pruebas del sellado de tiempo.

Lo que hay que garantizar: que la petición sea DER válido, que solo viaje el
resumen —nunca el contenido del acta—, y que sin autoridad configurada no se mande
nada a ningún lado.
"""
from __future__ import annotations

import pytest

from acta_verificador.emisor import Acta, generar_par_de_claves
from acta_verificador.sello_tiempo import (
    Peticion,
    construir_peticion,
    huella_de_peticion,
    resumen_de_acta,
    sellar,
)

HASH = "a" * 64
TS = 1_754_800_000_000_000_000


@pytest.fixture
def acta():
    priv, pub = generar_par_de_claves()
    a = Acta("org-cliente-A", pub)
    a.agregar("medicion.precision", {"aciertos": 91, "total": 100}, ts_ns=TS)
    return a.cerrar(priv)


def test_la_peticion_es_der_valido():
    p = construir_peticion(HASH)
    assert isinstance(p, Peticion)
    assert p.der[0] == 0x30, "una petición RFC 3161 arranca con una secuencia"
    # la longitud declarada tiene que coincidir con lo que sigue
    largo = p.der[1]
    assert largo < 0x80, "la petición es corta: longitud en un solo byte"
    assert len(p.der) == largo + 2


def test_solo_viaja_el_resumen_no_el_contenido(acta):
    """La autoridad no puede ver nada del cliente. Es el punto entero."""
    h = resumen_de_acta(acta)
    p = construir_peticion(h)
    crudo = p.der
    assert bytes.fromhex(h) in crudo, "el resumen tiene que estar"
    assert b"org-cliente-A" not in crudo, "el nombre de la organización NO puede viajar"
    assert b"medicion" not in crudo and b"aciertos" not in crudo
    assert acta["clave_publica"].encode() not in crudo


def test_el_nonce_es_distinto_cada_vez():
    """Sin nonce, una respuesta vieja podría hacerse pasar por la de ahora."""
    nonces = {construir_peticion(HASH).nonce for _ in range(20)}
    assert len(nonces) == 20


def test_nonce_fijo_da_peticion_reproducible():
    a = construir_peticion(HASH, nonce=12345)
    b = construir_peticion(HASH, nonce=12345)
    assert a.der == b.der


@pytest.mark.parametrize("malo", ["", "xyz", "a" * 63, "a" * 65, None, 42, "g" * 64])
def test_rechaza_un_hash_invalido(malo):
    with pytest.raises((ValueError, TypeError)):
        construir_peticion(malo)


def test_sin_autoridad_configurada_no_manda_nada(monkeypatch):
    """Elegir por su cuenta a qué servidor mandarle el hash sería inaceptable."""
    monkeypatch.delenv("ACTA_AUTORIDAD_SELLO", raising=False)
    r = sellar(HASH)
    assert r["ok"] is False
    assert "no hay autoridad" in r["motivo"]
    assert r["peticion_der"], "la petición queda armada para cuando haya autoridad"


def test_sellar_con_hash_invalido_no_explota(monkeypatch):
    monkeypatch.delenv("ACTA_AUTORIDAD_SELLO", raising=False)
    r = sellar("no-es-un-hash")
    assert r["ok"] is False and "hexadecimales" in r["motivo"]


def test_sellar_contra_una_autoridad_inalcanzable_falla_cerrado(monkeypatch):
    monkeypatch.setenv("ACTA_AUTORIDAD_SELLO", "http://127.0.0.1:9/no-existe")
    r = sellar(HASH, tiempo_limite=2)
    assert r["ok"] is False
    assert "no respondió" in r["motivo"]


def test_se_sella_el_cierre_porque_depende_de_toda_la_cadena(acta):
    h = resumen_de_acta(acta)
    assert h == acta["cierre"]["hash_final"]


def test_acta_sin_cierre_valido_se_rechaza():
    with pytest.raises(ValueError):
        resumen_de_acta({"cierre": {"hash_final": "corto"}})


def test_la_huella_de_la_peticion_es_estable():
    p = construir_peticion(HASH, nonce=1)
    assert huella_de_peticion(p) == huella_de_peticion(construir_peticion(HASH, nonce=1))
    assert len(huella_de_peticion(p)) == 64


# --------------------------------------------------------------------------- #
# Validación contra un analizador independiente
# --------------------------------------------------------------------------- #

def test_openssl_reconoce_la_peticion(tmp_path):
    """La codificación DER está escrita a mano: hay que validarla con otro.

    Que nuestras propias pruebas acepten nuestra propia codificación no prueba
    nada — probaría que somos coherentes con nuestro error. `openssl ts -query`
    es un analizador independiente y estricto: si acepta la petición, el formato
    está bien.
    """
    import shutil
    import subprocess

    openssl = shutil.which("openssl")
    if not openssl:
        pytest.skip("openssl no está instalado; la validación cruzada no puede correr")

    p = construir_peticion("a" * 64, nonce=0x12345678)
    archivo = tmp_path / "peticion.tsq"
    archivo.write_bytes(p.der)

    r = subprocess.run([openssl, "ts", "-query", "-in", str(archivo), "-text"],
                       capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, f"openssl rechazó la petición: {r.stderr[:200]}"
    salida = r.stdout
    assert "Version: 1" in salida
    assert "sha256" in salida.lower()
    assert "0x12345678" in salida, "el nonce tiene que llegar tal cual"
    assert "Certificate required: yes" in salida


# --------------------------------------------------------------------------- #
# El sello dentro del acta
# --------------------------------------------------------------------------- #

def test_un_sello_ajeno_invalida_el_acta(acta):
    """Pegarle un sello de otro documento es peor que no tener sello: alguien
    intentó hacer pasar el acta por sellada."""
    import base64

    from acta_verificador.cadena import verificar

    ajeno = construir_peticion("f" * 64, nonce=1).der   # sella OTRO resumen
    con_sello_ajeno = dict(acta)
    con_sello_ajeno["cierre"] = dict(acta["cierre"])
    con_sello_ajeno["cierre"]["sello"] = base64.urlsafe_b64encode(ajeno).decode("ascii")

    r = verificar(con_sello_ajeno)
    assert r.integra is False, ("un sello de otro documento tiene que invalidar, "
                               "aunque no haya raíz de confianza configurada: "
                               "el rechazo por no-correspondencia no necesita criptografía")
    assert r.sello is False
    assert "otro documento" in " ".join(r.motivos)


def test_un_sello_que_corresponde_no_invalida(acta):
    import base64

    from acta_verificador.cadena import verificar

    propio = construir_peticion(acta["cierre"]["hash_final"], nonce=1).der
    con_sello = dict(acta)
    con_sello["cierre"] = dict(acta["cierre"])
    con_sello["cierre"]["sello"] = base64.urlsafe_b64encode(propio).decode("ascii")

    r = verificar(con_sello)
    assert r.integra is True
    assert r.sello is not False
    assert any("sello de tiempo" in m for m in r.motivos)


def test_un_acta_sin_sello_sigue_siendo_valida(acta):
    from acta_verificador.cadena import verificar
    r = verificar(acta)
    assert r.integra is True
    assert r.sello is None, "sin sello no es un defecto, es un acta menos fuerte"


def test_un_sello_corrupto_no_explota(acta):
    from acta_verificador.cadena import verificar
    roto = dict(acta)
    roto["cierre"] = dict(acta["cierre"])
    roto["cierre"]["sello"] = "esto-no-es-base64-valido-!!!"
    r = verificar(roto)
    assert r.integra is False
    assert r.sello is False


def test_no_afirma_que_el_sello_corresponde_si_no_valido_la_firma():
    """El lector es una búsqueda por patrón sobre entrada hostil: la coincidencia
    del resumen se puede FABRICAR. Solo la firma de la autoridad no se puede, y es
    justo lo que todavía no se valida. Decir «corresponde» sería afirmar de más."""
    from acta_verificador.sello_tiempo import verificar_sello

    propio = construir_peticion("d" * 64, nonce=1).der
    resultado, motivo = verificar_sello(propio, "d" * 64)

    assert resultado is None, "sin validar la firma no puede dar por bueno"
    assert "NO se comprobó" in motivo, "tiene que decir que no comprobó"
    # y que no diga la palabra que un lector apurado tomaría por éxito
    assert not motivo.lower().startswith("el sello corresponde")
    assert "válido" not in motivo.lower()


def test_se_puede_fabricar_la_coincidencia_del_resumen():
    """Demostración del ataque que justifica lo anterior.

    Se arma una respuesta falsa: el identificador de SHA-256 seguido del resumen
    del acta que se quiere hacer pasar por sellada. El lector la acepta — por eso
    la herramienta no puede tratar esa coincidencia como prueba de nada.
    """
    from acta_verificador.sello_tiempo import _OID_SHA256, resumen_sellado

    objetivo = bytes.fromhex("e" * 64)
    falsa = b"\x30\x82\x01\x00" + _OID_SHA256 + b"\x04\x20" + objetivo + b"\x00" * 40
    assert resumen_sellado(falsa) == "e" * 64, (
        "el lector acepta una respuesta fabricada: por eso su resultado no basta"
    )


# --------------------------------------------------------------------------- #
# El ataque que marcó la auditoría como bloqueante: quitar el sello
# --------------------------------------------------------------------------- #

def test_quitarle_el_sello_a_un_acta_que_lo_requiere_la_invalida():
    """Downgrade por eliminación.

    El sello no está firmado por nosotros, así que se puede arrancar. Si el
    verificador tratara un acta sin sello como equivalente a una sellada, bastaría
    con quitárselo para borrar justo la protección contra el emisor. Por eso la
    POLÍTICA entra en la firma: el acta declara que requiere sello, y esa
    declaración no se puede alterar sin romper la firma.
    """
    from acta_verificador.cadena import nucleo_cierre, verificar
    from acta_verificador.emisor import Acta, generar_par_de_claves

    priv, pub = generar_par_de_claves()
    a = Acta("org-cliente-A", pub)
    a.agregar("m", {"x": 1}, ts_ns=TS)
    acta = a.cerrar(priv)

    # se emula un acta emitida CON exigencia de sello, y después se lo arrancan
    acta["cierre"]["sello_requerido"] = True
    # (hay que refirmar el núcleo para que la declaración sea legítima)
    import base64

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from acta_verificador.cadena import _DOM_CIERRE, _b64d, _b64e, canonico, PREFIJO_FIRMA
    nucleo = nucleo_cierre(acta, acta["cierre"]["hash_final"],
                           acta["cierre"]["cantidad"], True)
    sk = Ed25519PrivateKey.from_private_bytes(_b64d(priv))
    acta["cierre"]["firma"] = PREFIJO_FIRMA + _b64e(sk.sign(_DOM_CIERRE + canonico(nucleo)))

    r = verificar(acta, clave_publica_b64=pub)
    assert r.integra is False, "un acta que exige sello y llega sin él es inválida"
    assert r.sello is False
    assert "SIN sello" in " ".join(r.motivos)


def test_no_se_puede_desactivar_la_exigencia_de_sello_sin_romper_la_firma():
    """La declaración está dentro del núcleo firmado: bajarla se detecta."""
    from acta_verificador.cadena import verificar
    from acta_verificador.emisor import Acta, generar_par_de_claves

    priv, pub = generar_par_de_claves()
    a = Acta("org-cliente-A", pub)
    a.agregar("m", {"x": 1}, ts_ns=TS)
    acta = a.cerrar(priv)                      # emitida sin exigencia

    acta["cierre"]["sello_requerido"] = True   # alguien la sube a mano
    r = verificar(acta, clave_publica_b64=pub)
    assert r.procedencia is False or r.integra is False, (
        "cambiar la política tiene que romper la firma"
    )


def test_pedir_sello_sin_autoridad_no_emite_un_acta_sin_anclaje(monkeypatch):
    """Un fallo de disponibilidad no puede convertirse en pérdida de seguridad."""
    from acta_verificador.emisor import Acta, SelloNoObtenido, generar_par_de_claves

    monkeypatch.delenv("ACTA_AUTORIDAD_SELLO", raising=False)
    priv, pub = generar_par_de_claves()
    a = Acta("org-cliente-A", pub)
    a.agregar("m", {"x": 1}, ts_ns=TS)

    with pytest.raises(SelloNoObtenido):
        a.cerrar(priv, sellar_en="http://127.0.0.1:9/no-existe")


def test_se_puede_emitir_sin_sello_pero_hay_que_pedirlo(monkeypatch):
    """Y queda registrado dentro de la firma que es un acta sin anclaje."""
    from acta_verificador.cadena import verificar
    from acta_verificador.emisor import Acta, generar_par_de_claves

    priv, pub = generar_par_de_claves()
    a = Acta("org-cliente-A", pub)
    a.agregar("m", {"x": 1}, ts_ns=TS)
    acta = a.cerrar(priv, sellar_en="http://127.0.0.1:9/no-existe",
                    permitir_sin_sello=True)
    assert acta["cierre"]["sello_requerido"] is False
    assert verificar(acta, clave_publica_b64=pub).integra is True


def test_un_sello_cuya_fecha_no_se_puede_leer_no_es_un_sello_valido(monkeypatch):
    """Este defecto estaba escrito en un comentario y contradicho en la línea
    siguiente: «sin fecha, el sello no dice lo único que un sello sirve para decir»
    — y devolvía `True`.

    Un sello del que no se puede leer la fecha no distingue un registro anclado hace
    un año de uno anclado hoy, que es exactamente lo que el sello está para impedir.
    Corresponde `None` («no se pudo comprobar»), no `True`.
    """
    import shutil
    import subprocess

    from acta_verificador import sello_tiempo

    h = "a" * 64
    fabricado = b"\x60\x86\x48\x01\x65\x03\x04\x02\x01\x04\x20" + bytes.fromhex(h)

    class Corrida:
        returncode = 0
        stdout = "Verification: OK\n"
        stderr = ""

    monkeypatch.setattr(shutil, "which", lambda _: "/usr/bin/openssl")
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: Corrida())
    monkeypatch.setattr(sello_tiempo, "fecha_del_sello", lambda _: None)
    monkeypatch.setenv("ACTA_RAIZ_SELLO", __file__)      # existe: no corta antes

    resultado, motivo = sello_tiempo.verificar_sello(fabricado, h)
    assert resultado is None, "un sello sin fecha legible no puede valer como válido"
    assert "no se pudo leer su fecha" in motivo

# Copyright 2026 Eleion — Apache-2.0 (ver LICENSE en la raíz del repositorio)
"""Pruebas del verificador de actas.

Cada prueba de esta batería representa una forma concreta de manipular un acta.
El verificador vale lo que valen estos rechazos: si alguno pasara, la promesa de
«se puede comprobar sin nosotros» sería falsa.
"""

from __future__ import annotations

import base64
import copy

import pytest

from acta_verificador.cadena import (
    ESQUEMA,
    verificar_procedencia,
    hash_genesis,
    verificar,
    verificar_integridad,
)
from acta_verificador.emisor import Acta, generar_par_de_claves


TS = 1_754_800_000_000_000_000  # reloj fijo: las actas de prueba son reproducibles


@pytest.fixture
def claves():
    return generar_par_de_claves()


@pytest.fixture
def acta(claves):
    priv, pub = claves
    a = Acta("org-cliente-A", pub)
    a.agregar("medicion.latencia", {"p50_ms": 120, "p95_ms": 340}, ts_ns=TS)
    a.agregar("medicion.precision", {"aciertos": 91, "total": 100}, ts_ns=TS + 1000)
    a.agregar("config.modelo", {"nombre": "modelo-demo", "digest": "sha256:abc"}, ts_ns=TS + 2000)
    return a.cerrar(priv)


# --------------------------------------------------------------------------- #
# Caso feliz
# --------------------------------------------------------------------------- #

def test_acta_intacta_verifica(acta, claves):
    _, pub = claves
    r = verificar(acta, clave_publica_b64=pub)
    assert r.ok
    assert r.integra
    assert r.procedencia is True
    assert r.entradas == 3
    assert r.organizacion == "org-cliente-A"
    assert "VERIFICADA" in r.resumen()


def test_integridad_no_requiere_biblioteca_de_firma(acta):
    """El nivel 1 corre con biblioteca estándar: quien audita no instala nada."""
    r = verificar_integridad(acta)
    assert r.integra
    assert r.entradas == 3


# --------------------------------------------------------------------------- #
# Manipulaciones que tienen que ser rechazadas
# --------------------------------------------------------------------------- #

def test_rechaza_dato_alterado(acta, claves):
    _, pub = claves
    roto = copy.deepcopy(acta)
    roto["entradas"][1]["datos"]["aciertos"] = 99      # de 91 a 99
    r = verificar(roto, clave_publica_b64=pub)
    assert not r.ok and not r.integra
    assert "entrada 1" in " ".join(r.motivos)


def test_rechaza_entrada_eliminada(acta, claves):
    _, pub = claves
    roto = copy.deepcopy(acta)
    del roto["entradas"][1]
    r = verificar(roto, clave_publica_b64=pub)
    assert not r.ok and not r.integra


def test_rechaza_entrada_insertada(acta, claves):
    priv, pub = claves
    roto = copy.deepcopy(acta)
    intrusa = {"n": 3, "tipo": "medicion.precision",
               "datos": {"aciertos": 100, "total": 100}, "ts": TS + 500}
    from acta_verificador.cadena import hash_entrada
    intrusa["hash"] = hash_entrada(roto["entradas"][1]["hash"], intrusa)
    roto["entradas"].insert(2, intrusa)
    r = verificar(roto, clave_publica_b64=pub)
    assert not r.ok, "una entrada insertada con hash recalculado no puede pasar"


def test_rechaza_reordenamiento(acta, claves):
    _, pub = claves
    roto = copy.deepcopy(acta)
    roto["entradas"][0], roto["entradas"][2] = roto["entradas"][2], roto["entradas"][0]
    r = verificar(roto, clave_publica_b64=pub)
    assert not r.ok and not r.integra


def test_rechaza_cambio_de_organizacion(acta, claves):
    """El acta de un cliente no puede presentarse como la de otro."""
    _, pub = claves
    roto = copy.deepcopy(acta)
    roto["organizacion"] = "org-cliente-B"
    r = verificar(roto, clave_publica_b64=pub)
    assert not r.ok and not r.integra


def test_acta_de_A_no_verifica_bajo_la_clave_de_B(acta):
    """Requisito central: lo exportado para A no verifica con los datos de B."""
    _, pub_de_otro = generar_par_de_claves()
    r = verificar(acta, clave_publica_b64=pub_de_otro)
    assert not r.ok
    assert r.procedencia is False


def test_rechaza_truncado_con_cierre_recalculado(acta, claves):
    """Quien no tiene la clave privada no puede cerrar un acta recortada."""
    _, pub = claves
    roto = copy.deepcopy(acta)
    roto["entradas"] = roto["entradas"][:2]
    roto["cierre"]["cantidad"] = 2
    roto["cierre"]["hash_final"] = roto["entradas"][-1]["hash"]   # cadena coherente…
    r = verificar(roto, clave_publica_b64=pub)
    assert r.integra, "la cadena recortada es autoconsistente, y está bien que lo sea"
    assert r.procedencia is False, "pero la firma ya no cierra: ahí se detecta el recorte"
    assert not r.ok


def test_rechaza_firma_ajena(acta, claves):
    _, pub = claves
    otro_priv, otro_pub = generar_par_de_claves()
    roto = copy.deepcopy(acta)
    a2 = Acta("org-cliente-A", pub)
    a2.agregar("medicion.latencia", {"p50_ms": 1, "p95_ms": 2}, ts_ns=TS)
    firmada_por_otro = a2.cerrar(otro_priv)
    roto["cierre"]["firma"] = firmada_por_otro["cierre"]["firma"]
    r = verificar(roto, clave_publica_b64=pub)
    assert r.procedencia is False


def test_rechaza_clave_distinta_de_la_declarada(acta):
    _, pub_otro = generar_par_de_claves()
    r = verificar(acta, clave_publica_b64=pub_otro)
    assert r.procedencia is False
    assert "no es la que declara" in " ".join(r.motivos)


def test_cierre_con_cantidad_mentida(acta, claves):
    _, pub = claves
    roto = copy.deepcopy(acta)
    roto["cierre"]["cantidad"] = 99
    r = verificar(roto, clave_publica_b64=pub)
    assert not r.integra


# --------------------------------------------------------------------------- #
# Fail-closed y bordes
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("basura", [
    None, 42, "un texto", [], {},
    {"esquema": "otro"},
    {"esquema": ESQUEMA},
    {"esquema": ESQUEMA, "organizacion": "x"},
    {"esquema": ESQUEMA, "organizacion": "x", "clave_publica": "y"},
    {"esquema": ESQUEMA, "organizacion": "x", "clave_publica": "y", "entradas": "no-es-lista"},
    {"esquema": ESQUEMA, "organizacion": "x", "clave_publica": "y", "entradas": [1, 2]},
])
def test_entrada_malformada_no_explota(basura):
    """Un verificador que lanza una excepción es un verificador que no dice que no."""
    r = verificar_integridad(basura)
    assert r.integra is False
    assert isinstance(r.motivos, list) and r.motivos


def test_acta_sin_firma_da_integridad_pero_no_procedencia(acta):
    sin_firma = copy.deepcopy(acta)
    sin_firma["cierre"].pop("firma")
    r = verificar(sin_firma)
    assert r.integra is True
    assert r.procedencia is None
    assert not r.ok


def test_sin_clave_externa_nunca_da_procedencia_por_probada(acta):
    """Verificar con la clave que viene adentro es circular: no puede dar `ok`.

    Quien manipuló un acta puede firmarla con una clave propia y dejar su clave
    pública dentro del archivo. Si esto devolviera `True`, la herramienta estaría
    afirmando un origen que no comprobó — el peor defecto posible acá.
    """
    r = verificar(acta)                      # sin aportar clave por fuera
    assert r.integra is True
    assert r.procedencia is None, "sin clave independiente, la procedencia no se prueba"
    assert r.ok is False
    assert "no prueba procedencia" in " ".join(r.motivos)


def test_acta_forjada_con_clave_propia_no_pasa_como_verificada(claves):
    """El ataque concreto: alguien rehace el acta entera con su propio par de claves."""
    _, pub_legitima = claves
    priv_falsa, pub_falsa = generar_par_de_claves()
    falsa = Acta("org-cliente-A", pub_falsa)
    falsa.agregar("medicion.precision", {"aciertos": 100, "total": 100}, ts_ns=TS)
    acta_falsa = falsa.cerrar(priv_falsa)

    # Es internamente coherente: la cadena cierra y la firma valida con su propia clave.
    assert verificar_integridad(acta_falsa).integra is True
    assert verificar(acta_falsa).ok is False, "sin clave externa no puede dar por buena"

    # Y contra la clave verdadera de Eleion, se cae.
    r = verificar(acta_falsa, clave_publica_b64=pub_legitima)
    assert r.ok is False and r.procedencia is False


def test_acta_vacia_es_valida(claves):
    """Un trabajo que no midió nada produce un acta vacía, y debe poder verificarse."""
    priv, pub = claves
    a = Acta("org-cliente-A", pub)
    vacia = a.cerrar(priv)
    r = verificar(vacia, clave_publica_b64=pub)
    assert r.ok and r.entradas == 0


def test_no_se_puede_inyectar_texto_fuera_de_la_cadena(acta, claves):
    """Todo el contenido visible tiene que estar cubierto por la firma.

    Regresión de un fallo real que encontró una auditoría adversaria: una versión
    anterior excluía del hash los campos que empezaban con guion bajo, «para
    anotaciones». Eso permitía agregar texto a un acta legítima —que una persona
    lee— sin romper la verificación. Un documento presentado como verificado no
    puede tener contenido fuera de la firma.
    """
    _, pub = claves
    anotada = copy.deepcopy(acta)
    anotada["entradas"][0]["_comentario"] = "el sistema del proveedor es fraudulento"
    r = verificar(anotada, clave_publica_b64=pub)
    assert not r.ok, "un campo agregado tiene que romper la cadena"
    assert not r.integra


def test_el_numero_de_entrada_no_puede_mentir(acta, claves):
    """`n` tiene que coincidir con la posición: un índice falso es un dato falso."""
    _, pub = claves
    roto = copy.deepcopy(acta)
    roto["entradas"][1]["n"] = 7
    r = verificar(roto, clave_publica_b64=pub)
    assert not r.ok and not r.integra


# --------------------------------------------------------------------------- #
# La propiedad fina: prefijo de longitud contra colisiones por concatenación
# --------------------------------------------------------------------------- #

def test_organizaciones_distintas_no_colisionan_en_el_genesis():
    """Sin prefijo de longitud, ('ab','c') y ('a','bc') compartirían preimagen."""
    g1 = hash_genesis("ab", "c")
    g2 = hash_genesis("a", "bc")
    assert g1 != g2, "el prefijo de longitud es lo que impide esta colisión"


def test_dos_organizaciones_producen_cadenas_distintas(claves):
    priv, pub = claves
    entradas = [("medicion.latencia", {"p50_ms": 120})]
    actas = []
    for org in ("org-cliente-A", "org-cliente-B"):
        a = Acta(org, pub)
        for tipo, datos in entradas:
            a.agregar(tipo, datos, ts_ns=TS)
        actas.append(a.cerrar(priv))
    assert actas[0]["cierre"]["hash_final"] != actas[1]["cierre"]["hash_final"]
    # y el acta de A no se puede repintar como de B
    repintada = copy.deepcopy(actas[0])
    repintada["organizacion"] = "org-cliente-B"
    assert not verificar(repintada, clave_publica_b64=pub).integra


# --------------------------------------------------------------------------- #
# Regresiones de la segunda ronda de auditoría: campos no cubiertos por la firma
# --------------------------------------------------------------------------- #

def test_no_admite_campos_extra_en_la_raiz(acta, claves):
    """El mismo fallo de las entradas existía un nivel más arriba.

    El núcleo firmado solo cubre cinco campos concretos del acta, así que
    cualquier otra clave de primer nivel quedaba fuera de la cadena y de la firma:
    se podía agregar texto a la raíz de un acta legítima y seguía verificando.
    """
    _, pub = claves
    roto = copy.deepcopy(acta)
    roto["_comentario"] = "ESTA ACTA ES FALSA"
    r = verificar(roto, clave_publica_b64=pub)
    assert not r.ok and not r.integra
    assert "no reconoce" in " ".join(r.motivos)


def test_no_admite_campos_extra_en_el_cierre(acta, claves):
    _, pub = claves
    roto = copy.deepcopy(acta)
    roto["cierre"]["nota"] = "revisado"
    r = verificar(roto, clave_publica_b64=pub)
    assert not r.ok and not r.integra


def test_no_admite_campos_extra_en_una_entrada(acta, claves):
    _, pub = claves
    roto = copy.deepcopy(acta)
    roto["entradas"][0]["observacion"] = "medición dudosa"
    r = verificar(roto, clave_publica_b64=pub)
    assert not r.ok and not r.integra


def test_dos_actas_distintas_no_comparten_nucleo_firmado(claves):
    """Contraejemplo del auditor: dos actas que diferían solo en una clave extra
    de primer nivel producían el mismo núcleo y compartían firma válida."""
    priv, pub = claves
    a = Acta("org-cliente-A", pub)
    a.agregar("m", {"x": 1}, ts_ns=TS)
    original = a.cerrar(priv)

    gemela = copy.deepcopy(original)
    gemela["version"] = 2                      # única diferencia
    assert verificar(gemela, clave_publica_b64=pub).integra is False


def test_anidamiento_excesivo_se_rechaza_con_motivo(claves):
    priv, pub = claves
    a = Acta("org-cliente-A", pub)
    hondo = {}
    cursor = hondo
    for _ in range(200):
        cursor["x"] = {}
        cursor = cursor["x"]
    a.agregar("m", hondo, ts_ns=TS)
    acta_honda = a.cerrar(priv)
    r = verificar(acta_honda, clave_publica_b64=pub)
    assert not r.integra
    assert "anidan" in " ".join(r.motivos)


# --------------------------------------------------------------------------- #
# La décima instancia del patrón del proyecto: el sello obligatorio que nadie
# comprobó, informado como acta verificada. La encontró la auditoría final.
# --------------------------------------------------------------------------- #

def _refirmar(doc, priv, *, sello_requerido):
    """Vuelve a firmar el cierre. Es lo que haría el emisor legítimo — o cualquiera
    que tenga la clave privada, que es el escenario contra el que protege el sello."""
    from acta_verificador.cadena import (PREFIJO_FIRMA, _DOM_CIERRE, canonico,
                                         nucleo_cierre)
    from acta_verificador.emisor import _b64d, _b64e
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    sk = Ed25519PrivateKey.from_private_bytes(_b64d(priv))
    nucleo = nucleo_cierre(doc, doc["cierre"]["hash_final"],
                           doc["cierre"]["cantidad"], sello_requerido)
    doc["cierre"]["firma"] = PREFIJO_FIRMA + _b64e(sk.sign(_DOM_CIERRE + canonico(nucleo)))
    return doc


def _sello_fabricado(hash_final: str) -> str:
    """Once bytes cualesquiera seguidos del hash final. No es un sello RFC 3161:
    es lo mínimo para que un lector informativo encuentre el resumen adentro."""
    import base64
    # url-safe, como exige el formato para todo lo que viaja dentro del acta.
    return base64.urlsafe_b64encode(
        b"\x60\x86\x48\x01\x65\x03\x04\x02\x01\x04\x20" + bytes.fromhex(hash_final)
    ).decode()


def test_un_sello_obligatorio_que_no_se_pudo_comprobar_no_da_acta_verificada(
        acta, claves, monkeypatch):
    """El caso medido: un acta con `sello_requerido: true` y un sello **fabricado**
    devolvía `ACTA VERIFICADA` cuando el entorno no tenía raíz de confianza — que es
    el caso por omisión de cualquier cliente.

    `verificar_sello` había devuelto `None` («no lo pude comprobar») y sólo se
    invalidaba con `False`. El mismo defecto que este proyecto ya cerró nueve veces,
    esta vez sobre la única protección que existe contra el propio emisor.
    """
    monkeypatch.delenv("ACTA_RAIZ_SELLO", raising=False)
    priv, pub = claves
    d = copy.deepcopy(acta)
    d["cierre"]["sello_requerido"] = True
    d["cierre"]["sello"] = _sello_fabricado(d["cierre"]["hash_final"])
    _refirmar(d, priv, sello_requerido=True)

    r = verificar(d, clave_publica_b64=pub)
    assert r.integra is True          # la cadena sí es coherente
    assert r.procedencia is True      # y la firma es nuestra
    assert r.sello is None            # pero el sello no se pudo comprobar
    assert r.ok is False              # y eso NO es un acta verificada
    assert "SELLO NO COMPROBADO" in r.resumen()
    assert "declara requerir sello" in r.resumen()
    assert "ACTA VERIFICADA" not in r.resumen()


def test_cambiar_sello_requerido_por_una_cadena_no_desactiva_la_politica(acta, claves):
    """`bool("x")` es `True`, así que el núcleo firmado no cambia al reemplazar
    `true` por `"x"`: la firma sigue validando. Si la política se leyera con la
    misma tolerancia, bastaría eso para apagar la exigencia de sello sin tocar la
    firma — el downgrade completo de la protección contra el emisor."""
    priv, pub = claves
    d = copy.deepcopy(acta)
    d["cierre"]["sello_requerido"] = True
    d["cierre"]["sello"] = _sello_fabricado(d["cierre"]["hash_final"])
    _refirmar(d, priv, sello_requerido=True)

    d["cierre"]["sello_requerido"] = "x"
    r = verificar(d, clave_publica_b64=pub)
    assert r.ok is False
    assert "ACTA VERIFICADA" not in r.resumen()
    assert any("`sello_requerido` tiene que estar" in m for m in r.motivos), r.motivos


def test_una_cantidad_que_no_es_un_entero_no_verifica(acta, claves):
    """`bool` es subclase de `int`: `int(True) == 1`. Con `cantidad: 1` cambiado a
    `true`, la firma seguía validando y el acta quedaba VERIFICADA declarando una
    cantidad que no es un número. La firma autenticaba el valor convertido, no el
    que está escrito."""
    _, pub = claves
    d = copy.deepcopy(acta)
    d["cierre"]["cantidad"] = True
    r = verificar(d, clave_publica_b64=pub)
    assert r.ok is False
    assert any("no es un número entero" in m for m in r.motivos), r.motivos


@pytest.mark.parametrize("basura", [[], 0, False, "", {}])
def test_un_campo_sello_presente_pero_falso_no_pasa_inadvertido(acta, claves, basura):
    """El sello viaja fuera de la firma a propósito (lo agrega un tercero). Por eso
    un valor cualquiera pasaba entero: la rama que lo comprueba ni se ejecutaba, y
    el acta conservaba `ok=True` con un campo `sello` que no era un sello."""
    _, pub = claves
    d = copy.deepcopy(acta)
    d["cierre"]["sello"] = basura
    r = verificar(d, clave_publica_b64=pub)
    assert r.ok is False, f"{basura!r} pasó inadvertido"
    assert any("no es una cadena base64" in m for m in r.motivos), r.motivos


def test_el_resumen_distingue_firma_invalida_de_procedencia_no_comprobada(acta, claves):
    """Antes los dos casos imprimían `PROCEDENCIA NO PROBADA`: el objeto conservaba
    la distinción y el texto que lee una persona la borraba. No es lo mismo «no te
    pude comprobar la firma» que «te la comprobé y está mal»."""
    import base64
    _, pub = claves
    d = copy.deepcopy(acta)
    firma = d["cierre"]["firma"]
    crudo = bytearray(base64.urlsafe_b64decode(firma.split("_", 1)[1]))
    crudo[0] ^= 0x01                                   # un bit, y sólo uno
    d["cierre"]["firma"] = firma.split("_", 1)[0] + "_" + base64.urlsafe_b64encode(
        bytes(crudo)).decode()

    r = verificar(d, clave_publica_b64=pub)
    assert r.procedencia is False
    assert "FIRMA INVÁLIDA" in r.resumen()

    sin_clave = verificar(copy.deepcopy(acta))
    assert sin_clave.procedencia is None
    assert "PROCEDENCIA NO PROBADA" in sin_clave.resumen()
    assert sin_clave.resumen() != r.resumen()


def test_una_firma_con_basura_intercalada_no_verifica(acta, claves):
    """`urlsafe_b64decode` sin `validate` descarta en silencio los caracteres ajenos
    al alfabeto: `acta1_!<B64>` daba exactamente los mismos bytes que `acta1_<B64>`,
    así que el texto de la firma se podía alterar sin que nada cambiara. Dos actas
    distintas byte a byte no pueden verificar igual."""
    _, pub = claves
    assert verificar(copy.deepcopy(acta), clave_publica_b64=pub).ok      # control

    d = copy.deepcopy(acta)
    prefijo, cuerpo = d["cierre"]["firma"].split("_", 1)
    d["cierre"]["firma"] = f"{prefijo}_!{cuerpo}"
    assert verificar(d, clave_publica_b64=pub).ok is False


def test_un_sello_presente_sin_comprobar_tampoco_da_acta_verificada(acta, claves,
                                                                    monkeypatch):
    """Segunda ronda de la misma auditoría, sobre el arreglo de la primera.

    El arreglo anterior cubría sólo las actas que EXIGEN sello. Un acta que no lo
    exige pero **trae uno** seguía saliendo `ACTA VERIFICADA` con ese sello sin
    comprobar adentro — y el sello es contenido visible: alguien lo lee y cree que un
    tercero certificó la fecha.

    `sello_requerido` decide si se admite que el sello FALTE. Que el que está sea
    válido no es opcional nunca.
    """
    monkeypatch.delenv("ACTA_RAIZ_SELLO", raising=False)
    _, pub = claves
    d = copy.deepcopy(acta)
    assert not d["cierre"].get("sello_requerido")        # no lo exige
    d["cierre"]["sello"] = _sello_fabricado(d["cierre"]["hash_final"])

    r = verificar(d, clave_publica_b64=pub)
    assert r.sello is None
    assert r.ok is False
    assert "SELLO NO COMPROBADO" in r.resumen()
    assert "trae un sello" in r.resumen()

    # Y sin sello ninguno, el acta sigue verificando: no se rompió el caso normal.
    assert verificar(copy.deepcopy(acta), clave_publica_b64=pub).ok is True


def test_la_procedencia_publica_no_aprueba_un_acta_sin_integridad(acta, claves):
    """El módulo promete arriba que «nunca puede tener procedencia sin integridad».
    `verificar_procedencia` es pública —está en `__all__`— y confiaba en el
    `hash_final` y la `cantidad` que le pasara quien la llamara: con un acta alterada
    y los valores originales devolvía `(True, "")`.
    """
    _, pub = claves
    d = copy.deepcopy(acta)
    d["entradas"][0]["datos"] = {"alterado": True}

    assert verificar_integridad(d).integra is False
    ok, motivo = verificar_procedencia(d, clave_publica_b64=pub)
    assert ok is False
    assert "sin integridad no hay procedencia" in motivo

    # El acta intacta sigue probando procedencia con la clave externa.
    assert verificar_procedencia(copy.deepcopy(acta), clave_publica_b64=pub)[0] is True


# --------------------------------------------------------------------------- #
# Los artefactos de `ejemplo/`: lo primero que corre un cliente
# --------------------------------------------------------------------------- #

def test_el_acta_de_ejemplo_verifica():
    """Lo primero que hace alguien que recibe esta herramienta es correrla contra el
    ejemplo. Y el ejemplo decía **FIRMA INVÁLIDA · PROCEDENCIA RECHAZADA**.

    Había quedado firmado con el núcleo viejo, de antes de que `sello_requerido`
    entrara en la firma. Nadie lo notó porque ninguna prueba lo miraba: los 102 tests
    generaban sus propias actas. El archivo que se le entrega al cliente no estaba
    cubierto por nada.

    Esta prueba existe para que el ejemplo no pueda volver a quedar atrás del código.
    """
    import json
    from pathlib import Path

    raiz = Path(__file__).resolve().parent.parent / "ejemplo"
    acta = json.loads((raiz / "acta-demo.json").read_text(encoding="utf-8"))
    clave = (raiz / "clave-publica.txt").read_text(encoding="utf-8").strip()

    r = verificar(acta, clave_publica_b64=clave)
    assert r.ok, f"el acta de ejemplo NO verifica: {r.motivos}"
    assert "ACTA VERIFICADA" in r.resumen()

    # Y sin la clave externa dice lo que corresponde, que es lo que el ejemplo
    # enseña: comprobar contra la clave que viene adentro no prueba procedencia.
    sin_clave = verificar(acta)
    assert sin_clave.ok is False
    assert "PROCEDENCIA NO PROBADA" in sin_clave.resumen()


def test_dos_archivos_distintos_no_pueden_informar_los_dos_ACTA_VERIFICADA(acta, claves):
    """El README le dice al cliente que conservar su copia del acta le da una garantía
    por sí sola. Una revisión midió que con un decodificador tolerante eso deja de ser
    cierto: reescribiendo la firma del alfabeto url-safe al clásico quedaban **dos
    archivos distintos byte a byte, con sha256 distinto, que los dos informaban ACTA
    VERIFICADA**. El cliente que guarda el hash de su copia y después compara ya no
    distinguía una cosa de la otra.

    La firma la escribimos nosotros al emitir, así que se le puede exigir una sola
    representación. La clave pública llega por otro canal y con ella hay que ser
    tolerante — eso se comprueba en la prueba de abajo.
    """
    _, pub = claves
    assert verificar(copy.deepcopy(acta), clave_publica_b64=pub).ok

    from acta_verificador.cadena import _b64d, _b64d_canonico

    # La propiedad, sin depender del azar de la firma: el decodificador del acta
    # admite UNA sola representación; el de las claves, las dos.
    crudo = bytes(range(64))
    clasico = base64.b64encode(crudo).decode("ascii")
    urlsafe = base64.urlsafe_b64encode(crudo).decode("ascii")
    assert clasico != urlsafe, "el valor de prueba tiene que diferir entre alfabetos"
    assert _b64d_canonico(urlsafe) == crudo
    with pytest.raises(ValueError, match="canónico"):
        _b64d_canonico(clasico)
    assert _b64d(clasico) == _b64d(urlsafe) == crudo

    # Y de punta a punta, cuando la firma emitida tiene algún carácter que cambie
    # entre alfabetos (que es lo habitual, pero no siempre):
    d = copy.deepcopy(acta)
    prefijo, cuerpo = d["cierre"]["firma"].split("_", 1)
    otro = base64.b64encode(base64.urlsafe_b64decode(cuerpo)).decode("ascii")
    if otro != cuerpo:
        d["cierre"]["firma"] = prefijo + "_" + otro
        assert verificar(d, clave_publica_b64=pub).ok is False


def test_la_clave_publica_si_se_acepta_en_los_dos_alfabetos(acta, claves):
    """La clave la publica su dueño y la copia una persona: llega en el alfabeto en
    que se la dieron. Rechazarla por eso sería romper el caso bueno."""
    _, pub = claves
    clasico = base64.b64encode(base64.urlsafe_b64decode(pub)).decode("ascii")
    assert verificar(copy.deepcopy(acta), clave_publica_b64=clasico).ok is True


def test_un_indice_booleano_no_pasa_como_numero(acta, claves):
    """`False == 0` y `True == 1`: un booleano pasaba como índice de entrada pese a
    que `FORMATO.md` lo prohíbe explícitamente."""
    _, pub = claves
    d = copy.deepcopy(acta)
    d["entradas"][0]["n"] = False
    assert verificar(d, clave_publica_b64=pub).ok is False


def test_la_firma_sin_el_prefijo_del_formato_no_verifica(acta, claves):
    """El formato declara `acta1_` obligatorio y el verificador lo aceptaba de las dos
    maneras: la implementación no cumplía su propia especificación, y una misma firma
    admitía dos representaciones."""
    _, pub = claves
    d = copy.deepcopy(acta)
    d["cierre"]["firma"] = d["cierre"]["firma"].split("_", 1)[1]
    r = verificar(d, clave_publica_b64=pub)
    assert r.ok is False
    assert any("prefijo" in m for m in r.motivos), r.motivos


def test_la_via_documentada_desde_python_rechaza_las_claves_repetidas(
        acta, claves, tmp_path):
    """El arreglo anterior protegía la CLI y dejaba abierto el camino que el README
    recomendaba: `verificar(json.load(...))`. Para cuando `verificar` recibe el
    diccionario, la clave repetida ya desapareció."""
    import json as _json

    from acta_verificador import verificar_archivo

    _, pub = claves
    p = tmp_path / "trucada.json"
    p.write_text('{"organizacion": "BANCO CENTRAL", ' + _json.dumps(acta)[1:],
                 encoding="utf-8")
    # Fail-closed: no explota, devuelve un veredicto negativo que dice por qué.
    r = verificar_archivo(p, clave_publica_b64=pub)
    assert r.ok is False
    assert any("repetida" in m for m in r.motivos), r.motivos

    buena = tmp_path / "buena.json"
    buena.write_text(_json.dumps(acta), encoding="utf-8")
    assert verificar_archivo(buena, clave_publica_b64=pub).ok is True


def test_un_acta_hostil_no_puede_escribir_en_la_terminal(claves):
    """La `organizacion` la escribe quien emite el acta y el resumen la interpolaba
    tal cual. Con secuencias ANSI o retornos de carro se puede escribir un acta que
    en pantalla dice algo distinto de lo que el programa verificó —incluso borrando
    y reescribiendo la línea del veredicto— y funciona aunque el acta esté
    autofirmada y se corra sin clave externa."""
    from acta_verificador.cadena import Resultado

    hostil = "acme\x1b[2K\rACTA VERIFICADA POR EL BANCO CENTRAL"
    r = Resultado(integra=True, procedencia=True, entradas=1, organizacion=hostil)
    salida = r.resumen()
    assert "\x1b" not in salida and "\r" not in salida
    assert "‮" not in salida          # tampoco marcas bidireccionales

    # Y una organización normal no se toca:
    normal = Resultado(integra=True, procedencia=True, entradas=1,
                       organizacion="Organización Demo ÁÉÍ")
    assert "Organización Demo ÁÉÍ" in normal.resumen()


def test_verificar_archivo_no_propaga_excepciones(tmp_path):
    """El módulo promete que ninguna función pública propaga una excepción, y ésta las
    propagaba: un archivo ilegible, un JSON con claves repetidas o uno anidado hasta el
    fondo salían como traceback en vez de como veredicto."""
    from acta_verificador import verificar_archivo
    from acta_verificador.cadena import MAX_BYTES_ACTA

    assert verificar_archivo(tmp_path / "no-existe.json").ok is False

    roto = tmp_path / "roto.json"
    roto.write_text("{esto no es json", encoding="utf-8")
    assert verificar_archivo(roto).ok is False

    hondo = tmp_path / "hondo.json"
    hondo.write_text("[" * 100_000 + "0" + "]" * 100_000, encoding="utf-8")
    assert verificar_archivo(hondo).ok is False

    grande = tmp_path / "grande.json"
    grande.write_text("[" + "0," * (MAX_BYTES_ACTA // 2) + "0]", encoding="utf-8")
    r = verificar_archivo(grande)
    assert r.ok is False
    assert any("tope" in m for m in r.motivos), r.motivos


def test_no_se_puede_borrar_sello_requerido_de_un_acta_firmada(acta, claves):
    """El campo sólo se validaba si estaba presente, y su ausencia se normalizaba a
    `false`: se podía BORRAR de un acta legítima la declaración visible
    `sello_requerido: false` y la firma seguía valiendo, porque el núcleo firmado
    calcula el mismo booleano en los dos casos. El acta entregada dejaba de contener
    lo que la especificación dice que contiene."""
    _, pub = claves
    assert acta["cierre"]["sello_requerido"] is False
    d = copy.deepcopy(acta)
    del d["cierre"]["sello_requerido"]
    r = verificar(d, clave_publica_b64=pub)
    assert r.ok is False
    assert any("`sello_requerido` tiene que estar" in m for m in r.motivos), r.motivos


def test_un_salto_de_linea_no_puede_simular_otra_linea_de_veredicto(claves):
    """Una primera versión del escape dejaba pasar el tabulador y el salto de línea, y
    con un `\\n` alcanza para escribir debajo del veredicto una línea que parezca otro
    veredicto."""
    from acta_verificador.cadena import Resultado

    hostil = "acme\nACTA VERIFICADA · organización BANCO CENTRAL"
    r = Resultado(integra=True, procedencia=True, entradas=1, organizacion=hostil)
    # Lo que importa es que no haya salto de línea: el texto puede seguir ahí, pero
    # en una sola línea no simula un segundo veredicto.
    assert "\n" not in r.resumen() and "\t" not in r.resumen()
    assert r.resumen().count("\n") == 0


def test_el_tope_del_acta_se_mide_en_bytes_y_no_en_caracteres(tmp_path):
    """`fh.read(N)` sobre un archivo abierto en modo texto cuenta CARACTERES: con
    UTF-8 multibyte un acta podía pesar el triple del tope y pasar igual. El archivo
    se lee en binario y el límite se aplica sobre los bytes de verdad."""
    from acta_verificador import verificar_archivo
    from acta_verificador.cadena import MAX_BYTES_ACTA

    # Cada «€» son 3 bytes: en caracteres entra, en bytes no.
    p = tmp_path / "multibyte.json"
    p.write_text('["' + "€" * (MAX_BYTES_ACTA // 2) + '"]', encoding="utf-8")
    assert p.stat().st_size > MAX_BYTES_ACTA
    r = verificar_archivo(p)
    assert r.ok is False
    assert any("tope" in m for m in r.motivos), r.motivos


def test_los_flotantes_se_rechazan_por_los_dos_caminos(claves):
    """`FORMATO.md` dice que no hay números de punto flotante en ninguna parte y el
    código los aceptaba. El ataque que abre es concreto: `0.1` y
    `0.10000000000000001` son el MISMO `float`, así que canonizan igual y producen la
    misma firma. Cualquiera puede editar ese literal en un acta legítima y el
    verificador la sigue dando por buena **sin tener la clave privada**.
    """
    import json as _json

    from acta_verificador.cadena import cargar_estricto

    priv, pub = claves
    a = Acta("acme", pub)
    a.agregar("medicion", {"tasa": 0.1}, ts_ns=TS)
    d = a.cerrar(priv, permitir_sin_sello=True)
    crudo = _json.dumps(d)

    # (a) Al leer el archivo: se rechaza el literal, que es donde todavía existe.
    with pytest.raises(ValueError, match="coma decimal"):
        cargar_estricto(crudo.replace("0.1", "0.10000000000000001"))
    with pytest.raises(ValueError, match="coma decimal"):
        cargar_estricto(crudo)

    # (b) Con el diccionario armado desde Python, donde el literal ya no existe.
    assert verificar(_json.loads(crudo), clave_publica_b64=pub).ok is False


def test_un_sello_enorme_no_se_decodifica(acta, claves):
    """El sello NO está cubierto por la firma, así que cualquiera puede pegarle a un
    acta legítima una cadena enorme y forzar decodificación, archivo temporal y una
    corrida de OpenSSL."""
    from acta_verificador.sello_tiempo import MAX_BYTES_SELLO

    _, pub = claves
    d = copy.deepcopy(acta)
    d["cierre"]["sello"] = "A" * (MAX_BYTES_SELLO * 2 + 4)
    r = verificar(d, clave_publica_b64=pub)
    assert r.ok is False
    assert any("no pesa eso" in m for m in r.motivos), r.motivos


def test_la_linea_de_ordenes_tambien_acota_el_tamano(tmp_path, capsys, claves):
    """La CLI leía el archivo entero sin límite mientras `verificar_archivo` lo
    acotaba — y es justamente la CLI la que alguien corre sobre un archivo que le
    mandaron. Arreglar la mitad de un camino deja el camino abierto."""
    from acta_verificador.cadena import MAX_BYTES_ACTA
    from acta_verificador.cli import main

    _, pub = claves
    p = tmp_path / "enorme.json"
    p.write_text("[" + "0," * (MAX_BYTES_ACTA // 2) + "0]", encoding="utf-8")
    assert main([str(p), "--clave-publica", pub]) == 3
    assert "tope" in capsys.readouterr().err


def test_la_linea_de_ordenes_funciona_de_punta_a_punta(tmp_path, capsys, acta, claves):
    """La CLI **no tenía ni una prueba**, y es lo único que la mayoría de la gente va
    a correr. Se descubrió cuando un cambio le rompió el nombre de un argumento y las
    100 pruebas siguieron en verde."""
    import json as _json

    from acta_verificador.cli import main

    _, pub = claves
    p = tmp_path / "acta.json"
    p.write_text(_json.dumps(acta), encoding="utf-8")

    assert main([str(p), "--clave-publica", pub]) == 0
    assert "ACTA VERIFICADA" in capsys.readouterr().out

    assert main([str(p)]) == 2                      # sin clave: procedencia no probada
    assert "PROCEDENCIA NO PROBADA" in capsys.readouterr().out

    main([str(p), "--clave-publica", pub, "--json"])
    d = _json.loads(capsys.readouterr().out)
    assert d["verifica"] is True and d["entradas"] == len(acta["entradas"])

    roto = tmp_path / "roto.json"
    d2 = _json.loads(_json.dumps(acta))
    d2["entradas"][0]["datos"]["p50_ms"] = 999
    roto.write_text(_json.dumps(d2), encoding="utf-8")
    assert main([str(roto), "--clave-publica", pub]) == 1

    assert main([str(tmp_path / "no-existe.json")]) == 3


def test_una_clave_que_empieza_con_guion_no_tumba_la_demostracion(tmp_path, capsys,
                                                                  acta, claves):
    """El alfabeto base64 url-safe incluye «-», así que **una de cada 64 claves empieza
    con guion** y argparse la lee como si fuera otra opción. La orden que el propio
    producto le imprime al cliente al terminar de exportar fallaba con «expected one
    argument» delante suyo: la herramienta que se vende como «compruébelo usted» no
    arrancaba, en una demostración de cada 64.

    Las comillas del LEEME no ayudaban — protegen del intérprete de órdenes, no de
    argparse. Se cubren las dos salidas: `--clave-publica=VALOR` y, mejor, el archivo.
    """
    import json as _json

    from acta_verificador.cli import main

    _, pub = claves
    p = tmp_path / "acta.json"
    p.write_text(_json.dumps(acta), encoding="utf-8")

    # Se fuerza el caso: una clave que empieza con guion. No se espera al azar.
    clave_con_guion = "-" + pub[1:]

    # (a) La forma que falla, y con el código correcto: 3 («no se pudo leer»), NO 2.
    # El 2 es el que este programa documenta para «cadena íntegra, procedencia no
    # probada», así que un error de argumentos saliendo con 2 hace que una tubería lea
    # el estallido como si el acta estuviera bien.
    assert main([str(p), "--clave-publica", clave_con_guion]) == 3
    capsys.readouterr()

    # (b) Con el signo igual, la clave llega entera:
    assert main([str(p), f"--clave-publica={pub}"]) == 0
    assert "ACTA VERIFICADA" in capsys.readouterr().out

    # (c) Desde archivo, que es la forma recomendada y no depende del guion:
    k = tmp_path / "clave.pub"
    k.write_text(pub + "\n", encoding="utf-8")
    assert main([str(p), "--clave-publica-archivo", str(k)]) == 0
    assert "ACTA VERIFICADA" in capsys.readouterr().out

    # Y las dos juntas se rechazan en vez de que gane una en silencio:
    assert main([str(p), "--clave-publica", pub, "--clave-publica-archivo", str(k)]) == 3


def test_un_entero_de_millones_de_digitos_no_se_convierte(tmp_path):
    """Un acta cabe en 64 MiB y puede traer un SOLO entero de millones de dígitos.
    Convertirlo cuesta tiempo y memoria desproporcionados, y ocurre antes de que se
    apliquen los límites de entradas y profundidad: para entonces el daño está hecho.
    Los sellos de tiempo en nanosegundos tienen 19 dígitos."""
    from acta_verificador import verificar_archivo
    from acta_verificador.cadena import cargar_estricto

    with pytest.raises(ValueError, match="dígitos"):
        cargar_estricto('{"n": ' + "9" * 100_000 + "}")

    p = tmp_path / "gordo.json"
    p.write_text('{"n": ' + "9" * 200_000 + "}", encoding="utf-8")
    r = verificar_archivo(p)
    assert r.ok is False
    assert any("dígitos" in m for m in r.motivos), r.motivos

    # Un sello de tiempo real sigue entrando sin problema:
    assert cargar_estricto('{"ts": 1754800000000000000}')["ts"] == 1754800000000000000


def test_el_archivo_de_clave_se_lee_acotado(tmp_path, capsys, acta, claves):
    """Una clave pública Ed25519 en base64 son 44 caracteres. Leer el archivo entero
    permitía que uno enorme agotara la memoria, y era una regresión respecto del acta,
    que sí está acotada."""
    import json as _json

    from acta_verificador.cli import main

    _, pub = claves
    a = tmp_path / "acta.json"
    a.write_text(_json.dumps(acta), encoding="utf-8")

    gorda = tmp_path / "gorda.pub"
    gorda.write_text("A" * 5000, encoding="utf-8")
    assert main([str(a), "--clave-publica-archivo", str(gorda)]) == 3
    assert "no parece una clave" in capsys.readouterr().err

    buena = tmp_path / "buena.pub"
    buena.write_text(pub + "\n", encoding="utf-8")
    assert main([str(a), "--clave-publica-archivo", str(buena)]) == 0


def test_un_error_de_argumentos_no_se_confunde_con_un_veredicto(tmp_path, capsys):
    """argparse sale con 2, y 2 es el código que este programa documenta para «cadena
    íntegra, procedencia no probada». Una tubería que mire sólo el código de salida
    —que es lo que hace una tubería— leía el estallido como si el acta estuviera bien."""
    from acta_verificador.cli import main

    assert main(["acta.json", "--opcion-que-no-existe"]) == 3
    assert main([]) == 3


def test_un_archivo_de_clave_que_no_es_regular_no_cuelga(tmp_path, capsys, acta, claves):
    """Abrir un FIFO o un dispositivo bloquea el proceso para siempre. Un paquete que
    llega de afuera puede traer uno."""
    import json as _json
    import os

    from acta_verificador.cli import main

    _, pub = claves
    a = tmp_path / "acta.json"
    a.write_text(_json.dumps(acta), encoding="utf-8")

    tuberia = tmp_path / "tuberia.pub"
    os.mkfifo(tuberia)
    assert main([str(a), "--clave-publica-archivo", str(tuberia)]) == 3
    assert "no es un archivo regular" in capsys.readouterr().err

    # Y una clave con bytes que no son UTF-8 tampoco explota:
    mala = tmp_path / "mala.pub"
    mala.write_bytes(b"\xff\xfe\x00clave")
    assert main([str(a), "--clave-publica-archivo", str(mala)]) == 3


def test_ni_el_acta_ni_la_clave_pueden_ser_un_archivo_especial(tmp_path, claves):
    """Un FIFO o un dispositivo bloquean el proceso para siempre, y el tamaño que
    `stat` informa para ellos no significa nada.

    Esto se arregló primero para el archivo de CLAVE y no para el del ACTA — que es
    justamente el que llega de afuera. Fue la tercera vez en la misma auditoría que un
    arreglo cubrió la mitad de un camino, así que la prueba cubre los dos a la vez: si
    mañana aparece un tercer archivo de entrada, que se agregue acá.
    """
    import json as _json
    import os

    from acta_verificador import verificar_archivo
    from acta_verificador.cli import main

    _, pub = claves

    tuberia = tmp_path / "acta.fifo"
    os.mkfifo(tuberia)
    r = verificar_archivo(tuberia)
    assert r.ok is False and r.ilegible is True
    assert any("no es un archivo regular" in m for m in r.motivos), r.motivos

    # Y por la línea de órdenes, que es como lo corre el cliente:
    assert main([str(tuberia), "--clave-publica", pub]) == 3

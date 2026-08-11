# Copyright 2026 Eleion
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Sellado de tiempo por un tercero (RFC 3161).

## Qué problema resuelve, exactamente

La cadena firmada demuestra integridad frente a cualquiera **menos frente a quien la
produjo**: con la clave privada se puede rehacer un acta entera —cambiar un número,
recalcular los eslabones, volver a firmar— y el resultado verifica igual.

Un sello de tiempo lo corta. Una autoridad ajena firma que **este hash existía en
esta fecha**. A partir de ahí no podemos rehacer el acta sin que el sello deje de
coincidir, porque no podemos pedirle a la autoridad un sello con fecha pasada.

Con esto, la afirmación defendible pasa de:

> «esta acta no fue alterada después de que usted la recibió»

a:

> «esta acta existía, con este contenido exacto, el día que dice el sello»

que es lo que un auditor necesita y lo único que convierte el registro en prueba.

## Cómo funciona

Se manda a la autoridad **solo el hash** del cierre del acta, nunca su contenido:
una petición RFC 3161 es un `MessageImprint` —el identificador del algoritmo y el
resumen—, así que **la autoridad no ve nada del cliente**. Eso importa: mandarle el
acta a un tercero contradiría todo el producto.

La respuesta se guarda junto al acta. Verificarla no necesita internet: el sello es
autocontenido y se comprueba contra el certificado de la autoridad.

## Estado

La petición y el análisis de la respuesta están implementados con biblioteca
estándar. **El envío requiere una autoridad configurada**; hasta que se elija una y
se fije su certificado, `sellar()` produce la petición pero no la manda. Se hizo así
a propósito: es preferible una función que diga «falta configurar la autoridad» a
una que mande el hash a un servidor cualquiera de internet.
"""

from __future__ import annotations

import hashlib
import os
import struct
from dataclasses import dataclass

# Identificador del algoritmo SHA-256 en notación de objetos ASN.1 (2.16.840.1.101.3.4.2.1)
_OID_SHA256 = bytes([0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01])

#: Lo que puede pesar la respuesta de una autoridad de sellado. Un sello real son unos
#: pocos kilobytes; el tope está holgado y existe porque el tiempo límite acota cuánto
#: se espera, no cuánto llega.
MAX_BYTES_SELLO = 1 << 20


# --------------------------------------------------------------------------- #
# Codificación mínima de ASN.1 DER
#
# Se implementa a mano lo justo para armar una petición de sellado. La alternativa
# era una dependencia con superficie mucho mayor para construir cuatro estructuras
# fijas. Codificar es acotado y verificable; **analizar** la respuesta de un tercero
# con un analizador propio sería otra cosa, y por eso la verificación completa del
# sello se delega a `cryptography` cuando está disponible.
# --------------------------------------------------------------------------- #

def _longitud(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    cuerpo = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(cuerpo)]) + cuerpo


def _tlv(etiqueta: int, contenido: bytes) -> bytes:
    return bytes([etiqueta]) + _longitud(len(contenido)) + contenido


def _entero(n: int) -> bytes:
    if n == 0:
        return _tlv(0x02, b"\x00")
    cuerpo = n.to_bytes((n.bit_length() + 8) // 8, "big")
    return _tlv(0x02, cuerpo)


def _secuencia(*partes: bytes) -> bytes:
    return _tlv(0x30, b"".join(partes))


def _octetos(b: bytes) -> bytes:
    return _tlv(0x04, b)


def _oid(cuerpo: bytes) -> bytes:
    return _tlv(0x06, cuerpo)


def _nulo() -> bytes:
    return _tlv(0x05, b"")


def _booleano(v: bool) -> bytes:
    return _tlv(0x01, b"\xff" if v else b"\x00")


# --------------------------------------------------------------------------- #

@dataclass
class Peticion:
    """Petición de sellado, lista para enviar."""
    der: bytes
    nonce: int
    resumen_hex: str

    @property
    def tipo_de_contenido(self) -> str:
        return "application/timestamp-query"


def construir_peticion(hash_final_hex: str, *, pedir_certificado: bool = True,
                       nonce: int | None = None) -> Peticion:
    """Arma la petición RFC 3161 para el hash de cierre de un acta.

    Solo viaja el resumen. La autoridad **no ve el contenido del acta** — ni el
    nombre de la organización, ni una sola medición. Mandarle el acta a un tercero
    contradiría el producto entero.

    El `nonce` es aleatorio y sirve para atar la respuesta a esta petición: sin él,
    una respuesta vieja podría hacerse pasar por la de ahora.
    """
    if not (isinstance(hash_final_hex, str) and len(hash_final_hex) == 64):
        raise ValueError("hace falta el hash de cierre en 64 caracteres hexadecimales")
    try:
        resumen = bytes.fromhex(hash_final_hex)
    except ValueError as e:
        raise ValueError("el hash de cierre no es hexadecimal válido") from e

    if nonce is None:
        nonce = struct.unpack(">Q", os.urandom(8))[0]

    impronta = _secuencia(
        _secuencia(_oid(_OID_SHA256), _nulo()),
        _octetos(resumen),
    )
    partes = [_entero(1), impronta]           # versión 1
    if pedir_certificado:
        partes.append(_booleano(True))        # que devuelva el certificado
    partes.insert(2, _entero(nonce))

    return Peticion(der=_secuencia(*partes), nonce=nonce, resumen_hex=hash_final_hex)


def sellar(hash_final_hex: str, url_autoridad: str | None = None,
           *, tiempo_limite: int = 20) -> dict:
    """Pide el sello a la autoridad. Devuelve un resultado, nunca lanza.

    **`ok: True` NO quiere decir que el sello sea válido.** Quiere decir que hubo
    respuesta y que contiene el resumen que se pidió — un filtro de rechazo, no una
    validación. Quien decide si el sello vale es `verificar_sello`, contra la raíz de
    confianza. El resultado trae `sello_comprobado: False` justamente para que eso no
    dependa de cómo interprete alguien la palabra «ok».

    Sin autoridad configurada **no manda nada**: devuelve la petición armada y dice
    qué falta. Es deliberado — una función de sellado que elige por su cuenta a qué
    servidor de internet mandarle el hash de un acta de un cliente sería justo el
    tipo de cosa que este producto existe para no hacer.
    """
    try:
        pet = construir_peticion(hash_final_hex)
    except ValueError as e:
        return {"ok": False, "motivo": str(e)}

    url = url_autoridad or os.environ.get("ACTA_AUTORIDAD_SELLO", "").strip()
    if not url:
        return {
            "ok": False,
            "motivo": ("no hay autoridad de sellado configurada; la petición quedó "
                       "armada pero no se envió. Configurá ACTA_AUTORIDAD_SELLO con "
                       "la dirección de una autoridad RFC 3161 de confianza."),
            "peticion_der": pet.der,
            "nonce": pet.nonce,
        }

    try:
        import urllib.request
        req = urllib.request.Request(
            url, data=pet.der,
            headers={"Content-Type": pet.tipo_de_contenido,
                     "Accept": "application/timestamp-reply"})
        with urllib.request.urlopen(req, timeout=tiempo_limite) as r:
            # Tope de tamaño: un sello RFC 3161 pesa unos pocos kilobytes. El tiempo
            # límite acota cuánto se espera, no cuánto llega: una autoridad
            # comprometida —o una redirección— puede mandar sin fin y agotar la
            # memoria de quien emite. `límite + 1` para poder distinguir el borde.
            respuesta = r.read(MAX_BYTES_SELLO + 1)
        if len(respuesta) > MAX_BYTES_SELLO:
            return {"ok": False, "respuesta_recibida": True, "sello_comprobado": False,
                    "motivo": (f"la autoridad devolvió más de {MAX_BYTES_SELLO} bytes: "
                               "un sello no pesa eso, no se procesa"),
                    "peticion_der": pet.der, "nonce": pet.nonce}
    except Exception as e:                                  # fail-closed
        return {"ok": False, "motivo": f"la autoridad no respondió: {type(e).__name__}",
                "peticion_der": pet.der, "nonce": pet.nonce}

    # Una respuesta HTTP 200 NO es un sello.
    #
    # Una auditoría encontró que devolver `ok: True` con lo que sea que conteste el
    # servidor permitía que un servidor respondiera 200 con el texto «NO SOY UN
    # SELLO» y que eso terminara escrito como `sellado: true` **dentro de una
    # cadena firmada, para siempre**. El error es el mismo que este proyecto ya
    # corrigió tres veces: tratar «recibí algo» como «lo comprobé».
    #
    # Antes de dar por bueno el sello se exige, como mínimo, que contenga el
    # resumen que se pidió. Es un filtro de rechazo —no alcanza para aceptar, que
    # es trabajo de `verificar_sello` con la raíz de confianza— pero descarta de
    # entrada cualquier cosa que no sea, al menos, una respuesta a ESTA petición.
    if not respuesta:
        return {"ok": False, "motivo": "la autoridad respondió vacío",
                "peticion_der": pet.der, "nonce": pet.nonce}

    hallado = leer_resumen_informativo(respuesta)
    if hallado is None:
        return {"ok": False,
                "motivo": ("la respuesta de la autoridad no contiene ningún resumen: "
                           "no es un sello de tiempo"),
                "respuesta_cruda": respuesta, "nonce": pet.nonce}
    if hallado.lower() != pet.resumen_hex.lower():
        return {"ok": False,
                "motivo": ("la autoridad respondió un sello de OTRO resumen: pedimos "
                           f"{pet.resumen_hex[:16]}… y devolvió {hallado[:16]}…"),
                "respuesta_cruda": respuesta, "nonce": pet.nonce}

    # El sello llegó y responde a esta petición. Sigue sin estar VALIDADO: eso lo
    # hace `verificar_sello` contra la raíz de confianza, y hasta que exista una
    # configurada, un sello guardado vale como «adjunto», no como «comprobado».
    return {"ok": True, "sello_der": respuesta, "nonce": pet.nonce,
            "resumen": pet.resumen_hex, "autoridad": url,
            # `ok` significa «hubo respuesta y contiene el resumen que pedimos», que
            # es un filtro de rechazo. Un llamador que lea `if r["ok"]` y guarde el
            # sello como bueno se equivoca, así que los dos campos de abajo lo dicen
            # sin depender de cómo se llame la clave.
            "respuesta_recibida": True,
            "sello_comprobado": False,
            "validado": False,
            "aviso": ("el sello responde a esta petición pero NO se validó contra "
                      "una raíz de confianza: guardarlo no lo convierte en probado")}


def resumen_de_acta(acta: dict) -> str:
    """El valor que se sella: el hash de cierre del acta.

    Sellar el cierre alcanza porque el cierre depende de toda la cadena: cambiar
    cualquier entrada cambia el cierre, y el sello deja de corresponder.
    """
    cierre = acta.get("cierre") or {}
    h = cierre.get("hash_final")
    if not (isinstance(h, str) and len(h) == 64):
        raise ValueError("el acta no trae un hash de cierre válido")
    return h


def huella_de_peticion(pet: Peticion) -> str:
    """Huella de la petición, para poder referenciarla en el acta sin guardarla entera."""
    return hashlib.sha256(pet.der).hexdigest()


# --------------------------------------------------------------------------- #
# Lectura y comprobación de la respuesta de la autoridad
# --------------------------------------------------------------------------- #

def _leer_tlv(datos: bytes, pos: int) -> tuple[int, int, int, int]:
    """Lee un TLV de DER en `pos`. Devuelve (etiqueta, inicio, largo, siguiente).

    Analizar la respuesta de un tercero con un analizador propio es más delicado
    que codificar una petición fija: la entrada es hostil por definición. Por eso
    este lector es minúsculo, rechaza todo lo que no entiende, y **solo se usa para
    localizar el resumen sellado** — la validación criptográfica del sello se delega
    a una herramienta seria (ver `verificar_sello`).
    """
    if pos >= len(datos):
        raise ValueError("fin de datos inesperado")
    etiqueta = datos[pos]
    if etiqueta & 0x1F == 0x1F:
        raise ValueError("etiqueta de varios bytes no soportada")
    pos += 1
    if pos >= len(datos):
        raise ValueError("falta la longitud")
    primero = datos[pos]
    pos += 1
    if primero < 0x80:
        largo = primero
    else:
        n = primero & 0x7F
        if n == 0 or n > 4 or pos + n > len(datos):
            raise ValueError("longitud inválida")
        largo = int.from_bytes(datos[pos:pos + n], "big")
        pos += n
    if pos + largo > len(datos):
        raise ValueError("longitud mayor que los datos")
    return etiqueta, pos, largo, pos + largo


def resumen_sellado(sello_der: bytes) -> str | None:
    """Extrae el resumen que la autoridad efectivamente selló.

    Busca la primera cadena de octetos de 32 bytes que siga al identificador de
    SHA-256. Es una búsqueda deliberadamente simple: si no lo encuentra devuelve
    `None`, y quien llama trata eso como «no verificado», nunca como «verificado».
    """
    try:
        pos = sello_der.find(_OID_SHA256)
        if pos < 0:
            return None
        # a partir de ahí, la primera cadena de octetos de 32 bytes es la impronta
        i = pos + len(_OID_SHA256)
        limite = min(len(sello_der), i + 64)
        while i < limite:
            if sello_der[i] == 0x04 and i + 1 < len(sello_der) and sello_der[i + 1] == 32:
                return sello_der[i + 2:i + 34].hex()
            i += 1
        return None
    except Exception:
        return None


def verificar_sello(sello_der: bytes, hash_final_hex: str,
                    raiz_confianza: str | None = None) -> tuple[bool | None, str]:
    """Valida el sello ejecutando `openssl ts -verify`, atado al resumen esperado.

    Devuelve `(resultado, motivo)`:

    - `True`  — la autoridad firmó **este** resumen y su cadena valida contra la
      raíz de confianza configurada.
    - `False` — el sello es inválido, es de otro documento, o no se pudo analizar.
    - `None`  — no se pudo comprobar (falta `openssl` o falta la raíz de confianza).
      **No es éxito.**

    ## Por qué así, y no con el lector propio

    Una auditoría marcó como bloqueante la versión anterior, que decidía con una
    búsqueda por patrón sobre los bytes. Esa búsqueda no comprueba la etiqueta
    ASN.1, ni que el identificador esté dentro del `MessageImprint`, ni que el
    resumen pertenezca al `TSTInfo` **firmado**: un atacante puede anteponer el
    patrón señuelo a un sello genuino de otro documento y hacerla coincidir.

    `openssl ts -verify -digest` sí ata la validación al resumen esperado *dentro
    de la estructura firmada*. Es la única forma de que un `True` signifique algo.

    ## La raíz de confianza es obligatoria

    Sin `-CAfile` propio, OpenSSL puede aceptar un sello firmado por **cualquier**
    certificado incluido en el propio sello: una firma matemáticamente válida de
    una autoridad que nadie eligió. Por eso, sin raíz configurada esta función
    devuelve `None` y no valida: confiar en el certificado que viene adentro del
    documento que se quiere validar es circular.
    """
    if not isinstance(sello_der, (bytes, bytearray)) or not sello_der:
        return False, "el sello está vacío o no es binario"
    if not (isinstance(hash_final_hex, str) and len(hash_final_hex) == 64):
        return False, "el resumen esperado no es un sha256 hexadecimal"

    # Filtro de rechazo temprano. El lector es burdo y NO sirve para aceptar —la
    # coincidencia se puede fabricar—, pero sí para **rechazar**: si ni siquiera
    # aparece el resumen esperado, el sello es de otro documento y no hace falta
    # criptografía para descartarlo. Un chequeo que solo puede decir que no es
    # seguro aunque el analizador sea pobre; lo inseguro era usarlo para decir
    # que sí.
    hallado = leer_resumen_informativo(bytes(sello_der))
    if hallado is None:
        return False, "no se encontró ningún resumen dentro del sello"
    if hallado.lower() != hash_final_hex.lower():
        return False, ("el sello es de otro documento: contiene "
                       f"{hallado[:16]}… y esta acta cierra en {hash_final_hex[:16]}…")

    import shutil
    openssl = shutil.which("openssl")
    if not openssl:
        return None, ("falta `openssl` para validar la firma de la autoridad: "
                      "el sello NO se comprobó")

    raiz = raiz_confianza or os.environ.get("ACTA_RAIZ_SELLO", "").strip()
    if not raiz:
        return None, ("no hay raíz de confianza configurada (ACTA_RAIZ_SELLO): el "
                      "sello NO se comprobó. Sin raíz propia se aceptaría cualquier "
                      "autoridad, incluida una que puso el atacante en el sello.")
    if not os.path.exists(raiz):
        return None, f"la raíz de confianza no existe: {raiz}"

    import subprocess
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        ruta = os.path.join(tmp, "sello.tsr")
        with open(ruta, "wb") as fh:
            fh.write(bytes(sello_der))
        try:
            r = subprocess.run(
                [openssl, "ts", "-verify", "-digest", hash_final_hex,
                 "-in", ruta, "-CAfile", raiz],
                capture_output=True, text=True, timeout=60)
        except Exception as e:
            return None, f"no se pudo ejecutar la validación: {type(e).__name__}"

    salida = (r.stdout + r.stderr).lower()
    if r.returncode == 0 and "verification: ok" in salida:
        fecha = fecha_del_sello(bytes(sello_der))
        if fecha:
            return True, f"sello válido: la autoridad firmó este resumen el {fecha}"
        # Sin fecha, el sello no dice lo único que un sello sirve para decir. Esto
        # estaba escrito acá mismo, en este comentario, y la línea de abajo devolvía
        # `True` igual: el defecto de siempre, reconocido por escrito y contradicho
        # en la línea siguiente. Un sello cuya fecha no se puede leer no distingue un
        # registro anclado hace un año de uno anclado hoy, que es exactamente lo que
        # el sello está para impedir. Va `None` —«no se pudo comprobar»— y quien
        # exige sello obligatorio no lo da por bueno.
        return None, ("la firma del sello valida, pero no se pudo leer su fecha: sin "
                      "ella no distingue un registro anclado hace un año de uno "
                      "anclado hoy, que es para lo único que sirve un sello")
    return False, ("el sello no valida contra la raíz de confianza o no corresponde "
                   f"a este resumen: {(r.stderr or r.stdout).strip()[:160]}")


def fecha_del_sello(sello_der: bytes) -> str | None:
    """La fecha que declara el sello. **Sin esto el sello no prueba lo que promete.**

    Una auditoría midió el agujero: quien rehace una cadena y pide un sello **nuevo
    hoy** obtiene el mismo veredicto —«anclado por un tercero»— que un registro
    sellado hace un año. La frase que este módulo defiende es *«existía, con este
    contenido exacto, **el día que dice el sello**»*, y ese día no se informaba nunca.

    Se lee con `openssl ts -reply -text`, que la imprime como `Time stamp: …`.
    Devuelve `None` si no se puede leer, y quien llama debe tratar eso como «sin
    fecha», no como una fecha cualquiera.
    """
    import shutil
    openssl = shutil.which("openssl")
    if not openssl or not sello_der:
        return None

    import re
    import subprocess
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        ruta = os.path.join(tmp, "sello.tsr")
        with open(ruta, "wb") as fh:
            fh.write(bytes(sello_der))
        try:
            r = subprocess.run([openssl, "ts", "-reply", "-in", ruta, "-text"],
                               capture_output=True, text=True, timeout=30)
        except Exception:
            return None
    m = re.search(r"^Time stamp:\s*(.+)$", r.stdout or "", re.M)
    return m.group(1).strip() if m else None


def leer_resumen_informativo(sello_der: bytes) -> str | None:
    """Extrae el resumen del sello **solo para mostrarlo**. NO decide nada.

    Antes se llamaba `resumen_sellado` y se usaba para decidir si el sello
    correspondía. Una auditoría mostró que la coincidencia se puede fabricar
    anteponiendo el patrón a un sello genuino de otro documento, así que dejó de
    tener valor probatorio. Se conserva como dato de diagnóstico, con el nombre
    diciendo lo que es, para que nadie vuelva a usarlo como si decidiera.
    """
    try:
        pos = sello_der.find(_OID_SHA256)
        if pos < 0:
            return None
        i = pos + len(_OID_SHA256)
        limite = min(len(sello_der), i + 64)
        while i < limite:
            if sello_der[i] == 0x04 and i + 1 < len(sello_der) and sello_der[i + 1] == 32:
                return sello_der[i + 2:i + 34].hex()
            i += 1
        return None
    except Exception:
        return None


# Alias retirado a propósito: quien lo llame tiene que ver que cambió de sentido.
resumen_sellado = leer_resumen_informativo

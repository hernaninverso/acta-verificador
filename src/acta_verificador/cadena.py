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
"""Verificación de un acta de evidencia de Eleion Acta.

Un **acta** es el registro de todo lo que se midió durante un trabajo, encadenado
de modo que alterar cualquier cosa rompe la cadena entera, y firmado de modo que
se puede probar quién la emitió.

Este módulo existe para que **el cliente y su auditor puedan comprobar un acta sin
nosotros y sin ningún secreto compartido**. Es la razón por la que se publica bajo
Apache-2.0: si hubiera que pedirnos permiso para verificar, no sería verificación.

Dos niveles, deliberadamente separados:

- **Nivel 1 — integridad.** Que el acta sea autoconsistente: ninguna entrada
  alterada, eliminada, insertada ni reordenada. Se verifica con la **biblioteca
  estándar de Python únicamente**: quien audita no instala nada.
- **Nivel 2 — procedencia.** Que la emitiéramos nosotros. Requiere `cryptography`
  para la firma Ed25519.

Un acta puede tener integridad y no tener procedencia (alguien copió el formato),
o tener las dos. Nunca puede tener procedencia sin integridad: la firma cubre el
hash de cierre, que depende de toda la cadena.

## La cadena está atada a la organización

El bloque de génesis incorpora el identificador de la organización y su clave
pública. Consecuencia buscada: **el acta de un cliente no verifica bajo los datos
de otro**, y exportarle a un cliente lo suyo no exige entregarle filas de nadie más.
Una cadena global lineal no permite eso — de ahí esta decisión.

## Fail-closed

Toda función pública de verificación devuelve un resultado; **ninguna propaga una
excepción al llamador**. Ante entrada malformada, tipos raros o datos truncados, el
veredicto es «no verifica». Un verificador que explota es un verificador que no
dice que no.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
from dataclasses import dataclass, field

ESQUEMA = "acta-evidencia-1"

# Separación de dominio: dos usos distintos del mismo hash nunca comparten preimagen.
_DOM_GENESIS = b"acta-genesis-1:"
_DOM_ENLACE = b"acta-enlace-1:"
_DOM_CIERRE = b"acta-cierre-1:"

# Prefijo de esquema en la firma. Motivo práctico: una firma en base64 urlsafe puede
# empezar con '-' (aproximadamente 1 de cada 64) y cualquier intérprete de argumentos
# la tomaría por una opción. Con el prefijo, siempre empieza por letra.
PREFIJO_FIRMA = "acta1_"

_LARGO_HASH_HEX = 64

# Listas blancas de campos. Deliberadamente cerradas.
#
# Una auditoría adversaria mostró por qué: si se aceptan campos no reconocidos,
# se pueden agregar a un acta legítima —en la raíz, en el cierre o en una entrada—
# sin romper la verificación, porque ni la cadena ni la firma los cubren. El
# resultado es un documento que una persona lee con texto añadido y que la
# herramienta sigue informando como verificado. La primera versión cerró el agujero
# solo dentro de las entradas; el mismo agujero seguía abierto un nivel más arriba.
#
# La regla, entonces, vale para los tres niveles: lo que no está en la lista, no entra.
_CAMPOS_ACTA = frozenset({"esquema", "organizacion", "clave_publica", "entradas", "cierre"})
# `sello` es la única excepción a «todo campo visible entra en la firma», y hay que
# explicar por qué no es una grieta:
#
# El sello de tiempo se pide DESPUÉS de cerrar el acta —sella el `hash_final`, que
# ya está fijo— así que no puede estar dentro de la firma sin circularidad. Pero no
# queda sin cubrir: **se verifica solo**, contra la autoridad que lo emitió, y la
# verificación exige que el resumen sellado coincida con el `hash_final` del acta.
# Un sello ajeno, viejo o de otra acta se cae ahí.
#
# La diferencia con los campos que sí abrieron una grieta es que aquéllos no los
# cubría nada. A éste lo cubre un tercero, que es justamente el punto.
_CAMPOS_CIERRE = frozenset({"cantidad", "hash_final", "firma", "sello",
                            "sello_requerido"})
_CAMPOS_ENTRADA = frozenset({"n", "tipo", "ts", "datos", "hash"})

# Topes de sanidad: un acta legítima de un trabajo real queda muy por debajo.
#: Tope de tamaño del archivo. Un acta de un trabajo real pesa unos pocos cientos de
#: kilobytes; el tope está holgado y existe para que un archivo que llega de afuera no
#: pueda agotar la memoria antes de que ningún otro límite llegue a aplicarse.
MAX_BYTES_ACTA = 64 * 1024 * 1024

#: Dígitos máximos de un número del acta. Los sellos de tiempo en nanosegundos tienen
#: 19; el margen es amplio y el tope existe para que un literal de millones de dígitos
#: no se convierta a entero antes de que ningún otro límite llegue a aplicarse.
_MAX_DIGITOS = 40

_MAX_ENTRADAS = 1_000_000
_MAX_PROFUNDIDAD = 64


# --------------------------------------------------------------------------- #
# Utilidades deterministas
# --------------------------------------------------------------------------- #

#: Controles que no pueden salir por la terminal tal cual vienen del acta.
_CONTROLES = re.compile(
    r"[\x00-\x1f\x7f-\x9f\u200e\u200f\u202a-\u202e\u2066-\u2069]")


def _para_mostrar(texto: str, tope: int = 120) -> str:
    """Deja un texto del acta en condiciones de imprimirse en una terminal.

    La `organizacion` la escribe quien emite el acta y el resumen la interpola tal
    cual. Con secuencias ANSI, retornos de carro o marcas bidireccionales se puede
    escribir un acta que en pantalla dice algo distinto de lo que el programa
    verificó —incluso reescribiendo la línea del veredicto— y funciona aunque el acta
    esté autofirmada y se corra sin clave externa. La salida `--json` no lo necesita:
    el serializador ya escapa.
    """
    limpio = _CONTROLES.sub("\ufffd", str(texto))
    return limpio if len(limpio) <= tope else limpio[:tope] + "…"


def canonico(obj: dict) -> bytes:
    """JSON determinista: claves ordenadas, sin espacios, sin NaN ni infinitos, ASCII.

    La estabilidad byte a byte es un requisito, no una preferencia: si dos
    implementaciones serializan distinto, calculan hashes distintos y el acta deja
    de ser verificable por terceros. `ensure_ascii=True` evita que la codificación
    de un acento cambie los bytes según la plataforma.
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      allow_nan=False, ensure_ascii=True).encode("ascii")


def _lp(valor: str) -> bytes:
    """Prefija con la longitud antes de concatenar.

    Sin esto, ("ab", "c") y ("a", "bc") producirían la misma preimagen y por lo
    tanto el mismo hash. Con la longitud por delante, no hay concatenación ambigua.
    """
    s = "" if valor is None else str(valor)
    return f"{len(s)}:{s}".encode("utf-8")


def cargar_estricto(texto: str) -> dict:
    """Carga un acta rechazando **claves repetidas** en cualquier nivel.

    `json.load` se queda con la última clave repetida, en silencio. Una auditoría de
    publicación midió lo que eso permite: se antepone `{"organizacion": "BANCO
    CENTRAL", …}` a un acta legítima y queda un archivo donde **una persona lee
    «BANCO CENTRAL» y el programa verifica y certifica «acme»** — con
    `ACTA VERIFICADA` delante.

    La lista blanca de campos no lo detecta, porque la duplicación desaparece durante
    el parseo: para cuando el verificador mira el diccionario, la clave repetida ya no
    existe. Hay que atajarlo al leer.

    Es el mismo defecto que persigue todo este proyecto —que lo que se afirma sea más
    fuerte que lo que se comprobó— pero en el punto de entrada, donde el engaño no
    necesita romper ninguna firma.
    """
    def sin_repetidas(pares):
        vistas = set()
        for k, v in pares:
            if k in vistas:
                raise ValueError(
                    f"el acta trae la clave «{_para_mostrar(k, 60)}» repetida en el "
                    "mismo objeto. Un "
                    "archivo así muestra un valor a quien lo lee y otro al programa "
                    "que lo verifica; no se procesa.")
            vistas.add(k)
        return dict(pares)

    def sin_flotantes(literal):
        # `FORMATO.md` dice que no hay números de punto flotante en ninguna parte, y
        # el código los aceptaba. El ataque que abre es concreto: `0.1` y
        # `0.10000000000000001` son el MISMO `float`, así que canonizan igual y
        # producen la misma firma. Cualquiera puede editar ese literal en un acta
        # legítima y el verificador la sigue dando por buena, sin tener la clave
        # privada. Se rechaza al parsear, que es donde el literal todavía existe: una
        # vez convertido a `float`, la información de cómo estaba escrito se perdió.
        raise ValueError(
            f"el acta trae el número «{literal}» con coma decimal o exponente. El "
            "formato admite sólo enteros: dos literales distintos pueden dar el mismo "
            "número de punto flotante y entonces la firma deja de atar lo que dice el "
            "archivo.")

    def entero_acotado(literal):
        # Un acta de 64 MiB puede traer un solo entero de millones de dígitos.
        # Convertirlo cuesta tiempo y memoria desproporcionados, y ocurre ANTES de
        # que se apliquen los límites de entradas y profundidad — para entonces el
        # daño está hecho. Ningún número legítimo de este formato se acerca: los
        # sellos de tiempo en nanosegundos tienen 19 dígitos.
        if len(literal) > _MAX_DIGITOS:
            raise ValueError(
                f"el acta trae un número de {len(literal)} dígitos. Ninguno de este "
                f"formato pasa de {_MAX_DIGITOS}: no se convierte.")
        return int(literal)

    return json.loads(texto, object_pairs_hook=sin_repetidas,
                      parse_float=sin_flotantes, parse_constant=sin_flotantes,
                      parse_int=entero_acotado)


def verificar_archivo(ruta, *, clave_publica_b64: str | None = None) -> "Resultado":
    """Verifica un acta leyéndola de un archivo, con el cargador estricto.

    **Es la forma recomendada desde Python.** `verificar()` recibe un diccionario ya
    parseado, y para entonces las claves repetidas ya desaparecieron: quien haga
    `verificar(json.load(f))` vuelve a quedar expuesto al acta que le muestra una
    organización a la persona y otra al programa. La CLI usa este camino; la API
    pública tenía que ofrecerlo también, porque el README recomendaba el inseguro.
    """
    r = Resultado()
    try:
        # Archivo REGULAR, comprobado con `fstat` sobre el descriptor ya abierto.
        #
        # Esto se agregó primero al archivo de clave y no acá — que es el camino que
        # procesa el archivo hostil, no el otro. Es la tercera vez en esta auditoría
        # que un arreglo cubre la mitad de un camino: la lección es que cuando algo se
        # arregla en un lugar hay que preguntarse dónde MÁS entra lo mismo.
        #
        # Un FIFO o un dispositivo bloquean el proceso para siempre, y el tamaño que
        # `stat` informa para ellos no significa nada.
        import stat as _stat

        fd = os.open(ruta, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
        try:
            if not _stat.S_ISREG(os.fstat(fd).st_mode):
                r.ilegible = True
                r.motivos.append(f"{ruta} no es un archivo regular: no se procesa")
                return r
            fh = os.fdopen(fd, "rb")
            fd = -1                              # lo cierra el `with` de abajo
        finally:
            if fd >= 0:
                os.close(fd)
        with fh:
            # En BINARIO, y el límite en bytes. `fh.read(N)` sobre un archivo abierto
            # en modo texto cuenta CARACTERES: con UTF-8 multibyte un acta puede pesar
            # el triple del tope y pasar igual. `límite + 1` para distinguir «justo en
            # el tope» de «se pasó». Los topes de entradas y de profundidad se aplican
            # DESPUÉS de parsear, así que no protegen de esto: para entonces el
            # archivo ya está adentro.
            bruto = fh.read(MAX_BYTES_ACTA + 1)
        if len(bruto) > MAX_BYTES_ACTA:
            r.ilegible = True
            r.motivos.append(
                f"el acta supera el tope de {MAX_BYTES_ACTA} bytes. Un acta de un "
                "trabajo real queda muy por debajo; algo así no se parsea.")
            return r
        return verificar(cargar_estricto(bruto.decode("utf-8")),
                         clave_publica_b64=clave_publica_b64)
    except (OSError, ValueError, RecursionError, UnicodeDecodeError) as e:
        # La promesa del módulo es que ninguna función pública propaga una excepción.
        # Ésta las propagaba: un archivo ilegible, un JSON con claves repetidas o uno
        # anidado hasta el fondo salían como traceback en vez de como veredicto.
        r.ilegible = True
        r.motivos.append(f"no se pudo leer el acta: {_para_mostrar(str(e), 160)}")
        return r


def _b64d(s: str) -> bytes:
    """Base64 estricto para lo que llega **por un canal externo**: las claves.

    Estricto quiere decir que rechaza lo que no sea base64 válido: sin `validate`,
    `b64decode` descarta en silencio todo carácter ajeno al alfabeto, y entonces
    `!<B64>` da los mismos bytes que `<B64>`.

    Los dos alfabetos —el clásico `+/` y el url-safe `-_`— se aceptan por igual acá, y
    a propósito: una clave pública la publica su dueño, la copia una persona y llega
    en el alfabeto en que se la dieron. Rechazar una clave legítima por su alfabeto
    sería romper el caso bueno.
    """
    return base64.b64decode(s.encode("ascii"), altchars=b"-_", validate=True)


def _b64d_canonico(s: str) -> bytes:
    """Base64 estricto **y de una sola forma**, para lo que viaja DENTRO del acta.

    La diferencia con el de arriba no es un detalle. El README le dice al cliente que
    conservar su copia del acta le da una garantía por sí sola; una revisión midió que
    con el decodificador tolerante eso deja de ser cierto: reescribiendo la firma del
    alfabeto url-safe al clásico quedan **dos archivos distintos byte a byte, con
    sha256 distinto, que los dos informan ACTA VERIFICADA**. El cliente que guarda el
    hash de su copia y después compara ya no distingue una cosa de la otra.

    La clave llega de afuera y hay que ser tolerante con ella. La firma la escribimos
    nosotros al emitir, así que puede exigirse exacta: url-safe, con su relleno, y
    coincidiendo con su propia recodificación.
    """
    crudo = base64.b64decode(s.encode("ascii"), altchars=b"-_", validate=True)
    if base64.urlsafe_b64encode(crudo).decode("ascii") != s:
        raise ValueError("base64 no canónico: se admite una sola representación")
    return crudo


def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii")


# --------------------------------------------------------------------------- #
# Cálculo de la cadena
# --------------------------------------------------------------------------- #

def hash_genesis(organizacion: str, clave_publica_b64: str, esquema: str = ESQUEMA) -> str:
    """Primer eslabón, atado a la organización y a su clave pública.

    Que la organización entre acá es lo que hace que el acta de un cliente no
    pueda presentarse como la de otro: cambia el génesis y se cae toda la cadena.
    """
    pre = _DOM_GENESIS + _lp(esquema) + _lp(organizacion) + _lp(clave_publica_b64)
    return hashlib.sha256(pre).hexdigest()


def hash_entrada(hash_previo: str, entrada: dict) -> str:
    """Eslabón n a partir del eslabón n-1 y del contenido de la entrada.

    **Todo** el contenido de la entrada entra en el cálculo. La única exclusión es
    el propio campo `hash`, porque incluirlo sería circular.

    Una versión anterior excluía además los campos cuyo nombre empezaba con guion
    bajo, para permitir anotaciones de comodidad. Era un error y una auditoría
    adversaria lo marcó: dejaba un canal para inyectar texto **visible para una
    persona pero no cubierto por la firma** — se podía agregar un
    `"_comentario": "el sistema es fraudulento"` a un acta legítima y el verificador
    seguía informando «verificada». En un documento que se presenta como verificado
    no puede haber contenido fuera de la cadena. Si hace falta una anotación, va
    dentro de `datos`, donde queda cubierta.
    """
    cuerpo = {k: v for k, v in entrada.items() if k != "hash"}
    pre = _DOM_ENLACE + _lp(hash_previo) + _lp(canonico(cuerpo).decode("ascii"))
    return hashlib.sha256(pre).hexdigest()


def nucleo_cierre(acta: dict, hash_final: str, cantidad: int,
                  sello_requerido: bool = False) -> dict:
    """El bloque que se firma. Liga la identidad del acta con su estado final.

    Incluye `sello_requerido`, y esa inclusión es lo que cierra un ataque que una
    auditoría marcó como bloqueante: **el sello de tiempo no está firmado por
    nosotros, así que se puede quitar**. Si el verificador tratara un acta sin
    sello como equivalente a una sellada, bastaría con arrancarle el sello para
    borrar justamente la protección contra el emisor — y bloquear la autoridad
    durante la emisión lograría lo mismo, convirtiendo una falla de disponibilidad
    en una pérdida de seguridad.

    Al entrar en la firma, la **política** queda anclada: un acta que declara
    requerir sello y llega sin él es inválida, y esa declaración no se puede
    alterar sin romper la firma.
    """
    return {
        "cantidad": int(cantidad),
        "clave_publica": str(acta.get("clave_publica", "")),
        "esquema": str(acta.get("esquema", "")),
        "hash_final": str(hash_final),
        "organizacion": str(acta.get("organizacion", "")),
        "sello_requerido": bool(sello_requerido),
    }


# --------------------------------------------------------------------------- #
# Resultado
# --------------------------------------------------------------------------- #

@dataclass
class Resultado:
    """Veredicto de una verificación.

    `integra` y `procedencia` son independientes a propósito: un acta puede ser
    autoconsistente sin que podamos probar que la emitimos nosotros.
    """
    integra: bool = False
    procedencia: bool | None = None       # None = no se pudo comprobar; False = falló
    entradas: int = 0
    organizacion: str = ""
    hash_final: str = ""
    sello: bool | None = None      # None = sin sello o sin validar; False = ajeno
    #: El acta declara —dentro de la firma— que tiene que venir sellada.
    sello_requerido: bool = False
    #: No se pudo leer ni parsear el archivo. Es distinto de «no verifica»: hay que
    #: poder distinguirlos sin leer el texto de los motivos, que en parte lo controla
    #: el propio acta.
    ilegible: bool = False
    #: El acta TRAE un sello, lo exija o no. Un sello presente que no se pudo
    #: comprobar impide el veredicto positivo igual: ver `ok`.
    sello_presente: bool = False
    motivos: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        """Verdadero solo si la cadena es íntegra, la procedencia quedó probada **y**
        la política de sello que el acta declara se cumplió de verdad.

        Comprobar la firma contra la clave que viene dentro del mismo archivo no
        prueba procedencia: quien alteró el acta pudo firmarla con su propia clave
        y poner su propia clave pública adentro. Por eso, si no se aportó una clave
        por un canal independiente, `procedencia` queda en `None` y esto es falso.

        Lo del sello es la misma idea aplicada al tercero. Una auditoría lo midió:
        un acta con `sello_requerido: true` y un sello **fabricado** —once bytes
        cualesquiera seguidos del hash final— devolvía `ACTA VERIFICADA` cuando el
        entorno no tenía raíz de confianza configurada, que es el caso por omisión
        de cualquier cliente. `verificar_sello` había devuelto `None` («no lo pude
        comprobar») y sólo se invalidaba con `False`. Otra vez lo mismo: **no medí**
        informado como **está bien**, y encima sobre la única protección que hay
        contra el emisor.

        Con sello obligatorio, sólo `True` alcanza.
        """
        if self.sello_requerido and self.sello is not True:
            return False
        if self.sello_presente and self.sello is not True:
            # Segunda ronda de la misma auditoría: el arreglo de arriba cubría sólo
            # las actas que EXIGEN sello. Un acta que no lo exige pero **trae uno**
            # seguía saliendo «ACTA VERIFICADA» con ese sello sin comprobar adentro.
            #
            # El sello es contenido visible: alguien lo va a leer y va a creer que un
            # tercero certificó la fecha. Si está y no se pudo comprobar, no se puede
            # decir «verificada» a secas. `sello_requerido` decide si se admite que
            # FALTE; que el que está sea válido no es opcional nunca.
            return False
        return bool(self.integra and self.procedencia is True)

    def resumen(self) -> str:
        if self.ok:
            return (f"ACTA VERIFICADA · organización {_para_mostrar(self.organizacion)} · "
                    f"{self.entradas} entradas · cierre {self.hash_final[:16]}…")
        if self.sello_presente and self.sello is None:
            exige = ("declara requerir sello de tiempo y no se pudo comprobar el que "
                     "trae") if self.sello_requerido else (
                     "trae un sello de tiempo que no se pudo comprobar")
            return (f"SELLO NO COMPROBADO · esta acta {exige} · "
                    f"organización {_para_mostrar(self.organizacion)} · {self.entradas} entradas")
        if self.procedencia is False:
            return (f"FIRMA INVÁLIDA · PROCEDENCIA RECHAZADA · "
                    f"organización {_para_mostrar(self.organizacion)} · {self.entradas} entradas")
        if self.integra:
            return (f"CADENA ÍNTEGRA · PROCEDENCIA NO PROBADA · "
                    f"organización {_para_mostrar(self.organizacion)} · {self.entradas} entradas")
        return "ACTA NO VERIFICADA"


# --------------------------------------------------------------------------- #
# Verificación
# --------------------------------------------------------------------------- #

def verificar_integridad(acta: dict) -> Resultado:
    """Nivel 1: la cadena es autoconsistente. Solo biblioteca estándar.

    Detecta entrada alterada, eliminada, insertada, reordenada, y un acta
    presentada bajo una organización que no es la suya.
    """
    r = Resultado()
    try:
        if not isinstance(acta, dict):
            r.motivos.append("el acta no es un objeto")
            return r

        esquema = acta.get("esquema")
        if esquema != ESQUEMA:
            r.motivos.append(f"esquema desconocido: {esquema!r} (se esperaba {ESQUEMA!r})")
            return r

        sobrantes = set(acta) - _CAMPOS_ACTA
        if sobrantes:
            r.motivos.append(
                "el acta trae campos que este formato no reconoce y que la firma no "
                f"cubre: {sorted(sobrantes)}")
            return r

        organizacion = acta.get("organizacion")
        clave_publica = acta.get("clave_publica")
        if not isinstance(organizacion, str) or not organizacion:
            r.motivos.append("falta el identificador de organización")
            return r
        if not isinstance(clave_publica, str) or not clave_publica:
            r.motivos.append("falta la clave pública")
            return r
        r.organizacion = organizacion

        entradas = acta.get("entradas")
        if not isinstance(entradas, list):
            r.motivos.append("las entradas no son una lista")
            return r

        if len(entradas) > _MAX_ENTRADAS:
            r.motivos.append(f"el acta declara más de {_MAX_ENTRADAS} entradas")
            return r

        cierre = acta.get("cierre")
        if not isinstance(cierre, dict):
            r.motivos.append("falta el bloque de cierre")
            return r
        sobrantes_cierre = set(cierre) - _CAMPOS_CIERRE
        if sobrantes_cierre:
            r.motivos.append(
                f"el cierre trae campos no reconocidos: {sorted(sobrantes_cierre)}")
            return r

        # Tipos EXACTOS, no «lo que se pueda convertir». `nucleo_cierre` normaliza
        # con `int(...)` y `bool(...)`, y esas conversiones no son inyectivas: la
        # firma autentica el valor convertido, no el que está escrito en el acta.
        # Una auditoría midió las dos grietas que abre:
        #
        #   `cantidad: 1` → `true`  ..... `bool` es subclase de `int`, así que
        #       `int(True) == 1`: la firma sigue validando y el acta queda VERIFICADA
        #       declarando una cantidad que no es un número.
        #   `sello_requerido: true` → `"x"` ..... `bool("x")` es `True`, así que el
        #       núcleo firmado no cambia; pero la política se lee del acta, y una
        #       cadena no es `True`. Resultado: se desactiva la exigencia de sello
        #       **sin romper la firma**. Ese era el downgrade completo de la única
        #       protección que hay contra el emisor.
        #
        # Se validan acá, antes de cualquier normalización, y con `type(...) is`
        # porque `isinstance(True, int)` es verdadero y no serviría de nada.
        if type(cierre.get("cantidad")) is not int:
            r.motivos.append(
                "el cierre declara una cantidad que no es un número entero "
                f"({type(cierre.get('cantidad')).__name__})")
            return r
        # El campo es OBLIGATORIO, no opcional. Sólo se validaba si estaba presente
        # y su ausencia se normalizaba a `false`: se podía BORRAR de un acta legítima
        # la declaración visible `sello_requerido: false` y la firma seguía valiendo,
        # porque el núcleo firmado calcula el mismo booleano en los dos casos. El acta
        # entregada dejaba de contener lo que la especificación dice que contiene, y
        # dos implementaciones independientes podían discrepar sobre un acta así.
        if type(cierre.get("sello_requerido")) is not bool:
            r.motivos.append(
                "`sello_requerido` tiene que estar, y ser verdadero o falso. Acá "
                + ("falta" if "sello_requerido" not in cierre else
                   f"es {type(cierre['sello_requerido']).__name__}")
                + ": quitarlo o cambiarle el tipo altera la política sin romper la "
                "firma, porque el núcleo firmado calcula el mismo booleano")
            return r
        if "sello" in cierre and not (isinstance(cierre["sello"], str) and cierre["sello"]):
            # Está fuera de la firma a propósito (lo agrega un tercero), así que un
            # valor cualquiera —`[]`, `0`, `""`— pasaba entero sin comprobarse y sin
            # que la rama del sello llegara siquiera a ejecutarse.
            r.motivos.append(
                "el campo `sello` está presente pero no es una cadena base64 con "
                "contenido: o hay un sello, o no está el campo")
            return r

        h = hash_genesis(organizacion, clave_publica, esquema)
        for i, entrada in enumerate(entradas):
            if not isinstance(entrada, dict):
                r.motivos.append(f"la entrada {i} no es un objeto")
                return r
            sobrantes_entrada = set(entrada) - _CAMPOS_ENTRADA
            if sobrantes_entrada:
                r.motivos.append(
                    f"la entrada {i} trae campos no reconocidos: {sorted(sobrantes_entrada)}")
                return r
            if _hay_flotantes(entrada.get("datos")):
                r.motivos.append(
                    f"la entrada {i} trae un número de punto flotante. El formato "
                    "admite sólo enteros: dos literales distintos pueden dar el mismo "
                    "flotante y entonces la firma deja de atar lo que dice el archivo")
                return r
            if _profundidad(entrada.get("datos")) > _MAX_PROFUNDIDAD:
                r.motivos.append(f"los datos de la entrada {i} anidan demasiado")
                return r
            declarado = entrada.get("hash")
            if not (isinstance(declarado, str) and len(declarado) == _LARGO_HASH_HEX):
                r.motivos.append(f"la entrada {i} no declara un hash válido")
                return r
            # `n` tiene que coincidir con la posición real. Que la cadena ya detecte
            # el reordenamiento no alcanza: un `n` que miente es un dato falso que
            # una persona lee en el acta, aunque la cadena cierre.
            # `type(...) is int`: `False == 0` y `True == 1`, así que un booleano
            # pasaba como índice pese a que el formato lo prohíbe explícitamente.
            if type(entrada.get("n")) is not int or entrada["n"] != i:
                r.motivos.append(
                    f"la entrada en la posición {i} dice ser la número {entrada.get('n')!r}")
                return r
            calculado = hash_entrada(h, entrada)
            if not _iguales(calculado, declarado):
                r.motivos.append(
                    f"la cadena se rompe en la entrada {i}: el contenido no corresponde "
                    f"al hash declarado (o falta, sobra o cambió de lugar una entrada anterior)")
                return r
            h = calculado

        cantidad = cierre.get("cantidad")
        if cantidad != len(entradas):
            r.motivos.append(
                f"el cierre declara {cantidad} entradas y el acta trae {len(entradas)}")
            return r

        hash_final = cierre.get("hash_final")
        if not (isinstance(hash_final, str) and _iguales(hash_final, h)):
            r.motivos.append("el hash de cierre no corresponde al final de la cadena")
            return r

        r.integra = True
        r.entradas = len(entradas)
        r.hash_final = h
        return r
    except Exception as e:                                    # fail-closed
        r.integra = False
        r.motivos.append(f"error al procesar el acta: {type(e).__name__}")
        return r


def verificar_procedencia(acta: dict, hash_final: str | None = None,
                          cantidad: int | None = None,
                          clave_publica_b64: str | None = None) -> tuple[bool | None, str]:
    """Nivel 2: la firma prueba que el acta la emitimos nosotros. Requiere `cryptography`.

    **Sin clave aportada por un canal independiente, esta función nunca devuelve
    `True`.** Comprobar la firma contra la clave que viaja dentro del mismo archivo
    es circular: quien manipuló el acta pudo firmarla con una clave propia y dejar
    su clave pública adentro. En ese caso se comprueba la coherencia interna y se
    devuelve `None` — «no probada» —, nunca «probada».

    **Y sin integridad tampoco devuelve `True`.** Esta función es pública —está en
    `__all__`— y confiaba en el `hash_final` y la `cantidad` que le pasara quien la
    llamara. Una auditoría lo midió: tomando un acta válida, alterando sus entradas y
    pasando los valores originales, devolvía `(True, "")` sobre un documento cuya
    integridad es falsa. El módulo promete arriba que «nunca puede tener procedencia
    sin integridad»; quien la usara suelta obtenía justamente eso.

    Ahora, si no se le pasan `hash_final` y `cantidad`, los deriva del acta
    verificando su integridad primero. `verificar()` se los sigue pasando porque
    acaba de calcularlos: no se recorre la cadena dos veces.
    """
    # SIEMPRE se comprueba la integridad, se pasen o no los valores.
    #
    # El arreglo anterior sólo la comprobaba cuando el llamador NO los pasaba, así que
    # el agujero seguía abierto por el otro camino: con un acta alterada y el
    # `hash_final` y la `cantidad` originales, esta función pública devolvía «la
    # emitimos nosotros» sobre un documento cuya cadena no cierra. Arreglar la mitad
    # de un camino deja el camino abierto.
    #
    # `verificar()` no pasa por acá para evitar recorrer la cadena dos veces: usa
    # `_procedencia_de_nucleo_validado`, que es privada justamente porque presupone
    # una integridad ya comprobada. Quien la use de afuera se está saltando el
    # control a propósito, y para eso tiene que escribir un guion bajo.
    r = verificar_integridad(acta)
    if not r.integra:
        return False, ("la cadena del acta no es consistente: sin integridad no "
                       "hay procedencia que valga")
    return _procedencia_de_nucleo_validado(
        acta, r.hash_final, r.entradas, clave_publica_b64)


def _procedencia_de_nucleo_validado(
        acta: dict, hash_final: str, cantidad: int,
        clave_publica_b64: str | None = None) -> tuple[bool | None, str]:
    """Comprueba SÓLO la firma, dando por buena una integridad ya verificada.

    Privada a propósito: presupone que `hash_final` y `cantidad` salen de una
    verificación de integridad que acaba de correr. Con valores traídos de otro lado
    afirma procedencia sobre una cadena que puede no cerrar.
    """
    try:
        firma = (acta.get("cierre") or {}).get("firma")
        if not isinstance(firma, str) or not firma:
            return None, "el acta no trae firma"

        clave_del_acta = str(acta.get("clave_publica", ""))
        clave = clave_publica_b64 or clave_del_acta
        solo_interna = not clave_publica_b64
        if clave_publica_b64:
            # Se comparan los BYTES, no el texto. La misma clave escrita en el
            # alfabeto clásico y en el url-safe son dos cadenas distintas, y comparar
            # el texto rechazaba un acta legítima diciendo «la clave aportada no es la
            # que declara el acta» — que además es un mensaje que manda a buscar una
            # suplantación donde sólo hay una diferencia de codificación.
            try:
                if _b64d(clave_publica_b64) != _b64d(clave_del_acta):
                    return False, "la clave aportada no es la que declara el acta"
            except Exception:
                return False, "la clave aportada o la del acta no son base64 válido"

        try:
            from cryptography.exceptions import InvalidSignature
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        except ImportError:
            return None, ("falta la biblioteca `cryptography` para comprobar la firma; "
                          "la integridad de la cadena sí quedó verificada")

        requerido = bool((acta.get("cierre") or {}).get("sello_requerido", False))
        mensaje = _DOM_CIERRE + canonico(
            nucleo_cierre(acta, hash_final, cantidad, requerido))
        # El prefijo es OBLIGATORIO, no opcional. `FORMATO.md` lo declara y el
        # verificador lo aceptaba de las dos maneras: una firma admitía dos
        # representaciones y la implementación no cumplía su propia especificación.
        if not firma.startswith(PREFIJO_FIRMA):
            return False, (f"la firma no lleva el prefijo «{PREFIJO_FIRMA}» que el "
                           "formato exige")
        cruda = firma[len(PREFIJO_FIRMA):]
        pk = Ed25519PublicKey.from_public_bytes(_b64d(clave))
        try:
            pk.verify(_b64d_canonico(cruda), mensaje)
        except InvalidSignature:
            return False, "la firma no corresponde a esta acta"
        if solo_interna:
            # La firma cierra contra la clave del propio archivo. Es coherencia
            # interna, no origen: no alcanza para dar procedencia por probada.
            return None, ("la firma es coherente con la clave incluida en el acta, pero eso "
                          "no prueba procedencia: aportá con --clave-publica la clave "
                          "publicada por Eleion por un canal independiente")
        return True, ""
    except Exception as e:                                    # fail-closed
        return False, f"error al comprobar la firma: {type(e).__name__}"


def verificar(acta: dict, clave_publica_b64: str | None = None) -> Resultado:
    """Verificación completa: integridad y, si se puede, procedencia."""
    r = verificar_integridad(acta)
    if not r.integra:
        return r
    ok, aviso = _procedencia_de_nucleo_validado(
        acta, r.hash_final, r.entradas, clave_publica_b64)
    r.procedencia = ok
    if aviso:
        r.motivos.append(aviso)

    # Sello de tiempo, si lo trae. Un sello que no corresponde a esta acta la
    # invalida: es más grave que no tener sello, porque alguien intentó pegarle uno.
    cierre = acta.get("cierre") or {}
    # La política viaja al resultado: es lo que hace que un «no lo pude comprobar»
    # no pueda terminar en «ACTA VERIFICADA» (ver `Resultado.ok`).
    r.sello_requerido = cierre.get("sello_requerido") is True
    r.sello_presente = bool(cierre.get("sello"))
    if cierre.get("sello_requerido") and not cierre.get("sello"):
        # Downgrade por eliminación: el acta declara —dentro de la firma— que
        # tiene que venir sellada, y llegó sin sello.
        r.sello = False
        r.integra = False
        r.motivos.append(
            "esta acta declara requerir sello de tiempo y llegó SIN sello: "
            "se lo quitaron, o se emitió sin obtenerlo")
        return r

    sello_b64 = cierre.get("sello")
    if sello_b64:
        try:
            import base64

            from .sello_tiempo import verificar_sello
            # Estricto también acá: `b64decode` sin `validate` descarta la basura
            # intercalada en silencio, igual que en la firma.
            from .sello_tiempo import MAX_BYTES_SELLO

            # El sello NO está cubierto por la firma, así que cualquiera puede pegarle
            # a un acta legítima una cadena enorme y forzar decodificación, archivo
            # temporal y una corrida de OpenSSL. Se acota por el largo codificado,
            # antes de decodificar nada.
            if len(sello_b64) > MAX_BYTES_SELLO * 2:
                r.sello = False
                r.integra = False
                r.motivos.append(
                    f"el sello supera el tope de {MAX_BYTES_SELLO} bytes: un sello "
                    "de tiempo no pesa eso")
                return r
            corresponde, motivo = verificar_sello(_b64d_canonico(sello_b64),
                                                  r.hash_final)
            r.sello = corresponde
            r.motivos.append(f"sello de tiempo: {motivo}")
            if corresponde is False:
                r.integra = False
            elif corresponde is None and r.sello_requerido:
                # No se pudo comprobar (falta OpenSSL, falta raíz de confianza) y el
                # acta declara que el sello es obligatorio. No se toca `integra` —la
                # cadena sí es coherente— pero `ok` es falso: ver `Resultado.ok`.
                r.motivos.append(
                    "esta acta declara requerir sello de tiempo y el sello que trae "
                    "NO se pudo comprobar: no alcanza para darla por verificada")
        except Exception:
            r.sello = False
            r.integra = False
            r.motivos.append("sello de tiempo: no se pudo procesar")
    return r


def _hay_flotantes(obj) -> bool:
    """¿Queda algún número de punto flotante adentro? Ver `cargar_estricto`.

    Hace falta además del filtro del parseo, porque `verificar()` recibe un
    diccionario que puede haber armado cualquiera desde Python.
    """
    if isinstance(obj, float):
        return True
    if isinstance(obj, dict):
        return any(_hay_flotantes(v) for v in obj.values())
    if isinstance(obj, (list, tuple)):
        return any(_hay_flotantes(v) for v in obj)
    return False


def _profundidad(obj, nivel: int = 0) -> int:
    """Profundidad de anidamiento, con corte temprano.

    Serializar una estructura muy anidada agota la pila. El `try` general lo
    convierte en «no verifica», que es correcto pero opaco: conviene decir cuál es
    el problema. El corte en `_MAX_PROFUNDIDAD + 1` evita que medir la profundidad
    tenga el mismo costo que el problema que intenta prevenir.
    """
    if nivel > _MAX_PROFUNDIDAD:
        return nivel
    if isinstance(obj, dict):
        return max((_profundidad(v, nivel + 1) for v in obj.values()), default=nivel)
    if isinstance(obj, (list, tuple)):
        return max((_profundidad(v, nivel + 1) for v in obj), default=nivel)
    return nivel


def _iguales(a: str, b: str) -> bool:
    """Comparación de hashes en tiempo constante.

    Acá no protege un secreto —los hashes son públicos—, pero mantiene el hábito
    y evita que un cambio futuro que sí compare material sensible herede una
    comparación con salida temprana.
    """
    import hmac as _hmac
    return _hmac.compare_digest(str(a), str(b))

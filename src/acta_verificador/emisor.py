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
"""Emisor de referencia de actas de evidencia.

Va junto al verificador y bajo la misma licencia por una razón concreta: **un
formato que solo una implementación puede producir no es un formato abierto**.
Con el emisor a la vista, cualquiera puede generar un acta de prueba, romperla a
propósito y comprobar que el verificador la rechaza. Sin eso, verificar sería un
acto de fe.

Lo que **no** está acá, y es donde vive el valor del producto, es *qué* se mide y
*cómo*. El formato y su verificación son abiertos; el criterio con que se mide, no.

La clave privada nunca se escribe en el acta ni se registra en ningún log.
"""

from __future__ import annotations

import time

from .cadena import (
    ESQUEMA,
    PREFIJO_FIRMA,
    _b64d,
    _b64e,
    _DOM_CIERRE,
    canonico,
    hash_entrada,
    hash_genesis,
    nucleo_cierre,
)


def generar_par_de_claves() -> tuple[str, str]:
    """Devuelve (clave_privada, clave_publica) en base64 urlsafe de los 32 bytes crudos.

    La privada es de quien emite y no debe salir de su poder; la pública viaja en
    el acta y además conviene publicarla por un canal independiente, porque una
    clave que solo existe dentro del acta no prueba procedencia.
    """
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    sk = Ed25519PrivateKey.generate()
    priv = sk.private_bytes(serialization.Encoding.Raw,
                            serialization.PrivateFormat.Raw,
                            serialization.NoEncryption())
    pub = sk.public_key().public_bytes(serialization.Encoding.Raw,
                                       serialization.PublicFormat.Raw)
    return _b64e(priv), _b64e(pub)


class SelloNoObtenido(RuntimeError):
    """Se pidió sello de tiempo y no se consiguió. El acta no se emite.

    Es una excepción y no un aviso a propósito: si esto fuera un aviso, alguien
    terminaría ignorándolo y emitiendo actas sin anclaje sin darse cuenta.
    """


class Acta:
    """Acta en construcción para **una** organización.

    Cada organización lleva su propia cadena. No es una preferencia de diseño: es
    lo que permite entregarle a un cliente su evidencia completa sin filtrarle una
    sola fila de otro, y que lo que se le entrega no verifique bajo los datos de
    ningún tercero.
    """

    def __init__(self, organizacion: str, clave_publica_b64: str) -> None:
        if not organizacion or not isinstance(organizacion, str):
            raise ValueError("hace falta un identificador de organización")
        if not clave_publica_b64 or not isinstance(clave_publica_b64, str):
            raise ValueError("hace falta la clave pública")
        self.organizacion = organizacion
        self.clave_publica = clave_publica_b64
        self.entradas: list[dict] = []
        self._hash = hash_genesis(organizacion, clave_publica_b64, ESQUEMA)

    def agregar(self, tipo: str, datos: dict, ts_ns: int | None = None) -> dict:
        """Añade una medición y la encadena. Devuelve la entrada tal como queda.

        `ts_ns` se puede inyectar para que una corrida sea reproducible; si no se
        pasa, se toma el reloj del sistema.
        """
        if not isinstance(datos, dict):
            raise ValueError("los datos de la entrada deben ser un objeto")
        entrada = {
            "n": len(self.entradas),
            "tipo": str(tipo),
            "ts": int(time.time_ns() if ts_ns is None else ts_ns),
            "datos": datos,
        }
        entrada["hash"] = hash_entrada(self._hash, entrada)
        self._hash = entrada["hash"]
        self.entradas.append(entrada)
        return entrada

    def cerrar(self, clave_privada_b64: str, *,
               sellar_en: str | None = None,
               permitir_sin_sello: bool = False) -> dict:
        """Cierra el acta y la firma. Devuelve el acta completa, lista para entregar.

        Con `sellar_en` se pide además un sello de tiempo a esa autoridad RFC 3161.
        El sello va **fuera** de nuestra firma —se pide después de fijar el cierre,
        así que no puede estar dentro sin circularidad— pero no queda sin cubrir: se
        verifica solo, contra la autoridad, y la comprobación exige que el resumen
        sellado coincida con el cierre de esta acta.

        **Si se pidió sello y la autoridad no responde, esto falla.** No cierra un
        acta sin sello por su cuenta: una auditoría marcó que hacerlo convierte una
        falla de disponibilidad en una pérdida de seguridad — a un atacante le
        bastaría bloquear la autoridad para que el acta saliera sin anclaje externo,
        y el emisor conserva la clave para rehacerla después.

        Para emitir igual hay que pedirlo con `permitir_sin_sello=True`, que es una
        decisión consciente y queda registrada: el acta sale con
        `sello_requerido=False` **dentro de la firma**, así que su condición de acta
        sin anclaje es visible y no se puede disimular después.
        """
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        acta = {
            "esquema": ESQUEMA,
            "organizacion": self.organizacion,
            "clave_publica": self.clave_publica,
            "entradas": self.entradas,
        }
        # La política entra en la firma: si se pidió sello, queda anclado que este
        # acta tiene que venir sellada, y arrancarle el sello la invalida.
        sello_requerido = bool(sellar_en) and not permitir_sin_sello
        nucleo = nucleo_cierre(acta, self._hash, len(self.entradas), sello_requerido)
        sk = Ed25519PrivateKey.from_private_bytes(_b64d(clave_privada_b64))
        firma = PREFIJO_FIRMA + _b64e(sk.sign(_DOM_CIERRE + canonico(nucleo)))
        acta["cierre"] = {
            "cantidad": len(self.entradas),
            "hash_final": self._hash,
            "firma": firma,
            "sello_requerido": sello_requerido,
        }

        if sellar_en:
            from .sello_tiempo import sellar as _sellar
            r = _sellar(self._hash, sellar_en)
            if r.get("ok"):
                # `ok` significa «hubo respuesta y contiene el resumen que pedimos»
                # — el propio `sellar()` lo dice y devuelve `sello_comprobado: False`.
                # Adjuntarlo con eso alcanzaba para emitir un acta «lista para
                # entregar» con un sello inutilizable adentro: el verificador del
                # cliente falla cerrado, así que no se falsifica nada, pero se le
                # entrega evidencia que no va a poder usar. Se valida ACÁ, antes de
                # devolver el acta, que es donde todavía se puede hacer algo.
                from .sello_tiempo import verificar_sello as _verificar_sello

                vale, motivo_sello = _verificar_sello(r["sello_der"], self._hash)
                if vale is True:
                    # url-safe, como el resto del acta y como dice el formato. Con
                    # `b64encode` a secas el emisor producía el alfabeto clásico y el
                    # verificador exigía el otro: la especificación decía una cosa y
                    # las dos puntas hacían otra distinta cada una.
                    acta["cierre"]["sello"] = _b64e(r["sello_der"])
                elif sello_requerido:
                    raise SelloNoObtenido(
                        f"la autoridad respondió pero su sello no vale: {motivo_sello}. "
                        "El acta NO se cerró: entregar un acta que declara requerir "
                        "sello con un sello que no comprueba es entregar evidencia "
                        "inservible.")
                else:
                    # Sin sello obligatorio se sigue, pero el sello que no comprueba
                    # NO se adjunta: un sello que el verificador va a rechazar es peor
                    # que ninguno, porque convierte un acta válida en una que falla.
                    pass
            elif sello_requerido:
                raise SelloNoObtenido(
                    "se pidió sello de tiempo y la autoridad no lo dio: "
                    f"{r.get('motivo', 'sin detalle')}. El acta NO se cerró. Para "
                    "emitir igual, hay que pedirlo explícitamente con "
                    "permitir_sin_sello=True y asumir que queda sin anclaje externo.")
        return acta

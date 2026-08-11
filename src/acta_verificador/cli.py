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
"""Línea de comandos: comprobar un acta de evidencia.

    acta-verificar acta.json
    acta-verificar acta.json --clave-publica <clave publicada por Eleion>
    acta-verificar acta.json --json

Códigos de salida, pensados para encadenar en una tubería:

    0  el acta verifica (cadena íntegra y procedencia probada)
    1  el acta NO verifica
    2  la cadena es íntegra pero la procedencia no se pudo comprobar
    3  no se pudo leer el archivo
"""

from __future__ import annotations

import argparse
import json
import os
import sys

from .cadena import verificar_archivo


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="acta-verificar",
        description="Comprueba un acta de evidencia de Eleion Acta sin necesitar "
                    "ningún secreto ni contactar a nadie.",
        epilog="La clave pública conviene tomarla de un canal distinto del acta: "
               "una clave que solo existe dentro del archivo que se quiere validar "
               "comprueba consistencia interna, no procedencia.")
    p.add_argument("acta", help="archivo del acta en formato JSON")
    p.add_argument("--clave-publica", dest="clave", default=None,
                   help="clave pública de quien emitió, en base64 urlsafe. "
                        "Si empieza con «-», usá --clave-publica=LA_CLAVE (con el "
                        "signo igual) o mejor --clave-publica-archivo")
    p.add_argument("--clave-publica-archivo", dest="clave_archivo", default=None,
                   help="archivo que contiene la clave pública. Es la forma "
                        "recomendada: no depende de cómo el intérprete de órdenes "
                        "trate el valor, y la clave no queda en la lista de procesos")
    p.add_argument("--json", dest="como_json", action="store_true",
                   help="emitir el veredicto en JSON en lugar de texto")
    # argparse sale con 2 ante un argumento mal dado, y 2 es el código que este
    # programa documenta para «cadena íntegra, procedencia no probada». Una tubería que
    # mire sólo el código de salida —que es lo que hace una tubería— lee el estallido
    # como si el acta estuviera bien. Se traduce a 3, que es «no se pudo leer».
    try:
        args = p.parse_args(argv)
    except SystemExit as e:
        return 3 if e.code == 2 else int(e.code or 0)

    # Una clave que empieza con «-» no puede tumbar la demostración.
    #
    # El alfabeto base64 url-safe incluye «-», así que **una de cada 64 claves empieza
    # con guion** y argparse la lee como si fuera otra opción: la orden que el propio
    # producto le imprime al cliente al terminar de exportar fallaba con «expected one
    # argument» delante suyo. Las comillas del LEEME no ayudaban — protegen del
    # intérprete de órdenes, no de argparse.
    #
    # El archivo cierra la clase entera de fallo en vez de un carácter, y de paso saca
    # la clave de la lista de procesos.
    if args.clave_archivo:
        if args.clave:
            print("elegí una de las dos: --clave-publica o --clave-publica-archivo",
                  file=sys.stderr)
            return 3
        # Acotado, como todo lo que llega de afuera. Una clave pública Ed25519 en
        # base64 son 44 caracteres: leer el archivo entero permitía que uno enorme
        # agotara la memoria, y un FIFO o un dispositivo bloqueara el proceso para
        # siempre. Era una regresión respecto del acta, que sí está acotada.
        TOPE = 1024
        try:
            # Archivo REGULAR, y en binario. Abrir un FIFO o un dispositivo bloquea el
            # proceso para siempre, y un tope en modo texto cuenta caracteres, no
            # bytes. Las dos cosas las marcó una auditoría de publicación.
            import stat as _stat

            fd = os.open(args.clave_archivo, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
            try:
                if not _stat.S_ISREG(os.fstat(fd).st_mode):
                    print(f"{args.clave_archivo} no es un archivo regular",
                          file=sys.stderr)
                    return 3
                bruto = os.read(fd, TOPE + 1)
            finally:
                os.close(fd)
            crudo = bruto.decode("utf-8")
        except (OSError, UnicodeDecodeError) as e:
            print(f"no se pudo leer la clave: {e}", file=sys.stderr)
            return 3
        if len(bruto) > TOPE:
            print(f"el archivo {args.clave_archivo} no parece una clave pública: "
                  f"pesa más de {TOPE} bytes", file=sys.stderr)
            return 3
        args.clave = crudo.strip()
        if not args.clave:
            print(f"el archivo {args.clave_archivo} está vacío", file=sys.stderr)
            return 3

    # El MISMO camino acotado que la API: la CLI leía el archivo entero sin límite
    # mientras `verificar_archivo` lo acotaba, y es justamente la CLI la que alguien
    # corre sobre un archivo que le mandaron. Arreglar la mitad de un camino deja el
    # camino abierto — van dos veces en esta auditoría.
    if not os.path.exists(args.acta):
        print(f"no existe el archivo: {args.acta}", file=sys.stderr)
        return 3
    r = verificar_archivo(args.acta, clave_publica_b64=args.clave)
    if r.ilegible:
        # Antes esto se decidía buscando texto dentro de los motivos, y parte de esos
        # motivos los controla el acta: un acta hostil podía hacer que un fallo de
        # verificación se informara como «no se pudo leer», o al revés. El estado
        # viaja como un campo, no como una frase.
        print(f"no se pudo leer el acta: {r.motivos[0]}", file=sys.stderr)
        return 3

    if args.como_json:
        print(json.dumps({
            "verifica": r.ok,
            "integra": r.integra,
            "procedencia": r.procedencia,
            "entradas": r.entradas,
            "organizacion": r.organizacion,
            "hash_final": r.hash_final,
            "motivos": r.motivos,
        }, ensure_ascii=False, indent=2))
    else:
        print(r.resumen())
        for m in r.motivos:
            print(f"  · {m}")

    if r.ok:
        return 0
    if r.integra and r.procedencia is None:
        return 2
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

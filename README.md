# acta-verificador

Comprueba un **acta de evidencia** de Eleion Acta sin necesitar ningún secreto,
sin contactar a nadie y sin permiso de nadie.

Si usted contrató un trabajo de verificación y recibió un acta, esta herramienta
le permite comprobar por su cuenta —o dársela a su auditor para que la compruebe—
que el archivo no fue alterado después de emitido y que lo emitimos nosotros.

**Se publica bajo Apache-2.0 a propósito.** Una verificación que dependiera de
nuestro permiso, de nuestro servidor o de un secreto compartido no sería una
verificación. Si mañana Eleion desaparece, sus actas se siguen pudiendo comprobar.

## Instalación

```bash
# Solo integridad de la cadena: no instala ninguna dependencia
pip install acta-verificador

# Además, comprobar la firma (agrega `cryptography`)
pip install 'acta-verificador[firma]'
```

También funciona **sin instalar nada**: copie el directorio `src/acta_verificador`
al lado del acta y ejecútelo desde ahí. El nivel de integridad no necesita más que
la biblioteca estándar de Python.

## Uso

```bash
# Comprobación completa: hace falta la clave pública que publicamos aparte
acta-verificar acta.json --clave-publica <clave>

# Solo integridad de la cadena (no requiere ninguna biblioteca externa)
acta-verificar acta.json

# Para encadenar en un script
acta-verificar acta.json --clave-publica <clave> --json
```

Códigos de salida:

| Código | Significado |
|---|---|
| `0` | El acta verifica: cadena íntegra **y** procedencia probada. |
| `1` | El acta **no** verifica. |
| `2` | La cadena es íntegra, pero la procedencia no se pudo probar. |
| `3` | No se pudo leer el archivo. |

Desde Python:

```python
from acta_verificador import verificar_archivo

r = verificar_archivo("acta.json", clave_publica_b64=CLAVE)
print(r.ok, r.entradas, r.motivos)
```

Use `verificar_archivo`, no `verificar(json.load(...))`. El cargador de la
biblioteca estándar se queda **en silencio** con la última de dos claves repetidas,
y eso permite escribir un acta que le muestra una organización a quien la abre y
otra al programa que la comprueba. `verificar_archivo` rechaza esos archivos; un
diccionario ya parseado no permite detectarlo, porque para entonces la clave
repetida ya no existe.

## Los dos niveles, y por qué están separados

**Nivel 1 — integridad.** Que el acta sea autoconsistente: ninguna entrada
alterada, eliminada, insertada ni reordenada. Se comprueba **con la biblioteca
estándar de Python únicamente**. Quien audita no instala nada.

**Nivel 2 — procedencia.** Que la hayamos emitido nosotros. Necesita
`cryptography` para comprobar la firma Ed25519.

Un acta puede tener integridad sin procedencia: alguien puede copiar el formato y
armar un acta coherente con su propia clave. **Por eso la clave pública hay que
tomarla de un canal distinto del acta.** Si no se aporta, la herramienta comprueba
la coherencia interna y devuelve «procedencia no probada» — nunca «verificada».
Es la diferencia entre comprobar que un documento no tiene tachaduras y comprobar
quién lo firmó.

## Qué prueba y qué no

**Prueba** que el contenido del acta es exactamente el que se emitió, que está
completo, que las entradas están en el orden en que ocurrieron, que pertenece a la
organización que dice, y —con la clave publicada aparte— que la emitimos nosotros.

**No prueba** que lo medido sea cierto. Un acta firmada de una medición mal hecha
es un acta válida de una medición mal hecha. La cadena garantiza que nadie tocó el
registro después; el criterio de la medición es otra discusión, y se defiende con
el método, no con criptografía. Decir lo contrario sería vender humo con una firma
digital encima.

**Y tampoco protege contra nosotros.** Quien tiene la clave privada puede rehacer
el acta entera —cambiar un número, recalcular todos los eslabones, volver a
firmar— y el resultado verifica igual. Una cadena firmada demuestra integridad
frente a cualquiera *menos frente a quien la produjo*. Lo decimos acá porque es lo
primero que pregunta un auditor riguroso y porque la tentación es no mencionarlo.

Lo que lo resuelve es un **sellado de tiempo de un tercero** (RFC 3161): una
autoridad ajena firma que este hash existía en esta fecha, y a partir de ahí
rehacer el acta deja de ser posible sin que el sello delate el cambio. **Un acta
sin un sello RFC 3161 válido no protege frente a quien la emitió.** En ese caso la
afirmación defendible es «esta acta no fue alterada después de que usted la recibió» —y
conservar su copia al recibirla ya le da a usted esa garantía, sin depender de
nadie.

## Cada organización tiene su propia cadena

El primer eslabón incorpora el identificador de la organización y su clave pública.
Consecuencia buscada: **su acta no verifica bajo los datos de ningún otro cliente**,
y para entregarle lo suyo no hace falta entregarle una sola línea de nadie más. Una
cadena única y global no permitiría eso: para reverificar la propia habría que
recibir la de todos.

## Ejemplo incluido

En `ejemplo/` hay un acta y su clave pública. Pruebe a modificar cualquier número
dentro de `acta-demo.json` y vuelva a correr el verificador: tiene que rechazarla.

## Desarrollo

```bash
python3 -m venv .venv && ./.venv/bin/pip install -e '.[dev]'
./.venv/bin/python -m pytest -q
```

La batería cubre acta intacta, dato alterado, entrada eliminada, entrada insertada
con hash recalculado, reordenamiento, cambio de organización, acta de un cliente
presentada bajo la clave de otro, recorte con cierre recalculado, firma ajena, acta
forjada con clave propia, entradas malformadas de todo tipo, y la propiedad de que
dos organizaciones nunca colisionan en el primer eslabón.

El formato está especificado en [`FORMATO.md`](FORMATO.md) con el detalle necesario
para escribir otra implementación desde cero. Si usted escribe la suya y difiere de
esta, queremos saberlo.

---

Copyright 2026 Eleion · Apache-2.0

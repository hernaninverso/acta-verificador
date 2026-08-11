# Formato del acta de evidencia — `acta-evidencia-1`

Especificación suficiente para escribir otra implementación desde cero, en
cualquier lenguaje, sin mirar nuestro código. Ese es el punto: si la única
implementación posible fuera la nuestra, «verificable por terceros» sería una
figura retórica.

## Estructura

```json
{
  "esquema": "acta-evidencia-1",
  "organizacion": "org-cliente-A",
  "clave_publica": "<base64 urlsafe de 32 bytes crudos Ed25519>",
  "entradas": [
    {
      "n": 0,
      "tipo": "medicion.latencia",
      "ts": 1754800000000000000,
      "datos": { "p50_ms": 118, "p95_ms": 341 },
      "hash": "<64 caracteres hexadecimales>"
    }
  ],
  "cierre": {
    "cantidad": 1,
    "hash_final": "<64 caracteres hexadecimales>",
    "firma": "acta1_<base64 urlsafe de 64 bytes crudos>",
    "sello_requerido": false,
    "sello": "<base64 del sello RFC 3161 — opcional>"
  }
}
```

`ts` son nanosegundos desde la época. `datos` es libre: lo define cada tipo de
medición. `n` debe coincidir con la posición de la entrada en la lista, empezando
en cero.

## Campos permitidos: lista cerrada en los tres niveles

| Nivel | Campos admitidos |
|---|---|
| Raíz del acta | `esquema`, `organizacion`, `clave_publica`, `entradas`, `cierre` |
| `cierre` | `cantidad`, `hash_final`, `firma`, `sello_requerido`, `sello` |
| Cada entrada | `n`, `tipo`, `ts`, `datos`, `hash` |

**Cualquier campo fuera de estas listas invalida el acta.** No es rigidez
gratuita: dos rondas de revisión adversaria mostraron que aceptar campos no
reconocidos abre un canal para inyectar texto **visible para una persona y no
cubierto por la firma**. Se podía agregar un `"_comentario"` a un acta legítima
—en una entrada o en la raíz— y la herramienta seguía informando «verificada».
La segunda ronda encontró además que dos actas que diferían solo en una clave
extra de primer nivel producían el mismo núcleo firmado y **compartían una firma
válida**.

La regla general que se sigue de ahí: **lista blanca, nunca lista negra**. Si
hace falta guardar algo más, va dentro de `datos`, que sí entra en la cadena.

**Todo el contenido de una entrada entra en el cálculo del hash**, sin excepción
salvo el propio campo `hash` (incluirlo sería circular).

## Topes

Un acta con más de 1.000.000 de entradas, o con `datos` anidados a más de 64
niveles, se rechaza. Serializar una estructura muy anidada agota la pila; el
comportamiento fail-closed lo cubriría igual, pero conviene decir cuál es el
problema en vez de devolver un error genérico.

## JSON canónico

Toda serialización que entre en un hash o en una firma se hace así, sin excepción:

- claves ordenadas alfabéticamente;
- separadores `,` y `:` sin espacios;
- `NaN` e infinitos **rechazados**, no serializados;
- salida ASCII: los caracteres no ASCII se escapan (`\uXXXX`).

La estabilidad byte a byte no es una preferencia. Si dos implementaciones
serializan distinto, calculan hashes distintos y el acta deja de ser verificable
por terceros.

## Prefijo de longitud

Antes de concatenar dos cadenas para formar la preimagen de un hash, cada una se
prefija con su longitud en caracteres:

```
lp(s) = utf8( str(len(s)) + ":" + s )
```

Sin esto, `("ab", "c")` y `("a", "bc")` producirían la misma preimagen y por lo
tanto el mismo hash. Con la longitud por delante, no hay concatenación ambigua.

## Separación de dominio

Cada uso del hash lleva su propio prefijo de bytes, de modo que dos usos distintos
nunca compartan preimagen:

```
GENESIS = b"acta-genesis-1:"
ENLACE  = b"acta-enlace-1:"
CIERRE  = b"acta-cierre-1:"
```

## La cadena

**Primer eslabón** (no aparece en el archivo; se recalcula al verificar):

```
h₋₁ = SHA256( GENESIS ‖ lp(esquema) ‖ lp(organizacion) ‖ lp(clave_publica) )
```

Que la organización y su clave entren acá es lo que ata el acta a un cliente: el
acta de A no verifica bajo los datos de B.

**Eslabón n**, para cada entrada en orden:

```
cuerpo = entrada sin el campo "hash"   (todo lo demás entra, sin excepción)
hₙ = SHA256( ENLACE ‖ lp(hₙ₋₁) ‖ lp(canonico(cuerpo)) )
```

El valor `hₙ` es lo que la entrada declara en su campo `hash`. Además, `n` debe
ser igual a la posición de la entrada: un índice que miente es un dato falso
aunque la cadena cierre.

**Cierre**: `hash_final` debe ser igual al último `hₙ` calculado, y `cantidad`
igual al número de entradas.

**Los tipos son exactos, y esto no es pedantería.** Una revisión adversaria midió lo
que pasa si no lo son:

| Campo | Tipo | Qué pasaba sin exigirlo |
|---|---|---|
| `cantidad` | entero, y `true` **no** es un entero | `bool` es subclase de `int` en varios lenguajes: con `cantidad: true`, `int(True) == 1` y la firma seguía validando. El acta quedaba verificada declarando una cantidad que no es un número. |
| `sello_requerido` | booleano, y `"false"` **no** es un booleano | `bool("false")` es verdadero: el núcleo firmado no cambiaba, pero la política se lee del acta. Reemplazar `true` por cualquier cadena **apagaba la exigencia de sello sin romper la firma**. |
| `sello` | si está presente, cadena base64 no vacía | Viaja fuera de la firma a propósito, así que un `[]`, un `0` o un `""` pasaban enteros: la rama que comprueba el sello ni llegaba a ejecutarse. |
| `n` | entero igual a la posición | ídem `cantidad`: un booleano pasaba como índice cero. |

Una implementación que convierta con `int(...)` o `bool(...)` antes de comparar
reproduce estos agujeros. Hay que validar el tipo **antes** de cualquier conversión.

**El base64 se decodifica estricto.** Un decodificador que descarte en silencio los
caracteres fuera del alfabeto —el comportamiento por omisión en Python y en varias
bibliotecas— hace que `acta1_!<B64>` produzca exactamente los mismos bytes que
`acta1_<B64>`: dos actas distintas byte a byte que verifican igual. Hay que rechazar
lo que no sea base64 válido y comprobar que la recodificación coincida.

**La regla es distinta según de dónde venga el dato, y una implementación
independiente tiene que respetar las dos:**

- La **firma** y el **sello** viajan dentro del acta y los escribe quien emite: se
  exige base64 **url-safe canónico con relleno**, y el prefijo `acta1_` en la firma.
  Una sola representación por firma. Si se admitieran las dos, existirían dos
  archivos distintos byte a byte —con sha256 distinto— que verifican igual, y este
  formato le dice al receptor que conservar su copia le sirve de algo.
- La **clave pública** llega por un canal aparte, la publica su dueño y la copia una
  persona: se aceptan los dos alfabetos, y la comparación contra la clave que declara
  el acta se hace sobre los **bytes decodificados**, nunca sobre el texto.

Nada de esto vuelve único al archivo JSON: cambiar espacios o el orden de las claves
produce bytes distintos con el mismo contenido verificado. Lo que el formato garantiza
es integridad semántica del contenido, no identidad byte a byte del archivo.

## Qué es exactamente «canónico», para quien reimplemente esto

Una revisión adversaria señaló que sin esto no se puede escribir un verificador
compatible en otro lenguaje, y tenía razón. Reglas, todas obligatorias:

- **Claves ordenadas** por su secuencia de puntos de código Unicode (no por
  configuración regional), sin espacios entre elementos: separadores `,` y `:` sin
  blancos alrededor.
- **`ensure_ascii`**: todo carácter fuera de ASCII se escribe escapado (`\uXXXX`), y
  los pares suplentes de un carácter astral se escriben como dos escapes. Así los
  bytes no dependen de la codificación del archivo.
- **Sólo enteros.** No hay números de punto flotante en ninguna parte del acta, y
  `NaN` e infinitos se rechazan. **Esto importa más de lo que parece**: los sellos de
  tiempo van en nanosegundos y superan `2^53`, donde un entorno que use el número de
  coma flotante de doble precisión —JavaScript, por ejemplo— deja de distinguir dos
  enteros contiguos. Una implementación así calcularía el mismo hash para dos actas
  distintas. Quien reimplemente esto tiene que usar enteros de precisión arbitraria y
  parsear los números del JSON como enteros, nunca como `double`.
- **El prefijo de longitud cuenta puntos de código Unicode**, no unidades UTF-16 ni
  bytes. En un lenguaje cuyas cadenas sean UTF-16 hay que convertir antes de contar.
- **Tipos exactos**: donde el formato dice entero, un booleano no vale, aunque el
  lenguaje los trate como intercambiables.

## La firma

Se firma con Ed25519 el mensaje:

```
CIERRE ‖ canonico({
  "cantidad":        <entero>,
  "clave_publica":   <texto>,
  "esquema":         <texto>,
  "hash_final":      <texto>,
  "organizacion":    <texto>,
  "sello_requerido": <booleano>
})
```

La firma se guarda en base64 urlsafe con el prefijo `acta1_`.

Que `sello_requerido` entre en la firma **no es un detalle de forma**: cierra un
ataque que una revisión adversaria marcó como bloqueante. El sello de tiempo no lo
firma el emisor —se pide después de fijar el cierre—, así que **se puede arrancar**.
Si una implementación tratara un acta sin sello como equivalente a una sellada,
bastaría con quitárselo para borrar justamente la protección contra el emisor; y
bloquear la autoridad durante la emisión lograría lo mismo, convirtiendo una falla
de disponibilidad en una pérdida de seguridad.

Al estar dentro de la firma, la **política** queda anclada: un acta que declara
requerir sello y llega sin él es inválida, y esa declaración no se puede bajar sin
romper la firma.

## El sello de tiempo

`sello` es el único campo visible que **no** entra en la firma del emisor. No es una
grieta como las que se cerraron con la lista blanca, porque **lo cubre un tercero**:
la verificación exige que la autoridad haya firmado *este* resumen, comprobándolo
con

```
openssl ts -verify -digest <hash_final> -in <sello> -CAfile <raíz de confianza>
```

Tres condiciones que una implementación correcta **debe** respetar:

0. **Un sello que está y no se pudo comprobar impide el veredicto positivo.** No sólo
   cuando el acta lo declara obligatorio: `sello_requerido` decide si se admite que el
   sello **falte**, no si el que está puede quedar sin comprobar. El sello es contenido
   visible —alguien lo lee y cree que un tercero certificó la fecha— así que un acta
   que lo trae sin validar no puede informarse como verificada. Se midió: con un sello
   fabricado de once bytes y sin raíz de confianza configurada —el caso por omisión de
   cualquier instalación nueva— el veredicto era «acta verificada».

1. **La raíz de confianza es obligatoria.** Sin `-CAfile` propio se aceptaría un
   sello firmado por cualquier certificado incluido *en el propio sello*: una firma
   matemáticamente válida de una autoridad que nadie eligió. Confiar en el
   certificado que viene dentro del documento que se quiere validar es circular.
2. **No se decide con una búsqueda por patrón sobre los bytes.** Buscar el
   identificador de SHA-256 y tomar el resumen que le sigue es engañable: se puede
   anteponer ese patrón a un sello genuino de otro documento. Sirve solo como
   **filtro de rechazo** —si el resumen esperado ni aparece, se descarta sin
   criptografía— y jamás para aceptar.

El prefijo tiene un motivo práctico además del versionado: una firma en base64
urlsafe puede empezar con `-` (aproximadamente una de cada 64), y cualquier
intérprete de argumentos de línea de comandos la tomaría por una opción. Con el
prefijo, siempre empieza por letra.

## Procedimiento de verificación

1. Comprobar que `esquema` es `acta-evidencia-1`. Si no, rechazar.
2. Recalcular el primer eslabón a partir de `organizacion`, `clave_publica` y `esquema`.
3. Recorrer las entradas **en el orden en que aparecen**, recalculando cada `hₙ` y
   comparándolo con el `hash` declarado. Ante la primera diferencia, rechazar
   indicando el índice.
4. Comprobar que `cierre.cantidad` coincide con el número de entradas.
5. Comprobar que `cierre.hash_final` coincide con el último eslabón calculado.
6. Reconstruir el núcleo de cierre —incluyendo `sello_requerido`— y comprobar la
   firma Ed25519 contra la clave pública **aportada por un canal independiente**.
7. Si `sello_requerido` es verdadero y no hay `sello`: **rechazar**. Se lo quitaron,
   o se emitió sin obtenerlo.
8. Si hay `sello`, validarlo como se describe arriba. Un sello que no corresponde
   **invalida el acta**: pegarle uno ajeno es peor que no tener ninguno, porque
   alguien intentó hacerla pasar por sellada.

Si el paso 6 se hace con la clave que viene dentro del propio archivo, el resultado
comprueba coherencia interna y **no** procedencia: quien manipuló el acta pudo
firmarla con una clave propia y dejar su clave pública adentro. Una implementación
correcta **no debe informar «verificada» en ese caso**.

## Comportamiento exigido ante errores

La verificación **nunca** debe propagar una excepción al llamador. Ante entrada
malformada, tipos inesperados, campos faltantes o datos truncados, el veredicto es
«no verifica», con motivo. Un verificador que se cae es un verificador que no dice
que no.

## Qué detecta este diseño

| Manipulación | Cómo se detecta |
|---|---|
| Un dato alterado | El `hash` de esa entrada deja de corresponder |
| Una entrada eliminada | Se rompe el encadenado a partir de ahí |
| Una entrada insertada | Ídem, aunque se le recalcule su propio hash |
| Entradas reordenadas | Ídem |
| Cambio de organización | Cambia el primer eslabón y cae toda la cadena |
| Acta de otro cliente | No verifica contra la clave ni la organización propias |
| Recorte del final | La cadena queda coherente, pero **la firma del cierre no** |
| Acta forjada completa | Es coherente consigo misma, pero no valida contra la clave publicada |
| Quitarle el sello | Si el acta declara requerirlo, se rechaza: la declaración está firmada |
| Pegarle un sello ajeno | El resumen sellado no coincide con el cierre |
| Que la rehaga el propio emisor | **Solo lo detecta el sello de tiempo.** Sin sello, no se detecta |

El recorte merece una nota: una cadena recortada **es** internamente consistente, y
está bien que lo sea. Lo que lo delata es la firma del cierre, que quien recorta no
puede rehacer sin la clave privada. Por eso el cierre se firma y no solo se calcula.

## Límites explícitos

**Primero.** Este formato garantiza que el registro no fue alterado **por un
tercero** después de emitido. No dice nada sobre si lo registrado es cierto. La
validez de la medición se defiende con el método y con la posibilidad de repetirla,
no con una firma.

**Segundo, y es el que hay que decir en voz alta: la cadena no protege contra el
emisor.** Quien tiene la clave privada puede rehacer el acta entera —cambiar una
medición, recalcular todos los eslabones y volver a firmar— y el resultado
verifica perfectamente. Una cadena de hashes firmada demuestra integridad frente a
cualquiera **menos frente a quien la produjo**.

Esto importa porque es justamente lo que un auditor riguroso va a preguntar, y
porque la tentación comercial es no mencionarlo. Un acta nuestra prueba que *el
cliente* o un intermediario no la tocaron. No prueba, por sí sola, que nosotros no
la rehicimos.

**Qué lo mitiga de verdad**, en orden de fuerza:

1. **Sellado de tiempo de un tercero** (RFC 3161): una autoridad ajena firma que
   este hash existía en esta fecha. A partir de ahí no podemos rehacer el acta sin
   que el sello deje de coincidir. Es la mitigación real: **un acta sin un sello
   válido no protege frente a quien la emitió.**
2. **Registro de transparencia**: publicar los hashes de cierre en un registro
   público de solo agregado, para que rehacer un acta vieja sea detectable.
3. **Que el cliente conserve su copia** al momento de la entrega y compare después.
   Simple, sin infraestructura, y sorprendentemente efectivo.

Hasta que exista lo primero, la afirmación defendible es «esta acta no fue
alterada después de que usted la recibió», no «esta acta es incontrovertible».

---

Copyright 2026 Eleion · Apache-2.0

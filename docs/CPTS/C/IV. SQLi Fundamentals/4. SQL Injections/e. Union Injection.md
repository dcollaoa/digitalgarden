Ahora que sabemos cómo funciona la cláusula Union y cómo usarla, aprendamos a utilizarla en nuestras inyecciones SQL. Tomemos el siguiente ejemplo:

`http://SERVER_IP:PORT/search.php?port_code=cn`

![](https://academy.hackthebox.com/storage/modules/33/ports_cn.png)

Vemos una posible inyección SQL en los parámetros de búsqueda. Aplicamos los pasos de descubrimiento de SQLi inyectando una comilla simple (`'`), y obtenemos un error:

`http://SERVER_IP:PORT/search.php?port_code=cn`

![](https://academy.hackthebox.com/storage/modules/33/ports_quote.png)

Dado que causamos un error, esto puede significar que la página es vulnerable a la inyección SQL. Este escenario es ideal para la explotación a través de inyección basada en Union, ya que podemos ver los resultados de nuestras consultas.

---

## Detectar el número de columnas

Antes de proceder y explotar las consultas basadas en Union, necesitamos encontrar el número de columnas seleccionadas por el servidor. Hay dos métodos para detectar el número de columnas:

- Usando `ORDER BY`
- Usando `UNION`

### Usando ORDER BY

La primera forma de detectar el número de columnas es mediante la función `ORDER BY`, que discutimos anteriormente. Tenemos que inyectar una consulta que ordene los resultados por una columna especificada, 'es decir, columna 1, columna 2, y así sucesivamente', hasta que obtengamos un error diciendo que la columna especificada no existe.

Por ejemplo, podemos comenzar con `order by 1`, ordenar por la primera columna, y tener éxito, ya que la tabla debe tener al menos una columna. Luego haremos `order by 2` y luego `order by 3` hasta que lleguemos a un número que devuelva un error, o la página no muestre ninguna salida, lo que significa que ese número de columna no existe. La última columna que ordenamos con éxito nos da el número total de columnas.

Si fallamos en `order by 4`, esto significa que la tabla tiene tres columnas, que es el número de columnas por las que pudimos ordenar con éxito. Regresemos a nuestro ejemplo anterior e intentemos lo mismo, con el siguiente payload:

```r
' order by 1-- -
```

Recordatorio: Estamos agregando un guion extra (-) al final, para mostrar que hay un espacio después de (--).

Como vemos, obtenemos un resultado normal:

`http://SERVER_IP:PORT/search.php?port_code=`

![](https://academy.hackthebox.com/storage/modules/33/ports_cn.png)

A continuación, intentemos ordenar por la segunda columna, con el siguiente payload:

```r
' order by 2-- -
```

Aún obtenemos resultados. Notamos que están ordenados de manera diferente, como se esperaba:

`http://SERVER_IP:PORT/search.php?port_code=`

![](https://academy.hackthebox.com/storage/modules/33/order_by_2.jpg)

Hacemos lo mismo para las columnas `3` y `4` y obtenemos los resultados. Sin embargo, cuando intentamos `ORDER BY` columna 5, obtenemos el siguiente error:

`http://SERVER_IP:PORT/search.php?port_code=cn`

![](https://academy.hackthebox.com/storage/modules/33/order_by_5.jpg)

Esto significa que esta tabla tiene exactamente 4 columnas.

### Usando UNION

El otro método es intentar una inyección Union con un número diferente de columnas hasta que obtengamos los resultados con éxito. El primer método siempre devuelve los resultados hasta que encontramos un error, mientras que este método siempre da un error hasta que tenemos éxito. Podemos comenzar inyectando una consulta `UNION` de 3 columnas:

```r
cn' UNION select 1,2,3-- -
```

Obtenemos un error diciendo que el número de columnas no coincide:

`http://SERVER_IP:PORT/search.php?port_code=cn`

![](https://academy.hackthebox.com/storage/modules/33/ports_columns_diff.png)

Entonces, intentemos con cuatro columnas y veamos la respuesta:

```r
cn' UNION select 1,2,3,4-- -
```

`http://SERVER_IP:PORT/search.php?port_code=cn`

![](https://academy.hackthebox.com/storage/modules/33/ports_columns_correct.png)

Esta vez obtenemos los resultados con éxito, lo que significa una vez más que la tabla tiene 4 columnas. Podemos usar cualquiera de los métodos para determinar el número de columnas. Una vez que sabemos el número de columnas, sabemos cómo formar nuestro payload, y podemos proceder al siguiente paso.

---

## Ubicación de la inyección

Mientras una consulta puede devolver múltiples columnas, la aplicación web puede mostrar solo algunas de ellas. Entonces, si inyectamos nuestra consulta en una columna que no se imprime en la página, no obtendremos su salida. Por eso necesitamos determinar qué columnas se imprimen en la página, para saber dónde colocar nuestra inyección. En el ejemplo anterior, mientras la consulta inyectada devolvía 1, 2, 3, y 4, solo vimos 2, 3 y 4 mostradas en la página como datos de salida:

`http://SERVER_IP:PORT/search.php?port_code=cn`

![](https://academy.hackthebox.com/storage/modules/33/ports_columns_correct.png)

Es muy común que no todas las columnas se muestren al usuario. Por ejemplo, el campo ID a menudo se usa para vincular diferentes tablas, pero el usuario no necesita verlo. Esto nos dice que las columnas 2, 3 y 4 se imprimen, por lo que debemos colocar nuestra inyección en cualquiera de ellas. No podemos colocar nuestra inyección al principio, o su salida no se imprimirá.

Este es el beneficio de usar números como nuestros datos basura, ya que facilita el seguimiento de qué columnas se imprimen, por lo que sabemos en qué columna colocar nuestra consulta. Para probar que podemos obtener datos reales de la base de datos 'en lugar de solo números,' podemos usar la consulta SQL `@@version` como prueba y colocarla en la segunda columna en lugar del número 2:

```r
cn' UNION select 1,@@version,3,4-- -
```

`http://SERVER_IP:PORT/search.php?port_code=cn`

![](https://academy.hackthebox.com/storage/modules/33/db_version_1.jpg)

Como podemos ver, podemos obtener la versión de la base de datos mostrada. Ahora sabemos cómo formar nuestros payloads de inyección SQL Union para obtener con éxito la salida de nuestra consulta impresa en la página. En la siguiente sección, discutiremos cómo enumerar la base de datos y obtener datos de otras tablas y bases de datos.
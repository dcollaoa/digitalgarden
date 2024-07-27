En esta sección, aprenderemos cómo controlar la salida de los resultados de cualquier consulta.

---

## Sorting Results

Podemos ordenar los resultados de cualquier consulta usando [ORDER BY](https://dev.mysql.com/doc/refman/8.0/en/order-by-optimization.html) y especificando la columna por la que se desea ordenar:

```r
mysql> SELECT * FROM logins ORDER BY password;

+----+---------------+------------+---------------------+
| id | username      | password   | date_of_joining     |
+----+---------------+------------+---------------------+
|  2 | administrator | adm1n_p@ss | 2020-07-02 11:30:50 |
|  3 | john          | john123!   | 2020-07-02 11:47:16 |
|  1 | admin         | p@ssw0rd   | 2020-07-02 00:00:00 |
|  4 | tom           | tom123!    | 2020-07-02 11:47:16 |
+----+---------------+------------+---------------------+
4 rows in set (0.00 sec)
```

Por defecto, la ordenación se realiza en orden ascendente, pero también podemos ordenar los resultados usando `ASC` o `DESC`:

```r
mysql> SELECT * FROM logins ORDER BY password DESC;

+----+---------------+------------+---------------------+
| id | username      | password   | date_of_joining     |
+----+---------------+------------+---------------------+
|  4 | tom           | tom123!    | 2020-07-02 11:47:16 |
|  1 | admin         | p@ssw0rd   | 2020-07-02 00:00:00 |
|  3 | john          | john123!   | 2020-07-02 11:47:16 |
|  2 | administrator | adm1n_p@ss | 2020-07-02 11:30:50 |
+----+---------------+------------+---------------------+
4 rows in set (0.00 sec)
```

También es posible ordenar por múltiples columnas, para tener una ordenación secundaria para valores duplicados en una columna:

```r
mysql> SELECT * FROM logins ORDER BY password DESC, id ASC;

+----+---------------+-----------------+---------------------+
| id | username      | password        | date_of_joining     |
+----+---------------+-----------------+---------------------+
|  1 | admin         | p@ssw0rd        | 2020-07-02 00:00:00 |
|  2 | administrator | change_password | 2020-07-02 11:30:50 |
|  3 | john          | change_password | 2020-07-02 11:47:16 |
|  4 | tom           | change_password | 2020-07-02 11:50:20 |
+----+---------------+-----------------+---------------------+
4 rows in set (0.00 sec)
```

---

## LIMIT results

En caso de que nuestra consulta devuelva una gran cantidad de registros, podemos [LIMIT](https://dev.mysql.com/doc/refman/8.0/en/limit-optimization.html) los resultados a lo que queramos, usando `LIMIT` y el número de registros que queremos:

```r
mysql> SELECT * FROM logins LIMIT 2;

+----+---------------+------------+---------------------+
| id | username      | password   | date_of_joining     |
+----+---------------+------------+---------------------+
|  1 | admin         | p@ssw0rd   | 2020-07-02 00:00:00 |
|  2 | administrator | adm1n_p@ss | 2020-07-02 11:30:50 |
+----+---------------+------------+---------------------+
2 rows in set (0.00 sec)
```

Si quisiéramos limitar los resultados con un offset, podríamos especificar el offset antes del límite de conteo:

```r
mysql> SELECT * FROM logins LIMIT 1, 2;

+----+---------------+------------+---------------------+
| id | username      | password   | date_of_joining     |
+----+---------------+------------+---------------------+
|  2 | administrator | adm1n_p@ss | 2020-07-02 11:30:50 |
|  3 | john          | john123!   | 2020-07-02 11:47:16 |
+----+---------------+------------+---------------------+
2 rows in set (0.00 sec)
```

Nota: el offset marca el orden del primer registro que se incluirá, comenzando desde 0. Para el ejemplo anterior, comienza e incluye el segundo registro, y devuelve dos valores.

---

## WHERE Clause

Para filtrar o buscar datos específicos, podemos usar condiciones con la sentencia `SELECT` usando la cláusula [WHERE](https://dev.mysql.com/doc/refman/8.0/en/where-optimization.html), para afinar los resultados:

```r
SELECT * FROM table_name WHERE <condition>;
```

La consulta anterior devolverá todos los registros que cumplan con la condición dada. Veamos un ejemplo:

```r
mysql> SELECT * FROM logins WHERE id > 1;

+----+---------------+------------+---------------------+
| id | username      | password   | date_of_joining     |
+----+---------------+------------+---------------------+
|  2 | administrator | adm1n_p@ss | 2020-07-02 11:30:50 |
|  3 | john          | john123!   | 2020-07-02 11:47:16 |
|  4 | tom           | tom123!    | 2020-07-02 11:47:16 |
+----+---------------+------------+---------------------+
3 rows in set (0.00 sec)
```

El ejemplo anterior selecciona todos los registros donde el valor de `id` es mayor que `1`. Como podemos ver, la primera fila con su `id` como 1 se omitió en la salida. Podemos hacer algo similar para usernames:

```r
mysql> SELECT * FROM logins where username = 'admin';

+----+----------+----------+---------------------+
| id | username | password | date_of_joining     |
+----+----------+----------+---------------------+
|  1 | admin    | p@ssw0rd | 2020-07-02 00:00:00 |
+----+----------+----------+---------------------+
1 row in set (0.00 sec)
```

La consulta anterior selecciona el registro donde el username es `admin`. Podemos usar la sentencia `UPDATE` para actualizar ciertos registros que cumplan con una condición específica.

Nota: los tipos de datos string y date deben estar rodeados por comillas simples (') o comillas dobles ("), mientras que los números se pueden usar directamente.

---

## LIKE Clause

Otra cláusula SQL útil es [LIKE](https://dev.mysql.com/doc/refman/8.0/en/pattern-matching.html), que permite seleccionar registros coincidiendo con un cierto patrón. La consulta a continuación recupera todos los registros con usernames que comienzan con `admin`:

```r
mysql> SELECT * FROM logins WHERE username LIKE 'admin%';

+----+---------------+------------+---------------------+
| id | username      | password   | date_of_joining     |
+----+---------------+------------+---------------------+
|  1 | admin         | p@ssw0rd   | 2020-07-02 00:00:00 |
|  4 | administrator | adm1n_p@ss | 2020-07-02 15:19:02 |
+----+---------------+------------+---------------------+
2 rows in set (0.00 sec)
```

El símbolo `%` actúa como un wildcard y coincide con todos los caracteres después de `admin`. Se utiliza para coincidir con cero o más caracteres. De manera similar, el símbolo `_` se utiliza para coincidir exactamente con un carácter. La consulta a continuación coincide con todos los usernames con exactamente tres caracteres en ellos, que en este caso fue `tom`:

```r
mysql> SELECT * FROM logins WHERE username like '___';

+----+----------+----------+---------------------+
| id | username | password | date_of_joining     |
+----+----------+----------+---------------------+
|  3 | tom      | tom123!  | 2020-07-02 15:18:56 |
+----+----------+----------+---------------------+
1 row in set (0.01 sec)
```
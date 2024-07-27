A veces, las expresiones con una sola condición no son suficientes para satisfacer los requisitos del usuario. Para eso, SQL admite [Logical Operators](https://dev.mysql.com/doc/refman/8.0/en/logical-operators.html) para usar múltiples condiciones a la vez. Los operadores lógicos más comunes son `AND`, `OR` y `NOT`.

---

## AND Operator

El operador `AND` toma dos condiciones y devuelve `true` o `false` según su evaluación:

```r
condition1 AND condition2
```

El resultado de la operación `AND` es `true` si y solo si tanto `condition1` como `condition2` se evalúan como `true`:

```r
mysql> SELECT 1 = 1 AND 'test' = 'test';

+---------------------------+
| 1 = 1 AND 'test' = 'test' |
+---------------------------+
|                         1 |
+---------------------------+
1 row in set (0.00 sec)

mysql> SELECT 1 = 1 AND 'test' = 'abc';

+--------------------------+
| 1 = 1 AND 'test' = 'abc' |
+--------------------------+
|                        0 |
+--------------------------+
1 row in set (0.00 sec)
```

En términos de MySQL, cualquier valor `non-zero` se considera `true`, y generalmente devuelve el valor `1` para significar `true`. `0` se considera `false`. Como podemos ver en el ejemplo anterior, la primera consulta devolvió `true` ya que ambas expresiones se evaluaron como `true`. Sin embargo, la segunda consulta devolvió `false` ya que la segunda condición `'test' = 'abc'` es `false`.

---

## OR Operator

El operador `OR` también toma dos expresiones y devuelve `true` cuando al menos una de ellas se evalúa como `true`:

```r
mysql> SELECT 1 = 1 OR 'test' = 'abc';

+-------------------------+
| 1 = 1 OR 'test' = 'abc' |
+-------------------------+
|                       1 |
+-------------------------+
1 row in set (0.00 sec)

mysql> SELECT 1 = 2 OR 'test' = 'abc';

+-------------------------+
| 1 = 2 OR 'test' = 'abc' |
+-------------------------+
|                       0 |
+-------------------------+
1 row in set (0.00 sec)
```

Las consultas anteriores demuestran cómo funciona el operador `OR`. La primera consulta se evaluó como `true` ya que la condición `1 = 1` es `true`. La segunda consulta tiene dos condiciones `false`, lo que resulta en una salida `false`.

---

## NOT Operator

El operador `NOT` simplemente invierte un valor `boolean` 'es decir, `true` se convierte en `false` y viceversa':

```r
mysql> SELECT NOT 1 = 1;

+-----------+
| NOT 1 = 1 |
+-----------+
|         0 |
+-----------+
1 row in set (0.00 sec)

mysql> SELECT NOT 1 = 2;

+-----------+
| NOT 1 = 2 |
+-----------+
|         1 |
+-----------+
1 row in set (0.00 sec)
```

Como se ve en los ejemplos anteriores, la primera consulta resultó en `false` porque es la inversa de la evaluación de `1 = 1`, que es `true`, por lo que su inversa es `false`. Por otro lado, la segunda consulta devolvió `true`, ya que la inversa de `1 = 2` 'que es `false`' es `true`.

---

## Symbol Operators

Los operadores `AND`, `OR` y `NOT` también pueden representarse como `&&`, `||` y `!`, respectivamente. Los siguientes son los mismos ejemplos anteriores, utilizando los operadores de símbolos:

```r
mysql> SELECT 1 = 1 && 'test' = 'abc';

+-------------------------+
| 1 = 1 && 'test' = 'abc' |
+-------------------------+
|                       0 |
+-------------------------+
1 row in set, 1 warning (0.00 sec)

mysql> SELECT 1 = 1 || 'test' = 'abc';

+-------------------------+
| 1 = 1 || 'test' = 'abc' |
+-------------------------+
|                       1 |
+-------------------------+
1 row in set, 1 warning (0.00 sec)

mysql> SELECT 1 != 1;

+--------+
| 1 != 1 |
+--------+
|      0 |
+--------+
1 row in set (0.00 sec)
```

---

## Operators in queries

Veamos cómo se pueden usar estos operadores en consultas. La siguiente consulta lista todos los registros donde el `username` NO es `john`:

```r
mysql> SELECT * FROM logins WHERE username != 'john';

+----+---------------+------------+---------------------+
| id | username      | password   | date_of_joining     |
+----+---------------+------------+---------------------+
|  1 | admin         | p@ssw0rd   | 2020-07-02 00:00:00 |
|  2 | administrator | adm1n_p@ss | 2020-07-02 11:30:50 |
|  4 | tom           | tom123!    | 2020-07-02 11:47:16 |
+----+---------------+------------+---------------------+
3 rows in set (0.00 sec)
```

La siguiente consulta selecciona usuarios que tienen su `id` mayor que `1` Y `username` NO es igual a `john`:

```r
mysql> SELECT * FROM logins WHERE username != 'john' AND id > 1;

+----+---------------+------------+---------------------+
| id | username      | password   | date_of_joining     |
+----+---------------+------------+---------------------+
|  2 | administrator | adm1n_p@ss | 2020-07-02 11:30:50 |
|  4 | tom           | tom123!    | 2020-07-02 11:47:16 |
+----+---------------+------------+---------------------+
2 rows in set (0.00 sec)
```

---

## Multiple Operator Precedence

SQL admite varias otras operaciones, como adición, división, así como operaciones bitwise. Por lo tanto, una consulta podría tener múltiples expresiones con múltiples operaciones a la vez. El orden de estas operaciones se decide a través de la precedencia de operadores.

Aquí hay una lista de operaciones comunes y su precedencia, como se ve en la [Documentación de MariaDB](https://mariadb.com/kb/en/operator-precedence/):

- División (`/`), Multiplicación (`*`) y Modulus (`%`)
- Adición (`+`) y sustracción (`-`)
- Comparación (`=`, `>`, `<`, `<=`, `>=`, `!=`, `LIKE`)
- NOT (`!`)
- AND (`&&`)
- OR (`||`)

Las operaciones en la parte superior se evalúan antes que las de la parte inferior de la lista. Veamos un ejemplo:

```r
SELECT * FROM logins WHERE username != 'tom' AND id > 3 - 2;
```

La consulta tiene cuatro operaciones: `!=`, `AND`, `>` y `-`. A partir de la precedencia de operadores, sabemos que la sustracción viene primero, por lo que primero evaluará `3 - 2` a `1`:

```r
SELECT * FROM logins WHERE username != 'tom' AND id > 1;
```

A continuación, tenemos dos operaciones de comparación, `>` y `!=`. Ambas tienen la misma precedencia y se evaluarán juntas. Entonces, devolverá todos los registros donde el `username` no sea `tom`, y todos los registros donde el `id` sea mayor que 1, y luego aplicará `AND` para devolver todos los registros con ambas condiciones:

```r
mysql> select * from logins where username != 'tom' AND id > 3 - 2;

+----+---------------+------------+---------------------+
| id | username      | password   | date_of_joining     |
+----+---------------+------------+---------------------+
|  2 | administrator | adm1n_p@ss | 2020-07-03 12:03:53 |
|  3 | john          | john123!   | 2020-07-03 12:03:57 |
+----+---------------+------------+---------------------+
2 rows in set (0.00 sec)
```

Veremos algunos otros escenarios de precedencia de operadores en las próximas secciones.
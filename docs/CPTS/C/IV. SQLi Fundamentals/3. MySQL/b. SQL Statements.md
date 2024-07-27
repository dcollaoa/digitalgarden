Ahora que entendemos cómo usar la utilidad `mysql` y crear bases de datos y tablas, veamos algunas de las sentencias SQL esenciales y sus usos.

---

## INSERT Statement

La sentencia [INSERT](https://dev.mysql.com/doc/refman/8.0/en/insert.html) se utiliza para agregar nuevos registros a una tabla dada. La sintaxis es la siguiente:

```r
INSERT INTO table_name VALUES (column1_value, column2_value, column3_value, ...);
```

La sintaxis anterior requiere que el usuario complete los valores para todas las columnas presentes en la tabla.

```r
mysql> INSERT INTO logins VALUES(1, 'admin', 'p@ssw0rd', '2020-07-02');

Query OK, 1 row affected (0.00 sec)
```

El ejemplo anterior muestra cómo agregar un nuevo login a la tabla logins, con valores apropiados para cada columna. Sin embargo, podemos omitir columnas con valores predeterminados, como `id` y `date_of_joining`. Esto se puede hacer especificando los nombres de las columnas para insertar valores en una tabla de manera selectiva:

```r
INSERT INTO table_name(column2, column3, ...) VALUES (column2_value, column3_value, ...);
```

Nota: omitir columnas con la restricción 'NOT NULL' resultará en un error, ya que es un valor obligatorio.

Podemos hacer lo mismo para insertar valores en la tabla `logins`:

```r
mysql> INSERT INTO logins(username, password) VALUES('administrator', 'adm1n_p@ss');

Query OK, 1 row affected (0.00 sec)
```

Insertamos un par de username-password en el ejemplo anterior mientras omitíamos las columnas `id` y `date_of_joining`.

Nota: Los ejemplos insertan contraseñas en texto claro en la tabla, solo para demostración. Esto es una mala práctica, ya que las contraseñas siempre deben ser hashed/encriptadas antes de almacenarse.

También podemos insertar múltiples registros a la vez separándolos con una coma:

```r
mysql> INSERT INTO logins(username, password) VALUES ('john', 'john123!'), ('tom', 'tom123!');

Query OK, 2 rows affected (0.00 sec)
Records: 2  Duplicates: 0  Warnings: 0
```

La consulta anterior insertó dos nuevos registros a la vez.

---

## SELECT Statement

Ahora que hemos insertado datos en las tablas, veamos cómo recuperar datos con la sentencia [SELECT](https://dev.mysql.com/doc/refman/8.0/en/select.html). Esta sentencia también se puede usar para muchos otros propósitos, que veremos más adelante. La sintaxis general para ver toda la tabla es la siguiente:

```r
SELECT * FROM table_name;
```

El símbolo de asterisco (*) actúa como un wildcard y selecciona todas las columnas. La palabra clave `FROM` se usa para denotar la tabla de la cual seleccionar. Es posible ver los datos presentes en columnas específicas también:

```r
SELECT column1, column2 FROM table_name;
```

La consulta anterior seleccionará los datos presentes en column1 y column2 solamente.

```r
mysql> SELECT * FROM logins;

+----+---------------+------------+---------------------+
| id | username      | password   | date_of_joining     |
+----+---------------+------------+---------------------+
|  1 | admin         | p@ssw0rd   | 2020-07-02 00:00:00 |
|  2 | administrator | adm1n_p@ss | 2020-07-02 11:30:50 |
|  3 | john          | john123!   | 2020-07-02 11:47:16 |
|  4 | tom           | tom123!    | 2020-07-02 11:47:16 |
+----+---------------+------------+---------------------+
4 rows in set (0.00 sec)


mysql> SELECT username,password FROM logins;

+---------------+------------+
| username      | password   |
+---------------+------------+
| admin         | p@ssw0rd   |
| administrator | adm1n_p@ss |
| john          | john123!   |
| tom           | tom123!    |
+---------------+------------+
4 rows in set (0.00 sec)
```

La primera consulta en el ejemplo anterior muestra todos los registros presentes en la tabla logins. Podemos ver los cuatro registros que se ingresaron anteriormente. La segunda consulta selecciona solo las columnas username y password, omitiendo las otras dos.

---

## DROP Statement

Podemos usar [DROP](https://dev.mysql.com/doc/refman/8.0/en/drop-table.html) para eliminar tablas y bases de datos del servidor.

```r
mysql> DROP TABLE logins;

Query OK, 0 rows affected (0.01 sec)


mysql> SHOW TABLES;

Empty set (0.00 sec)
```

Como podemos ver, la tabla se eliminó por completo.

La sentencia 'DROP' eliminará permanentemente y completamente la tabla sin confirmación, por lo que debe usarse con precaución.

---

## ALTER Statement

Finalmente, podemos usar [ALTER](https://dev.mysql.com/doc/refman/8.0/en/alter-table.html) para cambiar el nombre de cualquier tabla y cualquiera de sus campos, o para eliminar o agregar una nueva columna a una tabla existente. El siguiente ejemplo agrega una nueva columna `newColumn` a la tabla `logins` usando `ADD`:

```r
mysql> ALTER TABLE logins ADD newColumn INT;

Query OK, 0 rows affected (0.01 sec)
```

Para renombrar una columna, podemos usar `RENAME COLUMN`:

```r
mysql> ALTER TABLE logins RENAME COLUMN newColumn TO oldColumn;

Query OK, 0 rows affected (0.01 sec)
```

También podemos cambiar el tipo de dato de una columna con `MODIFY`:

```r
mysql> ALTER TABLE logins MODIFY oldColumn DATE;

Query OK, 0 rows affected (0.01 sec)
```

Finalmente, podemos eliminar una columna usando `DROP`:

```r
mysql> ALTER TABLE logins DROP oldColumn;

Query OK, 0 rows affected (0.01 sec)
```

Podemos usar cualquiera de las sentencias anteriores con cualquier tabla existente, siempre que tengamos suficientes privilegios para hacerlo.

---

## UPDATE Statement

Mientras que `ALTER` se usa para cambiar las propiedades de una tabla, la sentencia [UPDATE](https://dev.mysql.com/doc/refman/8.0/en/update.html) se puede usar para actualizar registros específicos dentro de una tabla, basándose en ciertas condiciones. Su sintaxis general es:

```r
UPDATE table_name SET column1=newvalue1, column2=newvalue2, ... WHERE <condition>;
```

Especificamos el nombre de la tabla, cada columna y su nuevo valor, y la condición para actualizar registros. Veamos un ejemplo:

```r
mysql> UPDATE logins SET password = 'change_password' WHERE id > 1;

Query OK, 3 rows affected (0.00 sec)
Rows matched: 3  Changed: 3  Warnings: 0


mysql> SELECT * FROM logins;

+----+---------------+-----------------+---------------------+
| id | username      | password        | date_of_joining     |
+----+---------------+-----------------+---------------------+
|  1 | admin         | p@ssw0rd        | 2020-07-02 00:00:00 |
|  2 | administrator | change_password | 2020-07-02 11:30:50 |
|  3 | john          | change_password | 2020-07-02 11:47:16 |
|  4 | tom           | change_password | 2020-07-02 11:47:16 |
+----+---------------+-----------------+---------------------+
4 rows in set (0.00 sec)
```

La consulta anterior actualizó todas las contraseñas en todos los registros donde el id era mayor que 1.

Nota: debemos especificar la cláusula 'WHERE' con UPDATE, para especificar qué registros se actualizan. La cláusula 'WHERE' se discutirá a continuación.
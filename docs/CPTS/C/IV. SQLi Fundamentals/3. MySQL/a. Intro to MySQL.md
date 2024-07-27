Este módulo introduce la inyección de SQL a través de `MySQL`, y es crucial aprender más sobre `MySQL` y SQL para comprender cómo funcionan las inyecciones SQL y utilizarlas correctamente. Por lo tanto, esta sección cubrirá algunos de los conceptos básicos y la sintaxis de MySQL/SQL y ejemplos utilizados dentro de las bases de datos MySQL/MariaDB.

---

## Structured Query Language (SQL)

La sintaxis SQL puede diferir de un RDBMS a otro. Sin embargo, todos deben seguir el [estándar ISO](https://en.wikipedia.org/wiki/ISO/IEC_9075) para Structured Query Language. Seguiremos la sintaxis de MySQL/MariaDB para los ejemplos mostrados. SQL se puede usar para realizar las siguientes acciones:

- Recuperar datos
- Actualizar datos
- Eliminar datos
- Crear nuevas tablas y bases de datos
- Agregar/eliminar usuarios
- Asignar permisos a estos usuarios

---

## Command Line

La utilidad `mysql` se utiliza para autenticarse e interactuar con una base de datos MySQL/MariaDB. La flag `-u` se usa para proporcionar el nombre de usuario y la flag `-p` para la contraseña. La flag `-p` debe pasarse vacía, para que se nos solicite ingresar la contraseña y no pasarla directamente en la línea de comandos, ya que podría almacenarse en texto claro en el archivo bash_history.

```r
mysql -u root -p

Enter password: <password>
...SNIP...

mysql> 
```

Nuevamente, también es posible usar la contraseña directamente en el comando, aunque esto debe evitarse, ya que podría llevar a que la contraseña se guarde en los registros y el historial de la terminal:

```r
mysql -u root -p<password>

...SNIP...

mysql> 
```

Tip: No debe haber espacios entre '-p' y la contraseña.

Los ejemplos anteriores nos inician sesión como superusuario, es decir, "`root`" con la contraseña "`password`", para tener privilegios para ejecutar todos los comandos. Otros usuarios de DBMS tendrían ciertos privilegios sobre los cuales pueden ejecutar sentencias. Podemos ver qué privilegios tenemos usando el comando [SHOW GRANTS](https://dev.mysql.com/doc/refman/8.0/en/show-grants.html) que se discutirá más adelante.

Cuando no especificamos un host, por defecto será el servidor `localhost`. Podemos especificar un host remoto y un puerto utilizando las flags `-h` y `-P`.

```r
mysql -u root -h docker.hackthebox.eu -P 3306 -p 

Enter password: 
...SNIP...

mysql> 
```

Nota: El puerto predeterminado de MySQL/MariaDB es (3306), pero puede configurarse en otro puerto. Se especifica usando una `P` mayúscula, a diferencia de la `p` minúscula utilizada para contraseñas.

Nota: Para seguir los ejemplos, intenta usar la herramienta 'mysql' en tu PwnBox para iniciar sesión en el DBMS encontrado en la pregunta al final de la sección, usando su IP y puerto. Usa 'root' para el nombre de usuario y 'password' para la contraseña.

---

## Creating a database

Una vez que iniciamos sesión en la base de datos usando la utilidad `mysql`, podemos comenzar a usar consultas SQL para interactuar con el DBMS. Por ejemplo, se puede crear una nueva base de datos dentro del DBMS MySQL usando la sentencia [CREATE DATABASE](https://dev.mysql.com/doc/refman/5.7/en/create-database.html).

```r
mysql> CREATE DATABASE users;

Query OK, 1 row affected (0.02 sec)
```

MySQL espera que las consultas de la línea de comandos terminen con un punto y coma. El ejemplo anterior creó una nueva base de datos llamada `users`. Podemos ver la lista de bases de datos con [SHOW DATABASES](https://dev.mysql.com/doc/refman/8.0/en/show-databases.html), y podemos cambiar a la base de datos `users` con la sentencia `USE`:

```r
mysql> SHOW DATABASES;

+--------------------+
| Database           |
+--------------------+
| information_schema |
| mysql              |
| performance_schema |
| sys                |
| users              |
+--------------------+

mysql> USE users;

Database changed
```

Las sentencias SQL no son sensibles a mayúsculas y minúsculas, lo que significa que 'USE users;' y 'use users;' se refieren al mismo comando. Sin embargo, el nombre de la base de datos sí es sensible a mayúsculas y minúsculas, por lo que no podemos hacer 'USE USERS;' en lugar de 'USE users;'. Por lo tanto, es una buena práctica especificar las sentencias en mayúsculas para evitar confusiones.

---

## Tables

El DBMS almacena datos en forma de tablas. Una tabla está compuesta por filas horizontales y columnas verticales. La intersección de una fila y una columna se llama celda. Cada tabla se crea con un conjunto fijo de columnas, donde cada columna es de un tipo de dato particular.

Un tipo de dato define qué tipo de valor debe contener una columna. Ejemplos comunes son `numbers`, `strings`, `date`, `time`, y `binary data`. También podría haber tipos de datos específicos para el DBMS. Una lista completa de tipos de datos en MySQL se puede encontrar [aquí](https://dev.mysql.com/doc/refman/8.0/en/data-types.html). Por ejemplo, vamos a crear una tabla llamada `logins` para almacenar datos de usuarios, utilizando la consulta SQL [CREATE TABLE](https://dev.mysql.com/doc/refman/8.0/en/creating-tables.html):


```r
CREATE TABLE logins (
    id INT,
    username VARCHAR(100),
    password VARCHAR(100),
    date_of_joining DATETIME
    );
```

Como podemos ver, la consulta `CREATE TABLE` primero especifica el nombre de la tabla, y luego (dentro de paréntesis) especificamos cada columna por su nombre y su tipo de dato, todos separados por comas. Después del nombre y tipo, podemos especificar propiedades específicas, que se discutirán más adelante.

```r
mysql> CREATE TABLE logins (
    ->     id INT,
    ->     username VARCHAR(100),
    ->     password VARCHAR(100),
    ->     date_of_joining DATETIME
    ->     );
Query OK, 0 rows affected (0.03 sec)
```

Las consultas SQL anteriores crean una tabla llamada `logins` con cuatro columnas. La primera columna, `id` es un entero. Las siguientes dos columnas, `username` y `password` son cadenas de 100 caracteres cada una. Cualquier entrada más larga que esta resultará en un error. La columna `date_of_joining` de tipo `DATETIME` almacena la fecha en que se agregó una entrada.

```r
mysql> SHOW TABLES;

+-----------------+
| Tables_in_users |
+-----------------+
| logins          |
+-----------------+
1 row in set (0.00 sec)
```

Se puede obtener una lista de tablas en la base de datos actual utilizando la sentencia `SHOW TABLES`. Además, la palabra clave [DESCRIBE](https://dev.mysql.com/doc/refman/8.0/en/describe.html) se usa para listar la estructura de la tabla con sus campos y tipos de datos.


```r
mysql> DESCRIBE logins;

+-----------------+--------------+
| Field           | Type         |
+-----------------+--------------+
| id              | int          |
| username        | varchar(100) |
| password        | varchar(100) |
| date_of_joining | date         |
+-----------------+--------------+
4 rows in set (0.00 sec)
```

### Table Properties

Dentro de la consulta `CREATE TABLE`, hay muchas [propiedades](https://dev.mysql.com/doc/refman/8.0/en/create-table.html) que se pueden configurar para la tabla y cada columna. Por ejemplo, podemos configurar la columna `id` para que se autoincremente usando la palabra clave `AUTO_INCREMENT`, que incrementa automáticamente el id en uno cada vez que se agrega un nuevo elemento a la tabla:


```r
    id INT NOT NULL AUTO_INCREMENT,
```

La restricción `NOT NULL` asegura que una columna en particular nunca se deje vacía 'es decir, campo obligatorio.' También podemos usar la restricción `UNIQUE` para asegurar que los elementos insertados sean siempre únicos. Por ejemplo, si lo usamos con la columna `username`, podemos asegurarnos de que no haya dos usuarios con el mismo nombre de usuario:


```r
    username VARCHAR(100) UNIQUE NOT NULL,
```

Otra palabra clave importante es la palabra clave `DEFAULT`, que se usa para especificar el valor predeterminado. Por ejemplo, dentro de la columna `date_of_joining`, podemos establecer el valor predeterminado en [Now()](https://dev.mysql.com/doc/refman/8.0/en/date-and-time-functions.html#function_now), que en MySQL devuelve la fecha y hora actuales:


```r
    date_of_joining DATETIME DEFAULT NOW(),
```

Finalmente, una de las propiedades más importantes es `PRIMARY KEY`, que podemos usar para identificar de manera única cada registro en la tabla, refiriéndose a todos los datos de un registro dentro de una tabla para bases de datos relacionales, como se discutió anteriormente en la sección anterior. Podemos hacer que la columna `id` sea la `PRIMARY KEY` para esta tabla:


```r
    PRIMARY KEY (id)
```

La consulta final `CREATE TABLE` será la siguiente:


```r
CREATE TABLE

 logins (
    id INT NOT NULL AUTO_INCREMENT,
    username VARCHAR(100) UNIQUE NOT NULL,
    password VARCHAR(100) NOT NULL,
    date_of_joining DATETIME DEFAULT NOW(),
    PRIMARY KEY (id)
    );
```

Nota: Permita de 10 a 15 segundos para que los servidores en las preguntas se inicien, para permitir suficiente tiempo para que Apache/MySQL se inicien y ejecuten.
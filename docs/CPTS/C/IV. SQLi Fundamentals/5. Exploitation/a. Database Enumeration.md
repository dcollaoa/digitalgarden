En las secciones anteriores, aprendimos sobre diferentes consultas SQL en `MySQL` y SQL injections y cómo usarlas. Esta sección pondrá todo eso en práctica y recopilará datos de la base de datos utilizando consultas SQL dentro de SQL injections.

---

## MySQL Fingerprinting

Antes de enumerar la base de datos, generalmente necesitamos identificar el tipo de DBMS con el que estamos tratando. Esto se debe a que cada DBMS tiene diferentes consultas, y saber cuál es nos ayudará a saber qué consultas usar.

Como una suposición inicial, si el servidor web que vemos en las respuestas HTTP es `Apache` o `Nginx`, es una buena suposición que el servidor web está ejecutándose en Linux, por lo que el DBMS probablemente sea `MySQL`. Lo mismo también se aplica a Microsoft DBMS si el servidor web es `IIS`, por lo que probablemente sea `MSSQL`. Sin embargo, esta es una suposición lejana, ya que muchos otros DBMS pueden ser utilizados en cualquier sistema operativo o servidor web. Por lo tanto, hay diferentes consultas que podemos probar para identificar el tipo de base de datos con la que estamos tratando.

Como cubrimos `MySQL` en este módulo, vamos a identificar bases de datos `MySQL`. Las siguientes consultas y sus resultados nos dirán que estamos tratando con `MySQL`:

|Payload|Cuándo Usar|Resultado Esperado|Resultado Incorrecto|
|---|---|---|---|
|`SELECT @@version`|Cuando tenemos salida completa de la consulta|Versión de MySQL 'es decir, `10.3.22-MariaDB-1ubuntu1`'|En MSSQL devuelve la versión de MSSQL. Error con otros DBMS.|
|`SELECT POW(1,1)`|Cuando solo tenemos salida numérica|`1`|Error con otros DBMS|
|`SELECT SLEEP(5)`|Ciega/Sin Salida|Retrasa la respuesta de la página durante 5 segundos y devuelve `0`.|No retrasará la respuesta con otros DBMS|

Como vimos en el ejemplo de la sección anterior, cuando probamos `@@version`, nos dio:

`http://SERVER_IP:PORT/search.php?port_code=cn`

![](https://academy.hackthebox.com/storage/modules/33/db_version_1.jpg)

El resultado `10.3.22-MariaDB-1ubuntu1` significa que estamos tratando con un DBMS `MariaDB` similar a MySQL. Dado que tenemos salida directa de la consulta, no tendremos que probar las otras cargas útiles. En su lugar, podemos probarlas y ver qué obtenemos.

---

## INFORMATION_SCHEMA Database

Para extraer datos de tablas usando `UNION SELECT`, necesitamos formar correctamente nuestras consultas `SELECT`. Para hacerlo, necesitamos la siguiente información:

- Lista de bases de datos
- Lista de tablas dentro de cada base de datos
- Lista de columnas dentro de cada tabla

Con la información anterior, podemos formar nuestra declaración `SELECT` para volcar datos de cualquier columna en cualquier tabla dentro de cualquier base de datos dentro del DBMS. Aquí es donde podemos utilizar la base de datos `INFORMATION_SCHEMA`.

La base de datos [INFORMATION_SCHEMA](https://dev.mysql.com/doc/refman/8.0/en/information-schema-introduction.html) contiene metadatos sobre las bases de datos y tablas presentes en el servidor. Esta base de datos juega un papel crucial mientras se explotan vulnerabilidades de SQL injection. Como esta es una base de datos diferente, no podemos llamar a sus tablas directamente con una declaración `SELECT`. Si solo especificamos el nombre de una tabla para una declaración `SELECT`, buscará tablas dentro de la misma base de datos.

Por lo tanto, para referenciar una tabla presente en otra base de datos, podemos usar el operador punto `.`. Por ejemplo, para `SELECT` una tabla `users` presente en una base de datos llamada `my_database`, podemos usar:


```sql
SELECT * FROM my_database.users;
```

De manera similar, podemos ver tablas presentes en la base de datos `INFORMATION_SCHEMA`.

---

## SCHEMATA

Para comenzar nuestra enumeración, deberíamos encontrar qué bases de datos están disponibles en el DBMS. La tabla [SCHEMATA](https://dev.mysql.com/doc/refman/8.0/en/information-schema-schemata-table.html) en la base de datos `INFORMATION_SCHEMA` contiene información sobre todas las bases de datos en el servidor. Se usa para obtener nombres de bases de datos para que luego podamos consultarlas. La columna `SCHEMA_NAME` contiene todos los nombres de bases de datos actualmente presentes.

Primero probemos esto en una base de datos local para ver cómo se usa la consulta:

  Database Enumeration

```sql
mysql> SELECT SCHEMA_NAME FROM INFORMATION_SCHEMA.SCHEMATA;

+--------------------+
| SCHEMA_NAME        |
+--------------------+
| mysql              |
| information_schema |
| performance_schema |
| ilfreight          |
| dev                |
+--------------------+
6 rows in set (0.01 sec)
```

Vemos las bases de datos `ilfreight` y `dev`.

Nota: Las primeras tres bases de datos son bases de datos MySQL predeterminadas y están presentes en cualquier servidor, por lo que generalmente las ignoramos durante la enumeración de bases de datos. A veces hay una cuarta base de datos 'sys' también.

Ahora, hagamos lo mismo usando una SQL injection `UNION`, con la siguiente carga útil:


```sql
cn' UNION select 1,schema_name,3,4 from INFORMATION_SCHEMA.SCHEMATA-- -
```

`http://SERVER_IP:PORT/search.php?port_code=cn`

![](https://academy.hackthebox.com/storage/modules/33/ports_dbs.png)

Una vez más, vemos dos bases de datos, `ilfreight` y `dev`, además de las predeterminadas. Averigüemos qué base de datos está utilizando la aplicación web para recuperar datos de puertos. Podemos encontrar la base de datos actual con la consulta `SELECT database()`. Podemos hacer esto de manera similar a como encontramos la versión del DBMS en la sección anterior:


```sql
cn' UNION select 1,database(),2,3-- -
```

`http://SERVER_IP:PORT/search.php?port_code=cn`

![](https://academy.hackthebox.com/storage/modules/33/db_name.jpg)

Vemos que el nombre de la base de datos es `ilfreight`. Sin embargo, la otra base de datos (`dev`) parece interesante. Por lo tanto, intentemos recuperar las tablas de ella.

---

## TABLES

Antes de volcar datos de la base de datos `dev`, necesitamos obtener una lista de las tablas para consultarlas con una declaración `SELECT`. Para encontrar todas las tablas dentro de una base de datos, podemos usar la tabla `TABLES` en la base de datos `INFORMATION_SCHEMA`.

La tabla [TABLES](https://dev.mysql.com/doc/refman/8.0/en/information-schema-tables-table.html) contiene información sobre todas las tablas en la base de datos. Esta tabla contiene múltiples columnas, pero estamos interesados en las columnas `TABLE_SCHEMA` y `TABLE_NAME`. La columna `TABLE_NAME` almacena nombres de tablas, mientras que la columna `TABLE_SCHEMA` señala la base de datos a la que pertenece cada tabla. Esto se puede hacer de manera similar a como encontramos los nombres de las bases de datos. Por ejemplo, podemos usar la siguiente carga útil para encontrar las tablas dentro de la base de datos `dev`:


```sql
cn' UNION select 1,TABLE_NAME,TABLE_SCHEMA,4 from INFORMATION_SCHEMA.TABLES where table_schema='dev'-- -
```

Nota cómo reemplazamos los números '2' y '3' con 'TABLE_NAME' y 'TABLE_SCHEMA', para obtener la salida de ambas columnas en la misma consulta.

`http://SERVER_IP:PORT/search.php?port_code=cn`

![](https://academy.hackthebox.com/storage/modules/33/ports_tables_1.jpg)

Nota: agregamos una condición (where table_schema='dev') para que solo devuelva tablas de la base de datos 'dev', de lo contrario obtendríamos todas las tablas en todas las bases de datos, lo cual puede ser muchas.

Vemos cuatro tablas en la base de datos dev, a saber, `credentials`, `framework`, `pages` y `posts`. Por ejemplo, la tabla `credentials` podría contener información sensible para revisar.

---

## COLUMNS

Para volcar los datos de la tabla `credentials`, primero necesitamos encontrar los nombres de las columnas en la tabla, que se pueden encontrar en la tabla `COLUMNS` en la base de datos `INFORMATION_SCHEMA`. La tabla [COLUMNS](https://dev.mysql.com/doc/refman/8.0/en/information-schema-columns-table.html) contiene información sobre todas las columnas presentes en todas las bases de datos. Esto nos ayuda a encontrar los nombres de las columnas para consultar una tabla. Las columnas `COLUMN_NAME`, `TABLE_NAME` y `TABLE_SCHEMA` pueden ser utilizadas para lograr esto. Como hicimos antes, probemos esta carga útil para encontrar los nombres de las columnas en la tabla `credentials`:


```sql
cn' UNION select 1,COLUMN_NAME,TABLE_NAME,TABLE_SCHEMA from INFORMATION_SCHEMA.COLUMNS where table_name='credentials'-- -
```

`http://SERVER_IP:PORT/search.php?port_code=cn`

![](https://academy.hackthebox.com/storage/modules/33/ports_columns_1.jpg)

La tabla tiene dos columnas llamadas `username` y `password`. Podemos usar esta información y volcar datos de la tabla.

---

## Data

Ahora que tenemos toda la información, podemos formar nuestra consulta `UNION` para volcar datos de las columnas `username` y `password

` de la tabla `credentials` en la base de datos `dev`. Podemos colocar `username` y `password` en lugar de las columnas 2 y 3:


```sql
cn' UNION select 1, username, password, 4 from dev.credentials-- -
```

Recuerda: no olvides usar el operador punto para referenciar 'credentials' en la base de datos 'dev', ya que estamos ejecutándonos en la base de datos 'ilfreight', como se discutió anteriormente.

`http://SERVER_IP:PORT/search.php?port_code=cn`

![](https://academy.hackthebox.com/storage/modules/33/ports_credentials_1.png)

Pudimos obtener todas las entradas en la tabla `credentials`, que contiene información sensible como hashes de contraseñas y una clave API.
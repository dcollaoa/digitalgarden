Hemos aprendido sobre las SQL injections, por qué ocurren y cómo podemos explotarlas. También debemos aprender cómo evitar este tipo de vulnerabilidades en nuestro código y parchearlas cuando se encuentren. Veamos algunos ejemplos de cómo se pueden mitigar las SQL Injection.

---

## Input Sanitization

Aquí está el fragmento de código de la sección de bypass de autenticación que discutimos anteriormente:


```r
<SNIP>
  $username = $_POST['username'];
  $password = $_POST['password'];

  $query = "SELECT * FROM logins WHERE username='". $username. "' AND password = '" . $password . "';" ;
  echo "Executing query: " . $query . "<br /><br />";

  if (!mysqli_query($conn ,$query))
  {
          die('Error: ' . mysqli_error($conn));
  }

  $result = mysqli_query($conn, $query);
  $row = mysqli_fetch_array($result);
<SNIP>
```

Como podemos ver, el script toma el `username` y `password` de la solicitud POST y los pasa directamente a la consulta. Esto permitirá a un atacante inyectar cualquier cosa que desee y explotar la aplicación. La inyección se puede evitar sanitizando cualquier entrada del usuario, haciendo que las consultas inyectadas sean inútiles. Las librerías proporcionan múltiples funciones para lograr esto, un ejemplo es la función [mysqli_real_escape_string()](https://www.php.net/manual/en/mysqli.real-escape-string.php). Esta función escapa caracteres como `'` y `"`, para que no tengan ningún significado especial.


```r
<SNIP>
$username = mysqli_real_escape_string($conn, $_POST['username']);
$password = mysqli_real_escape_string($conn, $_POST['password']);

$query = "SELECT * FROM logins WHERE username='". $username. "' AND password = '" . $password . "';" ;
echo "Executing query: " . $query . "<br /><br />";
<SNIP>
```

El fragmento anterior muestra cómo se puede usar la función.

![mysqli_escape](https://academy.hackthebox.com/storage/modules/33/mysqli_escape.png)

Como era de esperar, la inyección ya no funciona debido a que las comillas simples están escapadas. Un ejemplo similar es [pg_escape_string()](https://www.php.net/manual/en/function.pg-escape-string.php) que se usa para escapar consultas en PostgreSQL.

---

## Input Validation

La entrada del usuario también puede validarse en función de los datos utilizados para la consulta para garantizar que coincida con la entrada esperada. Por ejemplo, al tomar un correo electrónico como entrada, podemos validar que la entrada esté en la forma de `...@email.com`, y así sucesivamente.

Considera el siguiente fragmento de código de la página de puertos, en la que usamos `UNION` injections:


```r
<?php
if (isset($_GET["port_code"])) {
	$q = "Select * from ports where port_code ilike '%" . $_GET["port_code"] . "%'";
	$result = pg_query($conn,$q);
    
	if (!$result)
	{
   		die("</table></div><p style='font-size: 15px;'>" . pg_last_error($conn). "</p>");
	}
<SNIP>
?>
```

Vemos que el parámetro GET `port_code` se usa directamente en la consulta. Ya se sabe que un código de puerto solo consta de letras o espacios. Podemos restringir la entrada del usuario a solo estos caracteres, lo que evitará la inyección de consultas. Se puede usar una expresión regular para validar la entrada:


```r
<SNIP>
$pattern = "/^[A-Za-z\s]+$/";
$code = $_GET["port_code"];

if(!preg_match($pattern, $code)) {
  die("</table></div><p style='font-size: 15px;'>Invalid input! Please try again.</p>");
}

$q = "Select * from ports where port_code ilike '%" . $code . "%'";
<SNIP>
```

El código se modifica para usar la función [preg_match()](https://www.php.net/manual/en/function.preg-match.php), que verifica si la entrada coincide con el patrón dado o no. El patrón utilizado es `[A-Za-z\s]+`, que solo coincidirá con cadenas que contengan letras y espacios. Cualquier otro carácter resultará en la terminación del script.

`http://SERVER_IP:PORT/search.php?port_code=c`

![](https://academy.hackthebox.com/storage/modules/33/postgres_copy_write.png)

Podemos probar la siguiente inyección:


```r
'; SELECT 1,2,3,4-- -
```

`http://SERVER_IP:PORT/search.php?port_code=`

![](https://academy.hackthebox.com/storage/modules/33/postgres_copy_write.png)

Como se ve en las imágenes anteriores, la entrada con consultas inyectadas fue rechazada por el servidor.

---

## User Privileges

Como se discutió inicialmente, el software DBMS permite la creación de usuarios con permisos detallados. Debemos asegurarnos de que el usuario que consulta la base de datos solo tenga los permisos mínimos.

Los superusuarios y usuarios con privilegios administrativos nunca deben usarse con aplicaciones web. Estas cuentas tienen acceso a funciones y características, lo que podría llevar a la compromisión del servidor.



```r
MariaDB [(none)]> CREATE USER 'reader'@'localhost';

Query OK, 0 rows affected (0.002 sec)


MariaDB [(none)]> GRANT SELECT ON ilfreight.ports TO 'reader'@'localhost' IDENTIFIED BY 'p@ssw0Rd!!';

Query OK, 0 rows affected (0.000 sec)
```

Los comandos anteriores agregan un nuevo usuario de MariaDB llamado `reader` que solo tiene privilegios `SELECT` en la tabla `ports`. Podemos verificar los permisos de este usuario iniciando sesión:



```r
mysql -u reader -p

MariaDB [(none)]> use ilfreight;
MariaDB [ilfreight]> SHOW TABLES;

+---------------------+
| Tables_in_ilfreight |
+---------------------+
| ports               |
+---------------------+
1 row in set (0.000 sec)


MariaDB [ilfreight]> SELECT SCHEMA_NAME FROM INFORMATION_SCHEMA.SCHEMATA;

+--------------------+
| SCHEMA_NAME        |
+--------------------+
| information_schema |
| ilfreight          |
+--------------------+
2 rows in set (0.000 sec)


MariaDB [ilfreight]> SELECT * FROM ilfreight.credentials;
ERROR 1142 (42000): SELECT command denied to user 'reader'@'localhost' for table 'credentials'
```

El fragmento anterior confirma que el usuario `reader` no puede consultar otras tablas en la base de datos `ilfreight`. El usuario solo tiene acceso a la tabla `ports` que necesita la aplicación.

---

## Web Application Firewall

Los Web Application Firewalls (WAF) se utilizan para detectar entradas maliciosas y rechazar cualquier solicitud HTTP que las contenga. Esto ayuda a prevenir la SQL Injection incluso cuando la lógica de la aplicación es defectuosa. Los WAF pueden ser de código abierto (ModSecurity) o premium (Cloudflare). La mayoría de ellos tienen reglas predeterminadas configuradas en función de ataques web comunes. Por ejemplo, cualquier solicitud que contenga la cadena `INFORMATION_SCHEMA` sería rechazada, ya que se usa comúnmente al explotar SQL injection.

---

## Parameterized Queries

Otra forma de garantizar que la entrada esté sanitizada de manera segura es utilizando consultas parametrizadas. Las consultas parametrizadas contienen marcadores de posición para los datos de entrada, que luego son escapados y pasados por los controladores. En lugar de pasar los datos directamente a la consulta SQL, usamos marcadores de posición y luego los llenamos con funciones de PHP.

Considera el siguiente código modificado:


```r
<SNIP>
  $username = $_POST['username'];
  $password = $_POST['password'];

  $query = "SELECT * FROM logins WHERE username=? AND password = ?" ;
  $stmt = mysqli_prepare($conn, $query);
  mysqli_stmt_bind_param($stmt, 'ss', $username, $password);
  mysqli_stmt_execute($stmt);
  $result = mysqli_stmt_get_result($stmt);

  $row = mysqli_fetch_array($result);
  mysqli_stmt_close($stmt);
<SNIP>
```

La consulta se modifica para contener dos marcadores de posición, marcados con `?` donde se colocarán el nombre de usuario y la contraseña. Luego vinculamos el nombre de usuario y la contraseña a la consulta usando la función [mysqli_stmt_bind_param()](https://www.php.net/manual/en/mysqli-stmt.bind-param.php). Esto escapará de manera segura cualquier comilla y colocará los valores en la consulta.

---

## Conclusion

La lista anterior no es exhaustiva y aún podría ser posible explotar SQL injection según la lógica de la aplicación. Los ejemplos de código mostrados están basados en PHP, pero la lógica se aplica a todos los lenguajes y librerías comunes.
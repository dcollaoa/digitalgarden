Ahora que tenemos una idea general de cómo funcionan MySQL y las consultas SQL, aprendamos sobre las inyecciones SQL.

---

## Use of SQL in Web Applications

Primero, veamos cómo las aplicaciones web utilizan bases de datos MySQL, en este caso, para almacenar y recuperar datos. Una vez que un DBMS está instalado y configurado en el servidor backend y está en funcionamiento, las aplicaciones web pueden comenzar a utilizarlo para almacenar y recuperar datos.

Por ejemplo, dentro de una aplicación web `PHP`, podemos conectarnos a nuestra base de datos y comenzar a usar la base de datos `MySQL` a través de la sintaxis `MySQL`, directamente en `PHP`, de la siguiente manera:

```r
$conn = new mysqli("localhost", "root", "password", "users");
$query = "select * from logins";
$result = $conn->query($query);
```

Luego, la salida de la consulta se almacenará en `$result`, y podemos imprimirla en la página o usarla de cualquier otra manera. El siguiente código PHP imprimirá todos los resultados devueltos de la consulta SQL en nuevas líneas:

```r
while($row = $result->fetch_assoc() ){
	echo $row["name"]."<br>";
}
```

Las aplicaciones web también suelen usar la entrada del usuario al recuperar datos. Por ejemplo, cuando un usuario usa la función de búsqueda para buscar a otros usuarios, su entrada de búsqueda se pasa a la aplicación web, que utiliza la entrada para buscar dentro de las bases de datos:

```r
$searchInput =  $_POST['findUser'];
$query = "select * from logins where username like '%$searchInput'";
$result = $conn->query($query);
```

`Si usamos la entrada del usuario dentro de una consulta SQL, y si no está codificada de manera segura, puede causar una variedad de problemas, como vulnerabilidades de inyección SQL.`

---

## What is an Injection?

En el ejemplo anterior, aceptamos la entrada del usuario y la pasamos directamente a la consulta SQL sin sanitización.

La sanitización se refiere a la eliminación de cualquier carácter especial en la entrada del usuario, con el fin de evitar intentos de inyección.

La inyección ocurre cuando una aplicación interpreta incorrectamente la entrada del usuario como código real en lugar de una cadena, cambiando el flujo del código y ejecutándolo. Esto puede ocurrir escapando los límites de la entrada del usuario mediante la inyección de un carácter especial como (`'`), y luego escribiendo código para ser ejecutado, como código JavaScript o SQL en las inyecciones SQL. A menos que la entrada del usuario esté sanitizada, es muy probable que el código inyectado se ejecute y se ejecute.

---

## SQL Injection

Una inyección SQL ocurre cuando la entrada del usuario se introduce en la cadena de consulta SQL sin sanitizar o filtrar adecuadamente la entrada. El ejemplo anterior mostró cómo se puede usar la entrada del usuario dentro de una consulta SQL, y no usó ninguna forma de sanitización de entrada:

```r
$searchInput =  $_POST['findUser'];
$query = "select * from logins where username like '%$searchInput'";
$result = $conn->query($query);
```

En casos típicos, el `searchInput` se introduciría para completar la consulta, devolviendo el resultado esperado. Cualquier entrada que escribamos va a la siguiente consulta SQL:

```r
select * from logins where username like '%$searchInput'
```

Entonces, si ingresamos `admin`, se convierte en `'%admin'`. En este caso, si escribimos cualquier código SQL, solo se consideraría como un término de búsqueda. Por ejemplo, si ingresamos `SHOW DATABASES;`, se ejecutaría como `'%SHOW DATABASES;'`. La aplicación web buscará nombres de usuario similares a `SHOW DATABASES;`. Sin embargo, como no hay sanitización, en este caso, **podemos agregar una comilla simple (`'`), que terminará el campo de entrada del usuario, y después de eso, podemos escribir código SQL real**. Por ejemplo, si buscamos `1'; DROP TABLE users;`, la entrada de búsqueda sería:

```r
'%1'; DROP TABLE users;'
```

Observa cómo agregamos una comilla simple (') después de "1", para escapar de los límites de la entrada del usuario en ('%$searchInput').

Entonces, la consulta SQL final ejecutada sería la siguiente:

```r
select * from logins where username like '%1'; DROP TABLE users;'
```

Como podemos ver en el resaltado de sintaxis, podemos escapar de los límites de la consulta original y hacer que nuestra consulta inyectada también se ejecute. `Una vez que se ejecute la consulta, la tabla` users `se eliminará.`

Nota: En el ejemplo anterior, por simplicidad, agregamos otra consulta SQL después de un punto y coma (;). Aunque esto en realidad no es posible con MySQL, es posible con MSSQL y PostgreSQL. En las próximas secciones, discutiremos los métodos reales de inyectar consultas SQL en MySQL.

---

## Syntax Errors

El ejemplo anterior de inyección SQL devolvería un error:

```r
Error: near line 1: near "'": syntax error
```

Esto se debe al último carácter final, donde tenemos una comilla simple extra (`'`) que no está cerrada, lo que causa un error de sintaxis SQL cuando se ejecuta:

```r
select * from logins where username like '%1'; DROP TABLE users;'
```

En este caso, solo teníamos un carácter final, ya que nuestra entrada de la consulta de búsqueda estaba cerca del final de la consulta SQL. Sin embargo, la entrada del usuario generalmente va en el medio de la consulta SQL, y el resto de la consulta SQL original viene después de ella.

Para tener una inyección exitosa, debemos asegurarnos de que la consulta SQL modificada sea aún válida y no tenga errores de sintaxis después de nuestra inyección. En la mayoría de los casos, no tendríamos acceso al código fuente para encontrar la consulta SQL original y desarrollar una inyección SQL adecuada para hacer una consulta SQL válida. Entonces, ¿cómo podríamos inyectar con éxito en la consulta SQL?

Una respuesta es usando `comentarios`, y discutiremos esto en una sección posterior. Otra es hacer que la sintaxis de la consulta funcione pasando múltiples comillas simples, como discutiremos a continuación (`'`).

Ahora que entendemos los conceptos básicos de las inyecciones SQL, comencemos a aprender algunos usos prácticos.

---

## Types of SQL Injections

Las inyecciones SQL se categorizan según cómo y dónde recuperamos su salida.

![dbms_architecture](https://academy.hackthebox.com/storage/modules/33/types_of_sqli.jpg)

En casos simples, la salida de tanto la consulta original como la nueva puede imprimirse directamente en el front-end, y podemos leerla directamente. Esto se conoce como `In-band` SQL injection, y tiene dos tipos: `Union Based` y `Error Based`.

Con la inyección SQL `Union Based`, es posible que tengamos que especificar la ubicación exacta, es decir, la columna, que podemos leer, por lo que la consulta dirigirá la salida para imprimirse allí. En cuanto a la inyección SQL `Error Based`, se usa cuando podemos obtener los errores `PHP` o `SQL` en el front-end, y así podemos intencionalmente causar un error SQL que devuelva la salida de nuestra consulta.

En casos más complicados, es posible que no obtengamos la salida impresa, por lo que podemos utilizar la lógica SQL para recuperar la salida carácter por carácter. Esto se conoce como inyección SQL `Blind`, y también tiene dos tipos: `Boolean Based` y `Time Based`.

Con la inyección SQL `Boolean Based`, podemos usar sentencias condicionales SQL para controlar si la página devuelve alguna salida, es decir, la respuesta de la consulta original, si nuestra sentencia condicional devuelve `true`. En cuanto a las inyecciones SQL `Time Based`, usamos sentencias condicionales SQL que retrasan la respuesta de la página si la sentencia condicional devuelve `true` utilizando la función `Sleep()`.

Finalmente, en algunos casos, es posible que no tengamos acceso directo a la salida en absoluto, por lo que podemos tener que dirigir la salida a una ubicación remota, es decir, un registro DNS, y luego intentar recuperarla desde allí. Esto se conoce como inyección SQL `Out-of-band`.

En este módulo, nos centraremos únicamente en introducir las inyecciones SQL aprendiendo sobre la inyección SQL `Union Based`.
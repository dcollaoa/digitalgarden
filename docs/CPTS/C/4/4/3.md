En esta sección, aprenderemos cómo usar comentarios para subvertir la lógica de consultas SQL más avanzadas y terminar con una consulta SQL funcional para eludir el proceso de autenticación de inicio de sesión.

---

## Comments

Al igual que cualquier otro lenguaje, SQL también permite el uso de comentarios. Los comentarios se utilizan para documentar consultas o ignorar una parte de la consulta. Podemos usar dos tipos de comentarios de línea con MySQL: `--` y `#`, además de un comentario en línea `/**/` (aunque este no se usa generalmente en las inyecciones SQL). El `--` se puede usar de la siguiente manera:

```r
mysql> SELECT username FROM logins; -- Selects usernames from the logins table 

+---------------+
| username      |
+---------------+
| admin         |
| administrator |
| john          |
| tom           |
+---------------+
4 rows in set (0.00 sec)
```

Nota: En SQL, usar solo dos guiones no es suficiente para comenzar un comentario. Por lo tanto, debe haber un espacio vacío después de ellos, para que el comentario comience con (-- ), con un espacio al final. Esto a veces se codifica en URL como (--+), ya que los espacios en las URL se codifican como (+). Para aclarar, agregaremos otro (-) al final (-- -), para mostrar el uso de un espacio en blanco.

El símbolo `#` también se puede usar.

```r
mysql> SELECT * FROM logins WHERE username = 'admin'; # You can place anything here AND password = 'something'

+----+----------+----------+---------------------+
| id | username | password | date_of_joining     |
+----+----------+----------+---------------------+
|  1 | admin    | p@ssw0rd | 2020-07-02 00:00:00 |
+----+----------+----------+---------------------+
1 row in set (0.00 sec)
```

Consejo: si estás ingresando tu carga útil en la URL dentro de un navegador, un símbolo (#) generalmente se considera como una etiqueta y no se pasará como parte de la URL. Para usar (#) como un comentario dentro de un navegador, podemos usar '%23', que es un símbolo (#) codificado en URL.

El servidor ignorará la parte de la consulta con `AND password = 'something'` durante la evaluación.

---

## Auth Bypass with comments

Volvamos a nuestro ejemplo anterior e inyectemos `admin'--` como nuestro nombre de usuario. La consulta final será:

```r
SELECT * FROM logins WHERE username='admin'-- ' AND password = 'something';
```

Como podemos ver en el resaltado de sintaxis, el nombre de usuario ahora es `admin`, y el resto de la consulta ahora se ignora como un comentario. Además, de esta manera, podemos asegurarnos de que la consulta no tenga problemas de sintaxis.

Intentemos usar esto en la página de inicio de sesión e iniciar sesión con el nombre de usuario `admin'--` y cualquier cosa como la contraseña:

![admin_dash](https://academy.hackthebox.com/storage/modules/33/admin_dash.png)

Como vemos, pudimos eludir la autenticación, ya que la nueva consulta modificada verifica el nombre de usuario, sin otras condiciones.

---

## Another Example

SQL admite el uso de paréntesis si la aplicación necesita verificar ciertas condiciones antes que otras. Las expresiones dentro del paréntesis tienen prioridad sobre otros operadores y se evalúan primero. Veamos un escenario como este:

![paranthesis_fail](https://academy.hackthebox.com/storage/modules/33/paranthesis_fail.png)

La consulta anterior asegura que el id del usuario sea siempre mayor que 1, lo que evitará que alguien inicie sesión como administrador. Además, también vemos que la contraseña fue hasheada antes de ser usada en la consulta. Esto nos impedirá inyectar a través del campo de la contraseña porque la entrada se convierte en un hash.

Intentemos iniciar sesión con credenciales válidas `admin / p@ssw0rd` para ver la respuesta.

![paranthesis_valid_fail](https://academy.hackthebox.com/storage/modules/33/paranthesis_valid_fail.png)

Como se esperaba, el inicio de sesión falló a pesar de que proporcionamos credenciales válidas porque el ID del administrador es igual a 1. Entonces, intentemos iniciar sesión con las credenciales de otro usuario, como `tom`.

![tom_login](https://academy.hackthebox.com/storage/modules/33/tom_login.png)

Iniciar sesión como el usuario con un ID diferente de 1 fue exitoso. Entonces, ¿cómo podemos iniciar sesión como administrador? Sabemos por la sección anterior sobre comentarios que podemos usarlos para comentar el resto de la consulta. Entonces, intentemos usar `admin'--` como nombre de usuario.

![paranthesis_error](https://academy.hackthebox.com/storage/modules/33/paranthesis_error.png)

El inicio de sesión falló debido a un error de sintaxis, ya que un paréntesis abierto no fue equilibrado por uno cerrado. Para ejecutar la consulta con éxito, tendremos que agregar un paréntesis de cierre. Intentemos usar el nombre de usuario `admin')--` para cerrar y comentar el resto.

![paranthesis_success](https://academy.hackthebox.com/storage/modules/33/paranthesis_success.png)

La consulta fue exitosa y nos registramos como administrador. La consulta final como resultado de nuestra entrada es:

```r
SELECT * FROM logins where (username='admin')
```

La consulta anterior es similar a la del ejemplo anterior y devuelve la fila que contiene al administrador.
Ahora que tenemos una idea básica de cómo funcionan las sentencias SQL, comencemos con la inyección SQL. Antes de comenzar a ejecutar consultas SQL completas, primero aprenderemos a modificar la consulta original inyectando el operador `OR` y utilizando comentarios SQL para subvertir la lógica de la consulta original. Un ejemplo básico de esto es eludir la autenticación web, que demostraremos en esta sección.

---

## Authentication Bypass

Consideremos la siguiente página de inicio de sesión de administrador.

![admin_panel](https://academy.hackthebox.com/storage/modules/33/admin_panel.png)

Podemos iniciar sesión con las credenciales de administrador `admin / p@ssw0rd`.

![admin_creds](https://academy.hackthebox.com/storage/modules/33/admin_creds.png)

La página también muestra la consulta SQL que se está ejecutando para comprender mejor cómo subvertiremos la lógica de la consulta. Nuestro objetivo es iniciar sesión como el usuario admin sin usar la contraseña existente. Como podemos ver, la consulta SQL actual que se está ejecutando es:

```r
SELECT * FROM logins WHERE username='admin' AND password = 'p@ssw0rd';
```

La página toma las credenciales, luego usa el operador `AND` para seleccionar registros que coincidan con el nombre de usuario y la contraseña dados. Si la base de datos `MySQL` devuelve registros coincidentes, las credenciales son válidas, por lo que el código `PHP` evaluaría la condición del intento de inicio de sesión como `true`. Si la condición se evalúa como `true`, se devuelve el registro del administrador y nuestro inicio de sesión se valida. Veamos qué sucede cuando ingresamos credenciales incorrectas.

![admin_incorrect](https://academy.hackthebox.com/storage/modules/33/admin_incorrect.png)

Como era de esperar, el inicio de sesión falló debido a la contraseña incorrecta, lo que lleva a un resultado `false` de la operación `AND`.

---

## SQLi Discovery

Antes de comenzar a subvertir la lógica de la aplicación web e intentar eludir la autenticación, primero debemos probar si el formulario de inicio de sesión es vulnerable a la inyección SQL. Para hacerlo, intentaremos agregar una de las siguientes payloads después de nuestro nombre de usuario y ver si causa algún error o cambia el comportamiento de la página:

|Payload|URL Encoded|
|---|---|
|`'`|`%27`|
|`"`|`%22`|
|`#`|`%23`|
|`;`|`%3B`|
|`)`|`%29`|

Nota: En algunos casos, es posible que debamos usar la versión codificada en URL de la carga útil. Un ejemplo de esto es cuando ponemos nuestra carga útil directamente en la URL (es decir, solicitud HTTP GET).

Entonces, comencemos inyectando una comilla simple:

![quote_error](https://academy.hackthebox.com/storage/modules/33/quote_error.png)

Vemos que se lanzó un error SQL en lugar del mensaje `Login Failed`. La página arrojó un error porque la consulta resultante fue:

```r
SELECT * FROM logins WHERE username=''' AND password = 'something';
```

Como se discutió en la sección anterior, la comilla que ingresamos resultó en un número impar de comillas, lo que causó un error de sintaxis. Una opción sería comentar el resto de la consulta y escribir el resto de la consulta como parte de nuestra inyección para formar una consulta funcional. Otra opción es usar un número par de comillas dentro de nuestra consulta inyectada, de modo que la consulta final aún funcione.

---

## OR Injection

Necesitaríamos que la consulta siempre devuelva `true`, independientemente del nombre de usuario y la contraseña ingresados, para eludir la autenticación. Para hacer esto, podemos abusar del operador `OR` en nuestra inyección SQL.

Como se discutió anteriormente, la documentación de MySQL sobre [precedencia de operadores](https://dev.mysql.com/doc/refman/8.0/en/operator-precedence.html) establece que el operador `AND` se evaluará antes que el operador `OR`. Esto significa que si hay al menos una condición `TRUE` en toda la consulta junto con un operador `OR`, toda la consulta se evaluará como `TRUE` ya que el operador `OR` devuelve `TRUE` si uno de sus operandos es `TRUE`.

Un ejemplo de una condición que siempre devolverá `true` es `'1'='1'`. Sin embargo, para mantener la consulta SQL funcionando y mantener un número par de comillas, en lugar de usar ('1'='1'), eliminaremos la última comilla y usaremos ('1'='1), de modo que la comilla simple restante de la consulta original esté en su lugar.

Entonces, si inyectamos la siguiente condición y tenemos un operador `OR` entre ella y la condición original, siempre debería devolver `true`:

```r
admin' or '1'='1
```

La consulta final debería ser la siguiente:

```r
SELECT * FROM logins WHERE username='admin' or '1'='1' AND password = 'something';
```

Esto significa lo siguiente:

- Si el nombre de usuario es `admin`  
    `OR`
- Si `1=1` devuelve `true` 'lo cual siempre devuelve `true`'  
    `AND`
- Si la contraseña es `something`

![or_inject_diagram](https://academy.hackthebox.com/storage/modules/33/or_inject_diagram.png)

El operador `AND` se evaluará primero y devolverá `false`. Luego, el operador `OR` se evaluará, y si alguna de las declaraciones es `true`, devolverá `true`. Dado que `1=1` siempre devuelve `true`, esta consulta devolverá `true` y nos otorgará acceso.

Nota: La carga útil que usamos anteriormente es una de muchas payloads de bypass de autenticación que podemos usar para subvertir la lógica de autenticación. Puedes encontrar una lista completa de payloads de SQLi para eludir la autenticación en [PayloadAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection#authentication-bypass), cada una de las cuales funciona en un cierto tipo de consultas SQL.

---

## Auth Bypass with OR operator

Intentemos esto como el nombre de usuario y veamos la respuesta.

![inject_success](https://academy.hackthebox.com/storage/modules/33/inject_success.png)

Pudimos iniciar sesión con éxito como administrador. Sin embargo, ¿qué pasa si no conocemos un nombre de usuario válido? Intentemos la misma solicitud con un nombre de usuario diferente esta vez.

![notadmin_fail](https://academy.hackthebox.com/storage/modules/33/notadmin_fail.png)

El inicio de sesión falló porque `notAdmin` no existe en la tabla y resultó en una consulta falsa en general.

![notadmin_diagram](https://academy.hackthebox.com/storage/modules/33/notadmin_diagram_1.png)

Para iniciar sesión con éxito una vez más, necesitaremos una consulta `true` en general. Esto se puede lograr inyectando una condición `OR` en el campo de la contraseña, de modo que siempre devuelva `true`. Intentemos `something' or '1'='1` como la contraseña.

![password_or_injection](https://academy.hackthebox.com/storage/modules/33/password_or_injection.png)

La condición adicional `OR` resultó en una consulta `true` en general, ya que la cláusula `WHERE` devuelve todo en la tabla y se inicia sesión con el usuario presente en la primera fila. En este caso, como ambas condiciones devolverán `true`, no tenemos que proporcionar un nombre de usuario y una contraseña de prueba y podemos comenzar directamente con la inyección `'` y iniciar sesión con solo `' or '1' = '1`.

![basic_auth_bypass](https://academy.hackthebox.com/storage/modules/33/basic_auth_bypass.png)

Esto funciona ya que la consulta se evalúa como `true` independientemente del nombre de usuario o la contraseña.
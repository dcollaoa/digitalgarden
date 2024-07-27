Hasta ahora, solo hemos estado utilizando vulnerabilidades de IDOR para acceder a archivos y recursos que están fuera del alcance de nuestro usuario. Sin embargo, las vulnerabilidades de IDOR también pueden existir en llamadas a funciones y APIs, y explotarlas nos permitiría realizar varias acciones como otros usuarios.

Mientras que las `IDOR Information Disclosure Vulnerabilities` nos permiten leer varios tipos de recursos, las `IDOR Insecure Function Calls` nos permiten llamar APIs o ejecutar funciones como otro usuario. Estas funciones y APIs pueden ser usadas para cambiar la información privada de otro usuario, restablecer la contraseña de otro usuario o incluso comprar artículos usando la información de pago de otro usuario. En muchos casos, podríamos estar obteniendo cierta información a través de una vulnerabilidad de divulgación de información IDOR y luego usar esta información con vulnerabilidades de llamada a funciones inseguras de IDOR, como veremos más adelante en el módulo.

---

## Identifying Insecure APIs

Volviendo a nuestra aplicación web `Employee Manager`, podemos empezar probando la página `Edit Profile` en busca de vulnerabilidades de IDOR:

`http://SERVER_IP:PORT/`

![Employee Manager](https://academy.hackthebox.com/storage/modules/134/web_attacks_idor_employee_manager.jpg)

Cuando hacemos clic en el botón `Edit Profile`, se nos lleva a una página para editar la información de nuestro perfil de usuario, es decir, `Full Name`, `Email` y `About Me`, que es una característica común en muchas aplicaciones web:

`http://SERVER_IP:PORT/profile/index.php`

![Edit Profile](https://academy.hackthebox.com/storage/modules/134/web_attacks_idor_edit_profile.jpg)

Podemos cambiar cualquiera de los detalles en nuestro perfil y hacer clic en `Update profile`, y veremos que se actualizan y persisten a través de las actualizaciones, lo que significa que se actualizan en una base de datos en algún lugar. Interceptemos la solicitud de `Update` en Burp y observémosla:

![Update Request](https://academy.hackthebox.com/storage/modules/134/web_attacks_idor_update_request.jpg)

Vemos que la página está enviando una solicitud `PUT` al endpoint de la API `/profile/api.php/profile/1`. Las solicitudes `PUT` generalmente se usan en APIs para actualizar detalles de elementos, mientras que `POST` se usa para crear nuevos elementos, `DELETE` para eliminar elementos, y `GET` para recuperar detalles de elementos. Por lo tanto, una solicitud `PUT` para la función de `Update profile` es esperada. La parte interesante son los parámetros JSON que está enviando:

```json
{
    "uid": 1,
    "uuid": "40f5888b67c748df7efba008e7c2f9d2",
    "role": "employee",
    "full_name": "Amy Lindon",
    "email": "a_lindon@employees.htb",
    "about": "A Release is like a boat. 80% of the holes plugged is not good enough."
}
```

Vemos que la solicitud `PUT` incluye algunos parámetros ocultos, como `uid`, `uuid` y, más interesante, `role`, que está configurado como `employee`. La aplicación web también parece estar configurando los privilegios de acceso del usuario (por ejemplo, `role`) en el lado del cliente, en forma de nuestra cookie `Cookie: role=employee`, que parece reflejar el `role` especificado para nuestro usuario. Este es un problema de seguridad común. Los privilegios de control de acceso se envían como parte de la solicitud HTTP del cliente, ya sea como una cookie o como parte de la solicitud JSON, dejándolos bajo el control del cliente, lo que podría ser manipulado para obtener más privilegios.

Entonces, a menos que la aplicación web tenga un sistema de control de acceso sólido en el backend, deberíamos poder establecer un rol arbitrario para nuestro usuario, lo que podría otorgarnos más privilegios. Sin embargo, ¿cómo sabríamos qué otros roles existen?

---

## Exploiting Insecure APIs

Sabemos que podemos cambiar los parámetros `full_name`, `email` y `about`, ya que estos son los que están bajo nuestro control en el formulario HTML en la página web `/profile`. Así que, intentemos manipular los otros parámetros.

Hay algunas cosas que podríamos intentar en este caso:

1. Cambiar nuestro `uid` al `uid` de otro usuario, de modo que podamos tomar control de sus cuentas
2. Cambiar los detalles de otro usuario, lo que podría permitirnos realizar varios ataques web
3. Crear nuevos usuarios con detalles arbitrarios, o eliminar usuarios existentes
4. Cambiar nuestro rol a un rol más privilegiado (por ejemplo, `admin`) para poder realizar más acciones

Comencemos cambiando nuestro `uid` al `uid` de otro usuario (por ejemplo, `"uid": 2`). Sin embargo, cualquier número que establezcamos que no sea nuestro propio `uid` nos da una respuesta de `uid mismatch`:

![UID Mismatch](https://academy.hackthebox.com/storage/modules/134/web_attacks_idor_uid_mismatch.jpg)

La aplicación web parece estar comparando el `uid` de la solicitud con el endpoint de la API (`/1`). Esto significa que una forma de control de acceso en el backend nos impide cambiar arbitrariamente algunos parámetros JSON, lo cual podría ser necesario para evitar que la aplicación web se bloquee o devuelva errores.

Tal vez podamos intentar cambiar los detalles de otro usuario. Cambiaremos el endpoint de la API a `/profile/api.php/profile/2`, y cambiaremos `"uid": 2` para evitar el `uid mismatch` anterior:

![UUID Mismatch](https://academy.hackthebox.com/storage/modules/134/web_attacks_idor_uuid_mismatch.jpg)

Como podemos ver, esta vez, obtenemos un mensaje de error diciendo `uuid mismatch`. La aplicación web parece estar comprobando si el valor `uuid` que estamos enviando coincide con el `uuid` del usuario. Dado que estamos enviando nuestro propio `uuid`, nuestra solicitud falla. Esto parece ser otra forma de control de acceso para evitar que los usuarios cambien los detalles de otro usuario.

A continuación, veamos si podemos crear un nuevo usuario con una solicitud `POST` al endpoint de la API. Podemos cambiar el método de la solicitud a `POST`, cambiar el `uid` a un nuevo `uid`, y enviar la solicitud al endpoint de la API del nuevo `uid`:

![Create New User](https://academy.hackthebox.com/storage/modules/134/web_attacks_idor_create_new_user_1.jpg)

Obtenemos un mensaje de error diciendo `Creating new employees is for admins only`. Lo mismo ocurre cuando enviamos una solicitud `DELETE`, ya que obtenemos `Deleting employees is for admins only`. La aplicación web podría estar comprobando nuestra autorización a través de la cookie `role=employee` porque esta parece ser la única forma de autorización en la solicitud HTTP.

Finalmente, intentemos cambiar nuestro `role` a `admin`/`administrator` para obtener mayores privilegios. Desafortunadamente, sin conocer un nombre de `role` válido, obtenemos `Invalid role` en la respuesta HTTP, y nuestro `role` no se actualiza: 

![Invalid Role](https://academy.hackthebox.com/storage/modules/134/web_attacks_idor_invalid_role.jpg)

Así que, todos nuestros intentos parecen haber fallado. No podemos crear ni eliminar usuarios ya que no podemos cambiar nuestro `role`. No podemos cambiar nuestro propio `uid`, ya que hay medidas preventivas en el backend que no podemos controlar, ni podemos cambiar los detalles de otro usuario por la misma razón. ¿Entonces, la aplicación web es segura contra ataques de IDOR?

Hasta ahora, solo hemos estado probando las `IDOR Insecure Function Calls`. Sin embargo, no hemos probado la solicitud `GET` de la API en busca de `IDOR Information Disclosure Vulnerabilities`. Si no hubiera un sistema de control de acceso robusto en su lugar, podríamos leer los detalles de otros usuarios, lo que podría ayudarnos con los ataques anteriores que intentamos.

Intenta probar la API contra vulnerabilidades de divulgación de información IDOR intentando obtener los detalles de otros usuarios con solicitudes `GET`. Si la API es vulnerable, podríamos filtrar los detalles de otros usuarios y luego usar esta información para completar nuestros ataques de IDOR en las llamadas a funciones.
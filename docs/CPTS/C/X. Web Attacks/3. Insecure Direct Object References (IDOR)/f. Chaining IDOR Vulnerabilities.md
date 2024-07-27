Usualmente, una solicitud `GET` al endpoint de la API debería devolver los detalles del usuario solicitado, así que podemos intentar llamarlo para ver si podemos recuperar los detalles de nuestro usuario. También notamos que después de que la página carga, obtiene los detalles del usuario con una solicitud `GET` al mismo endpoint de la API: ![get_api](https://academy.hackthebox.com/storage/modules/134/web_attacks_idor_get_api.jpg)

Como se mencionó en la sección anterior, la única forma de autorización en nuestras solicitudes HTTP es la cookie `role=employee`, ya que la solicitud HTTP no contiene ninguna otra forma de autorización específica del usuario, como un token JWT, por ejemplo. Incluso si existiera un token, a menos que se estuviera comparando activamente con los detalles del objeto solicitado por un sistema de control de acceso de back-end, aún podríamos recuperar los detalles de otros usuarios.

---

## Information Disclosure

Vamos a enviar una solicitud `GET` con otro `uid`:

![get_another_user](https://academy.hackthebox.com/storage/modules/134/web_attacks_idor_get_another_user.jpg)

Como podemos ver, esto devolvió los detalles de otro usuario, con su propio `uuid` y `role`, confirmando una `IDOR Information Disclosure vulnerability`:


```r
{
    "uid": "2",
    "uuid": "4a9bd19b3b8676199592a346051f950c",
    "role": "employee",
    "full_name": "Iona Franklyn",
    "email": "i_franklyn@employees.htb",
    "about": "It takes 20 years to build a reputation and few minutes of cyber-incident to ruin it."
}
```

Esto nos proporciona nuevos detalles, en particular el `uuid`, que no podíamos calcular antes, y por lo tanto no podíamos cambiar los detalles de otros usuarios.

---

## Modifying Other Users' Details

Ahora, con el `uuid` del usuario en mano, podemos cambiar los detalles de este usuario enviando una solicitud `PUT` a `/profile/api.php/profile/2` con los detalles anteriores junto con cualquier modificación que hayamos hecho, de la siguiente manera:

![modify_another_user](https://academy.hackthebox.com/storage/modules/134/web_attacks_idor_modify_another_user.jpg)

Esta vez no obtenemos mensajes de error de control de acceso, y cuando intentamos `GET` los detalles del usuario nuevamente, vemos que de hecho actualizamos sus detalles:

![new_another_user_details](https://academy.hackthebox.com/storage/modules/134/web_attacks_idor_new_another_user_details.jpg)

Además de permitirnos ver detalles potencialmente sensibles, la capacidad de modificar los detalles de otro usuario también nos permite realizar varios otros ataques. Un tipo de ataque es `modifying a user's email address` y luego solicitar un enlace de restablecimiento de contraseña, que se enviará a la dirección de correo electrónico que especificamos, lo que nos permitirá tomar el control de su cuenta. Otro posible ataque es `placing an XSS payload in the 'about' field`, que se ejecutaría una vez que el usuario visite su página de `Edit profile`, permitiéndonos atacar al usuario de diferentes maneras.

---

## Chaining Two IDOR Vulnerabilities

Dado que hemos identificado una IDOR Information Disclosure vulnerability, también podemos enumerar todos los usuarios y buscar otros `roles`, idealmente un rol de admin. `Try to write a script to enumerate all users, similarly to what we did previously`.

Una vez que enumeremos a todos los usuarios, encontraremos un usuario administrador con los siguientes detalles:


```r
{
    "uid": "X",
    "uuid": "a36fa9e66e85f2dd6f5e13cad45248ae",
    "role": "web_admin",
    "full_name": "administrator",
    "email": "webadmin@employees.htb",
    "about": "HTB{FLAG}"
}
```

Podemos modificar los detalles del administrador y luego realizar uno de los ataques mencionados anteriormente para tomar el control de su cuenta. Sin embargo, como ahora conocemos el nombre del rol de administrador (`web_admin`), podemos configurarlo para nuestro usuario para que podamos crear nuevos usuarios o eliminar usuarios actuales. Para hacerlo, interceptaremos la solicitud cuando hagamos clic en el botón `Update profile` y cambiaremos nuestro rol a `web_admin`:

![modify_our_role](https://academy.hackthebox.com/storage/modules/134/web_attacks_idor_modify_our_role.jpg)

Esta vez, no obtenemos el mensaje de error `Invalid role`, ni obtenemos mensajes de error de control de acceso, lo que significa que no hay medidas de control de acceso de back-end para los roles que podemos asignar a nuestro usuario. Si `GET` nuestros detalles de usuario, vemos que nuestro `role` ha sido configurado a `web_admin`:


```r
{
    "uid": "1",
    "uuid": "40f5888b67c748df7efba008e7c2f9d2",
    "role": "web_admin",
    "full_name": "Amy Lindon",
    "email": "a_lindon@employees.htb",
    "about": "A Release is like a boat. 80% of the holes plugged is not good enough."
}
```

Ahora, podemos refrescar la página para actualizar nuestra cookie, o configurarla manualmente como `Cookie: role=web_admin`, y luego interceptar la solicitud de `Update` para crear un nuevo usuario y ver si se nos permite hacerlo:

![create_new_user_2](https://academy.hackthebox.com/storage/modules/134/web_attacks_idor_create_new_user_2.jpg)

No obtuvimos un mensaje de error esta vez. Si enviamos una solicitud `GET` para el nuevo usuario, vemos que ha sido creado con éxito:

![create_new_user_2](https://academy.hackthebox.com/storage/modules/134/web_attacks_idor_get_new_user.jpg)

Al combinar la información que obtuvimos de la `IDOR Information Disclosure vulnerability` con un ataque de `IDOR Insecure Function Calls` en un endpoint de la API, pudimos modificar los detalles de otros usuarios y crear/eliminar usuarios mientras eludíamos varias verificaciones de control de acceso existentes. En muchas ocasiones, la información que filtramos a través de vulnerabilidades IDOR puede ser utilizada en otros ataques, como IDOR o XSS, lo que lleva a ataques más sofisticados o a la elusión de mecanismos de seguridad existentes.

Con nuestro nuevo `role`, también podemos realizar asignaciones masivas para cambiar campos específicos para todos los usuarios, como colocar payloads XSS en sus perfiles o cambiar su correo electrónico a uno que especifiquemos. `Try to write a script that changes all users' email to an email you choose`. Puedes hacerlo recuperando sus `uuids` y luego enviando una solicitud `PUT` para cada uno con el nuevo correo electrónico.
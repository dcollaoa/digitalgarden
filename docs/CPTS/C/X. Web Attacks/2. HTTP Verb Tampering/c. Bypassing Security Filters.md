Exploiting HTTP Verb Tampering vulnerabilities es usualmente un proceso relativamente sencillo. Solo necesitamos probar métodos HTTP alternativos para ver cómo son manejados por el servidor web y la aplicación web. Mientras que muchas herramientas automatizadas de escaneo de vulnerabilidades pueden identificar consistentemente vulnerabilidades de HTTP Verb Tampering causadas por configuraciones inseguras del servidor, usualmente no logran identificar vulnerabilidades de HTTP Tampering causadas por codificación insegura. Esto se debe a que el primer tipo puede ser identificado fácilmente una vez que pasamos una página de autenticación, mientras que el otro necesita pruebas activas para ver si podemos pasar los filtros de seguridad en su lugar.

El primer tipo de vulnerabilidad de HTTP Verb Tampering es principalmente causado por `Insecure Web Server Configurations`, y explotar esta vulnerabilidad puede permitirnos pasar el prompt de HTTP Basic Authentication en ciertas páginas.

---

## Identify

Cuando comenzamos el ejercicio al final de esta sección, vemos que tenemos una aplicación web básica de `File Manager`, en la que podemos agregar nuevos archivos escribiendo sus nombres y presionando `enter`:

`http://SERVER_IP:PORT/`

![](https://academy.hackthebox.com/storage/modules/134/web_attacks_verb_tampering_add.jpg)

Sin embargo, supongamos que intentamos borrar todos los archivos haciendo clic en el botón rojo `Reset`. En ese caso, vemos que esta funcionalidad parece estar restringida solo para usuarios autenticados, ya que obtenemos el siguiente prompt de `HTTP Basic Auth`:

`http://SERVER_IP:PORT/`

![](https://academy.hackthebox.com/storage/modules/134/web_attacks_verb_tampering_reset.jpg)

Como no tenemos credenciales, obtendremos una página `401 Unauthorized`:

`http://SERVER_IP:PORT/admin/reset.php`

![](https://academy.hackthebox.com/storage/modules/134/web_attacks_verb_tampering_unauthorized.jpg)

Así que, veamos si podemos pasar esto con un ataque de HTTP Verb Tampering. Para hacerlo, necesitamos identificar qué páginas están restringidas por esta autenticación. Si examinamos la solicitud HTTP después de hacer clic en el botón Reset o miramos la URL a la que el botón navega después de hacer clic en él, vemos que está en `/admin/reset.php`. Entonces, o el directorio `/admin` está restringido solo para usuarios autenticados, o solo la página `/admin/reset.php` lo está. Podemos confirmar esto visitando el directorio `/admin`, y efectivamente se nos solicita iniciar sesión nuevamente. Esto significa que el directorio completo `/admin` está restringido.

---

## Exploit

Para intentar explotar la página, necesitamos identificar el método de solicitud HTTP utilizado por la aplicación web. Podemos interceptar la solicitud en Burp Suite y examinarla: ![unauthorized_request](https://academy.hackthebox.com/storage/modules/134/web_attacks_verb_tampering_unauthorized_request.jpg)

Como la página utiliza una solicitud `GET`, podemos enviar una solicitud `POST` y ver si la página web permite solicitudes `POST` (es decir, si la autenticación cubre solicitudes `POST`). Para hacerlo, podemos hacer clic derecho en la solicitud interceptada en Burp y seleccionar `Change Request Method`, y cambiará automáticamente la solicitud a una solicitud `POST`: ![change_request](https://academy.hackthebox.com/storage/modules/134/web_attacks_verb_tampering_change_request.jpg)

Una vez que lo hagamos, podemos hacer clic en `Forward` y examinar la página en nuestro navegador. Desafortunadamente, aún se nos solicita iniciar sesión y obtendremos una página `401 Unauthorized` si no proporcionamos las credenciales:

![](https://academy.hackthebox.com/storage/modules/134/web_attacks_verb_tampering_reset.jpg)

Así que, parece que las configuraciones del servidor web cubren tanto las solicitudes `GET` como `POST`. Sin embargo, como hemos aprendido anteriormente, podemos utilizar muchos otros métodos HTTP, notablemente el método `HEAD`, que es idéntico a una solicitud `GET` pero no devuelve el cuerpo en la respuesta HTTP. Si esto tiene éxito, puede que no recibamos ninguna salida, pero la función `reset` aún debería ejecutarse, que es nuestro objetivo principal.

Para ver si el servidor acepta solicitudes `HEAD`, podemos enviar una solicitud `OPTIONS` y ver qué métodos HTTP son aceptados, de la siguiente manera:

  Bypassing Basic Authentication

```shell-session
3ky@htb[/htb]$ curl -i -X OPTIONS http://SERVER_IP:PORT/

HTTP/1.1 200 OK
Date: 
Server: Apache/2.4.41 (Ubuntu)
Allow: POST,OPTIONS,HEAD,GET
Content-Length: 0
Content-Type: httpd/unix-directory
```

Como podemos ver, la respuesta muestra `Allow: POST,OPTIONS,HEAD,GET`, lo que significa que el servidor web efectivamente acepta solicitudes `HEAD`, que es la configuración predeterminada para muchos servidores web. Así que, intentemos interceptar la solicitud `reset` nuevamente, y esta vez utilizar una solicitud `HEAD` para ver cómo el servidor web la maneja:

![HEAD_request](https://academy.hackthebox.com/storage/modules/134/web_attacks_verb_tampering_HEAD_request.jpg)

Una vez que cambiamos de `POST` a `HEAD` y reenviamos la solicitud, veremos que ya no se nos solicita iniciar sesión ni obtenemos una página `401 Unauthorized` y obtenemos una salida vacía en su lugar, como se esperaba con una solicitud `HEAD`. Si volvemos a la aplicación web `File Manager`, veremos que todos los archivos han sido eliminados, lo que significa que activamos con éxito la funcionalidad `Reset` sin tener acceso de administrador o cualquier credencial:

`http://SERVER_IP:PORT/`

![](https://academy.hackthebox.com/storage/modules/134/web_attacks_verb_tampering_after_reset.jpg)

Intenta probar otros métodos HTTP, y ve cuáles pueden pasar exitosamente el prompt de autenticación.
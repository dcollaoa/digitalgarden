
No habrá ninguna protección desplegada en el lado del objetivo en un escenario ideal, por lo que no se impedirá la explotación automática. De lo contrario, podemos esperar problemas al ejecutar una herramienta automatizada de cualquier tipo contra dicho objetivo. No obstante, muchos mecanismos están incorporados en SQLMap, que pueden ayudarnos a eludir con éxito tales protecciones.

---

## Anti-CSRF Token Bypass

Una de las primeras líneas de defensa contra el uso de herramientas de automatización es la incorporación de tokens anti-CSRF (i.e., Cross-Site Request Forgery) en todas las solicitudes HTTP, especialmente aquellas generadas como resultado del llenado de formularios web.

En términos más básicos, cada solicitud HTTP en tal escenario debería tener un valor de token (válido) disponible solo si el usuario realmente visitó y utilizó la página. Aunque la idea original era la prevención de escenarios con enlaces maliciosos, donde simplemente abrir estos enlaces tendría consecuencias no deseadas para los usuarios con sesión iniciada (e.g., abrir páginas de administrador y agregar un nuevo usuario con credenciales predefinidas), esta característica de seguridad también endureció inadvertidamente las aplicaciones contra la automatización (no deseada).

No obstante, SQLMap tiene opciones que pueden ayudar a eludir la protección anti-CSRF. Específicamente, la opción más importante es `--csrf-token`. Al especificar el nombre del parámetro del token (que ya debería estar disponible dentro de los datos de solicitud proporcionados), SQLMap intentará automáticamente analizar el contenido de la respuesta del objetivo y buscar nuevos valores de token para usarlos en la siguiente solicitud.

Además, incluso en un caso en el que el usuario no especifique explícitamente el nombre del token a través de `--csrf-token`, si uno de los parámetros proporcionados contiene alguno de los infijos comunes (i.e. `csrf`, `xsrf`, `token`), se le pedirá al usuario que lo actualice en solicitudes futuras:

```r
sqlmap -u "http://www.example.com/" --data="id=1&csrf-token=WfF1szMUHhiokx9AHFply5L2xAOfjRkE" --csrf-token="csrf-token"

        ___
       __H__
 ___ ___[,]_____ ___ ___  {1.4.9}
|_ -| . [']     | .'| . |
|___|_  [)]_|_|_|__,|  _|
      |_|V...       |_|   http://sqlmap.org

[*] starting @ 22:18:01 /2020-09-18/

POST parameter 'csrf-token' appears to hold anti-CSRF token. Do you want sqlmap to automatically update it in further requests? [y/N] y
```

---

## Unique Value Bypass

En algunos casos, la aplicación web puede requerir que se proporcionen valores únicos dentro de parámetros predefinidos. Tal mecanismo es similar a la técnica anti-CSRF descrita anteriormente, excepto que no es necesario analizar el contenido de la página web. Por lo tanto, simplemente asegurando que cada solicitud tenga un valor único para un parámetro predefinido, la aplicación web puede evitar fácilmente los intentos de CSRF al mismo tiempo que evita algunas de las herramientas de automatización. Para esto, se debe usar la opción `--randomize`, apuntando al nombre del parámetro que contiene un valor que debe ser aleatorizado antes de ser enviado:

```r
sqlmap -u "http://www.example.com/?id=1&rp=29125" --randomize=rp --batch -v 5 | grep URI

URI: http://www.example.com:80/?id=1&rp=99954
URI: http://www.example.com:80/?id=1&rp=87216
URI: http://www.example.com:80/?id=9030&rp=36456
URI: http://www.example.com:80/?id=1.%2C%29%29%27.%28%28%2C%22&rp=16689
URI: http://www.example.com:80/?id=1%27xaFUVK%3C%27%22%3EHKtQrg&rp=40049
URI: http://www.example.com:80/?id=1%29%20AND%209368%3D6381%20AND%20%287422%3D7422&rp=95185
```

---

## Calculated Parameter Bypass

Otro mecanismo similar es cuando una aplicación web espera que un valor de parámetro adecuado se calcule en función de otros valores de parámetros. Con mayor frecuencia, un valor de parámetro debe contener el digest del mensaje (e.g. `h=MD5(id)`) de otro. Para eludir esto, se debe usar la opción `--eval`, donde se evalúa un código Python válido justo antes de que se envíe la solicitud al objetivo:

```r
sqlmap -u "http://www.example.com/?id=1&h=c4ca4238a0b923820dcc509a6f75849b" --eval="import hashlib; h=hashlib.md5(id).hexdigest()" --batch -v 5 | grep URI

URI: http://www.example.com:80/?id=1&h=c4ca4238a0b923820dcc509a6f75849b
URI: http://www.example.com:80/?id=1&h=c4ca4238a0b923820dcc509a6f75849b
URI: http://www.example.com:80/?id=9061&h=4d7e0d72898ae7ea3593eb5ebf20c744
URI: http://www.example.com:80/?id=1%2C.%2C%27%22.%2C%28.%29&h=620460a56536e2d32fb2f4842ad5a08d
URI: http://www.example.com:80/?id=1%27MyipGP%3C%27%22%3EibjjSu&h=db7c815825b14d67aaa32da09b8b2d42
URI: http://www.example.com:80/?id=1%29%20AND%209978%socks4://177.39.187.70:33283ssocks4://177.39.187.70:332833D1232%20AND%20%284955%3D4955&h=02312acd4ebe69e2528382dfff7fc5cc
```

---

## IP Address Concealing

En caso de que queramos ocultar nuestra dirección IP, o si una determinada aplicación web tiene un mecanismo de protección que pone en la lista negra nuestra dirección IP actual, podemos intentar usar un proxy o la red de anonimato Tor. Un proxy se puede configurar con la opción `--proxy` (e.g. `--proxy="socks4://177.39.187.70:33283"`), donde deberíamos agregar un proxy funcional.

Además, si tenemos una lista de proxies, podemos proporcionarlos a SQLMap con la opción `--proxy-file`. De esta manera, SQLMap recorrerá secuencialmente la lista, y en caso de cualquier problema (e.g., poner en la lista negra la dirección IP), simplemente pasará del actual al siguiente de la lista. La otra opción es el uso de la red Tor para proporcionar una fácil anonimización, donde nuestra IP puede aparecer desde cualquier lugar de una gran lista de nodos de salida de Tor. Cuando se instala correctamente en la máquina local, debería haber un servicio de proxy `SOCKS4` en el puerto local 9050 o 9150. Al usar el interruptor `--tor`, SQLMap intentará automáticamente encontrar el puerto local y usarlo apropiadamente.

Si quisiéramos asegurarnos de que Tor se está usando correctamente, para prevenir un comportamiento no deseado, podríamos usar el interruptor `--check-tor`. En tales casos, SQLMap se conectará a `https://check.torproject.org/` y verificará la respuesta para el resultado esperado (i.e., aparece `Congratulations`).

---

## WAF Bypass

Siempre que ejecutamos SQLMap, como parte de las pruebas iniciales, SQLMap envía una carga maliciosa predefinida usando un nombre de parámetro inexistente (e.g. `?pfov=...`) para probar la existencia de un WAF (Web Application Firewall). Habrá un cambio sustancial en la respuesta en comparación con la original en caso de cualquier protección entre el usuario y el objetivo. Por ejemplo, si se implementa una de las soluciones WAF más populares (ModSecurity), debería haber una respuesta `406 - Not Acceptable` después de tal solicitud.

En caso de una detección positiva, para identificar el mecanismo de protección real, SQLMap usa una biblioteca de terceros [identYwaf](https://github.com/stamparm/identYwaf), que contiene las firmas de 80 soluciones WAF diferentes. Si quisiéramos omitir esta prueba heurística por completo (i.e., para producir menos ruido), podemos usar el interruptor `--skip-waf`.

---

## User-agent Blacklisting Bypass

En caso de problemas inmediatos (e.g., código de error HTTP 5XX desde el principio) al ejecutar SQLMap, una de las primeras cosas que deberíamos considerar es la posible inclusión en la lista negra del user-agent predeterminado usado por SQLMap (e.g. `User-agent: sqlmap/1.4.9 (http://sqlmap.org)`).

Esto es trivial de eludir con el interruptor `--random-agent`, que cambia el

 user-agent predeterminado por un valor elegido al azar de un gran conjunto de valores usados por los navegadores.

Nota: Si se detecta alguna forma de protección durante la ejecución, podemos esperar problemas con el objetivo, incluso con otros mecanismos de seguridad. La razón principal es el desarrollo continuo y las nuevas mejoras en tales protecciones, dejando menos y menos espacio de maniobra para los atacantes.

---

## Tamper Scripts

Finalmente, uno de los mecanismos más populares implementados en SQLMap para eludir soluciones WAF/IPS es el llamado "tamper scripts". Los tamper scripts son un tipo especial de scripts (Python) escritos para modificar solicitudes justo antes de ser enviadas al objetivo, en la mayoría de los casos para eludir alguna protección.

Por ejemplo, uno de los tamper scripts más populares [between](https://github.com/sqlmapproject/sqlmap/blob/master/tamper/between.py) reemplaza todas las ocurrencias del operador mayor que (`>`) con `NOT BETWEEN 0 AND #`, y el operador igual (`=`) con `BETWEEN # AND #`. De esta manera, muchos mecanismos de protección primitivos (enfocados principalmente en prevenir ataques XSS) se eluden fácilmente, al menos para propósitos de SQLi.

Los tamper scripts se pueden encadenar, uno tras otro, dentro de la opción `--tamper` (e.g. `--tamper=between,randomcase`), donde se ejecutan según su prioridad predefinida. La prioridad está predefinida para evitar cualquier comportamiento no deseado, ya que algunos scripts modifican las cargas útiles al modificar su sintaxis SQL (e.g. [ifnull2ifisnull](https://github.com/sqlmapproject/sqlmap/blob/master/tamper/ifnull2ifisnull.py)). En contraste, algunos tamper scripts no se preocupan por el contenido interno (e.g. [appendnullbyte](https://github.com/sqlmapproject/sqlmap/blob/master/tamper/appendnullbyte.py)).

Los tamper scripts pueden modificar cualquier parte de la solicitud, aunque la mayoría cambia el contenido de la carga útil. Los tamper scripts más notables son los siguientes:

|**Tamper-Script**|**Descripción**|
|---|---|
|`0eunion`|Reemplaza instancias de `UNION` con `e0UNION`|
|`base64encode`|Codifica en Base64 todos los caracteres en una carga útil dada|
|`between`|Reemplaza el operador mayor que (`>`) con `NOT BETWEEN 0 AND #` y el operador igual (`=`) con `BETWEEN # AND #`|
|`commalesslimit`|Reemplaza instancias (MySQL) como `LIMIT M, N` con el equivalente `LIMIT N OFFSET M`|
|`equaltolike`|Reemplaza todas las ocurrencias del operador igual (`=`) con el equivalente `LIKE`|
|`halfversionedmorekeywords`|Agrega un comentario versionado (MySQL) antes de cada palabra clave|
|`modsecurityversioned`|Incluye la consulta completa con un comentario versionado (MySQL)|
|`modsecurityzeroversioned`|Incluye la consulta completa con un comentario de versión cero (MySQL)|
|`percentage`|Agrega un signo de porcentaje (`%`) frente a cada carácter (e.g. SELECT -> %S%E%L%E%C%T)|
|`plus2concat`|Reemplaza el operador más (`+`) con la función CONCAT() (MsSQL)|
|`randomcase`|Reemplaza cada carácter de palabra clave con un valor de caso aleatorio (e.g. SELECT -> SEleCt)|
|`space2comment`|Reemplaza el carácter de espacio con comentarios `/|
|`space2dash`|Reemplaza el carácter de espacio con un comentario de guion (`--`) seguido de una cadena aleatoria y una nueva línea (`\n`)|
|`space2hash`|Reemplaza las instancias (MySQL) del carácter de espacio con un carácter de almohadilla (`#`) seguido de una cadena aleatoria y una nueva línea (`\n`)|
|`space2mssqlblank`|Reemplaza las instancias (MsSQL) del carácter de espacio con un carácter en blanco aleatorio de un conjunto válido de caracteres alternativos|
|`space2plus`|Reemplaza el carácter de espacio con un más (`+`)|
|`space2randomblank`|Reemplaza el carácter de espacio con un carácter en blanco aleatorio de un conjunto válido de caracteres alternativos|
|`symboliclogical`|Reemplaza los operadores lógicos AND y OR con sus equivalentes simbólicos (`&&` y `\|`)|
|`versionedkeywords`|Incluye cada palabra clave no funcional con un comentario versionado (MySQL)|
|`versionedmorekeywords`|Incluye cada palabra clave con un comentario versionado (MySQL)|

Para obtener una lista completa de los tamper scripts implementados, junto con la descripción como arriba, se puede usar el interruptor `--list-tampers`. También podemos desarrollar tamper scripts personalizados para cualquier tipo de ataque personalizado, como una SQLi de segundo orden.

---

## Miscellaneous Bypasses

Entre otros mecanismos de elusión de protección, hay dos más que deben mencionarse. El primero es la codificación de transferencia `Chunked`, activada mediante el interruptor `--chunked`, que divide el cuerpo de la solicitud POST en los llamados "chunks". Las palabras clave SQL en la lista negra se dividen entre los chunks de manera que la solicitud que las contiene pueda pasar desapercibida.

El otro mecanismo de elusión es la `HTTP parameter pollution` (`HPP`), donde las cargas útiles se dividen de manera similar al caso de `--chunked` entre diferentes valores de nombre de parámetro mismo (e.g. `?id=1&id=UNION&id=SELECT&id=username,password&id=FROM&id=users...`), que se concatenan por la plataforma objetivo si la soporta (e.g. `ASP`).
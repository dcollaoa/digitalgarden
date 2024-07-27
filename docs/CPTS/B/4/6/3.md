En la sección anterior, exploramos algunas herramientas que podemos usar desde nuestro host de ataque en Linux para enumerar con credenciales de dominio válidas. En esta sección, experimentaremos con algunas herramientas para enumerar desde un host de ataque en Windows, como SharpHound/BloodHound, PowerView/SharpView, Grouper2, Snaffler y algunas herramientas integradas útiles para la enumeración de AD. Parte de los datos que recopilamos en esta fase pueden proporcionar más información para el informe, no solo conducir directamente a rutas de ataque. Dependiendo del tipo de evaluación, nuestro cliente puede estar interesado en todos los hallazgos posibles, por lo que incluso problemas como la capacidad de ejecutar BloodHound libremente o ciertos atributos de cuentas de usuario pueden valer la pena incluirlos en nuestro informe como hallazgos de riesgo medio o en una sección de apéndice separada. No todos los problemas que descubrimos tienen que estar orientados a avanzar en nuestros ataques. Algunos de los resultados pueden ser informativos por naturaleza, pero útiles para el cliente para ayudar a mejorar su postura de seguridad.

En este punto, estamos interesados en otras configuraciones incorrectas y problemas de permisos que podrían conducir a movimientos laterales y verticales. También estamos interesados en obtener una visión más amplia de cómo está configurado el dominio, es decir, ¿existen confianzas con otros dominios tanto dentro como fuera del bosque actual? También nos interesa saquear los recursos compartidos de archivos a los que tiene acceso nuestro usuario, ya que a menudo contienen datos sensibles como credenciales que se pueden usar para ampliar nuestro acceso.

---

## TTPs

La primera herramienta que exploraremos es el [ActiveDirectory PowerShell module](https://docs.microsoft.com/en-us/powershell/module/activedirectory/?view=windowsserver2022-ps). Al aterrizar en un host de Windows en el dominio, especialmente uno que usa un administrador, existe la posibilidad de encontrar herramientas y scripts valiosos en el host.

---

## ActiveDirectory PowerShell Module

El módulo ActiveDirectory PowerShell es un grupo de cmdlets de PowerShell para administrar un entorno de Active Directory desde la línea de comandos. Consta de 147 cmdlets diferentes en el momento de escribir esto. No podemos cubrirlos todos aquí, pero veremos algunos que son particularmente útiles para enumerar entornos de AD. Siéntase libre de explorar otros cmdlets incluidos en el módulo en el laboratorio construido para esta sección y ver qué combinaciones interesantes y salidas puede crear.

Antes de que podamos utilizar el módulo, debemos asegurarnos de que esté importado primero. El cmdlet [Get-Module](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/get-module?view=powershell-7.2), que forma parte del [Microsoft.PowerShell.Core module](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/?view=powershell-7.2), enumerará todos los módulos disponibles, su versión y comandos potenciales para usar. Esta es una excelente manera de ver si algo como Git o scripts de administrador personalizados están instalados. Si el módulo no está cargado, ejecute `Import-Module ActiveDirectory` para cargarlo para su uso.

### Discover Modules

```r
PS C:\htb> Get-Module

ModuleType Version    Name                                ExportedCommands
---------- -------    ----                                ----------------
Manifest   3.1.0.0    Microsoft.PowerShell.Utility        {Add-Member, Add-Type, Clear-Variable, Compare-Object...}
Script     2.0.0      PSReadline                          {Get-PSReadLineKeyHandler, Get-PSReadLineOption, Remove-PS...
```

Veremos que el módulo ActiveDirectory aún no está importado. Vamos a importarlo.

### Load ActiveDirectory Module

```r
PS C:\htb> Import-Module ActiveDirectory
PS C:\htb> Get-Module

ModuleType Version    Name                                ExportedCommands
---------- -------    ----                                ----------------
Manifest   1.0.1.0    ActiveDirectory                     {Add-ADCentralAccessPolicyMember, Add-ADComputerServiceAcc...
Manifest   3.1.0.0    Microsoft.PowerShell.Utility        {Add-Member, Add-Type, Clear-Variable, Compare-Object...}
Script     2.0.0      PSReadline                          {Get-PSReadLineKeyHandler, Get-PSReadLineOption, Remove-PS...  
```

Ahora que nuestros módulos están cargados, comencemos. Primero, enumeraremos información básica sobre el dominio con el cmdlet [Get-ADDomain](https://docs.microsoft.com/en-us/powershell/module/activedirectory/get-addomain?view=windowsserver2022-ps).

### Get Domain Info

```r
PS C:\htb> Get-ADDomain

AllowedDNSSuffixes                 : {}
ChildDomains                       : {LOGISTICS.INLANEFREIGHT.LOCAL}
ComputersContainer                 : CN=Computers,DC=INLANEFREIGHT,DC=LOCAL
DeletedObjectsContainer            : CN=Deleted Objects,DC=INLANEFREIGHT,DC=LOCAL
DistinguishedName                  : DC=INLANEFREIGHT,DC=LOCAL
DNSRoot                            : INLANEFREIGHT.LOCAL
DomainControllersContainer         : OU=Domain Controllers,DC=INLANEFREIGHT,DC=LOCAL
DomainMode                         : Windows2016Domain
DomainSID                          : S-1-5-21-3842939050-3880317879-2865463114
ForeignSecurityPrincipalsContainer : CN=ForeignSecurityPrincipals,DC=INLANEFREIGHT,DC=LOCAL
Forest                             : INLANEFREIGHT.LOCAL
InfrastructureMaster               : ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL
LastLogonReplicationInterval       :
LinkedGroupPolicyObjects           : {cn={DDBB8574-E94E-4525-8C9D-ABABE31223D0},cn=policies,cn=system,DC=INLANEFREIGHT,
                                     DC=LOCAL, CN={31B2F340-016D-11D2-945F-00C04FB984F9},CN=Policies,CN=System,DC=INLAN
                                     EFREIGHT,DC=LOCAL}
LostAndFoundContainer              : CN=LostAndFound,DC=INLANEFREIGHT,DC=LOCAL
ManagedBy                          :
Name                               : INLANEFREIGHT
NetBIOSName                        : INLANEFREIGHT
ObjectClass                        : domainDNS
ObjectGUID                         : 71e4ecd1-a9f6-4f55-8a0b-e8c398fb547a
ParentDomain                       :
PDCEmulator                        : ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL
PublicKeyRequiredPasswordRolling   : True
QuotasContainer                    : CN=NTDS Quotas,DC=INLANEFREIGHT,DC=LOCAL
ReadOnlyReplicaDirectoryServers    : {}
ReplicaDirectoryServers            : {ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL}
RIDMaster                          : ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL
SubordinateReferences              : {DC=LOGISTICS,DC=INLANEFREIGHT,DC=LOCAL,
                                     DC=ForestDnsZones,DC=INLANEFREIGHT,DC=LOCAL,
                                     DC=DomainDnsZones,DC=INLANEFREIGHT,DC=LOCAL,
                                     CN=Configuration,DC=INLANEFREIGHT,DC=LOCAL}
SystemsContainer                   : CN=System,DC=INLANEFREIGHT,DC=LOCAL
UsersContainer                     : CN=Users,DC=INLANEFREIGHT,DC=LOCAL
```

Esto imprimirá información útil como el SID del dominio, el nivel funcional del dominio, cualquier dominio hijo y más. A continuación, utilizaremos el cmdlet [Get-ADUser](https://docs.microsoft.com/en-us/powershell/module/activedirectory/get-aduser?view=windowsserver2022-ps). Filtraremos las cuentas con la propiedad `ServicePrincipalName` poblada. Esto nos proporcionará una lista de cuentas que pueden ser susceptibles a un ataque de Kerberoasting, que cubriremos en profundidad después de la siguiente sección.

### Get-ADUser

```r
PS C:\htb> Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName

DistinguishedName    : CN=adfs,OU=Service Accounts,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
Enabled              : True
GivenName            : Sharepoint
Name                 : adfs
ObjectClass          : user
ObjectGUID           : 49b53bea-4bc4-4a68-b694-b806d9809e95
SamAccountName       : adfs
ServicePrincipalName : {adfsconnect/azure01.inlanefreight.local}
SID                  : S-1-5-21-3842939050-3880317879-2865463114-5244
Surname              : Admin
UserPrincipalName    :

DistinguishedName    : CN=BACKUPAGENT,OU=Service Accounts,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
Enabled              : True
GivenName            : Jessica
Name                 : BACKUPAGENT
ObjectClass          : user
ObjectGUID           : 2ec53e98-3a64-4706-be23-1d824ff61bed
SamAccountName       : backupagent
ServicePrincipalName : {backupjob/veam001.inlanefreight.local}
SID                  : S-1-5-21-3842939050-3880317879-2865463114-5220
Surname              : Systemmailbox 8Cc370d3-822A-4Ab8-A926-Bb94bd0641a9
UserPrincipalName    :

<SNIP>
```

Otra verificación interesante que podemos ejecutar utilizando el módulo ActiveDirectory sería verificar las relaciones de confianza del dominio utilizando el cmdlet [Get-ADTrust](https://docs.microsoft.com/en-us/powershell/module/activedirectory/get-adtrust?view=windowsserver2022-ps).

### Checking For Trust Relationships

```r
PS C:\htb> Get-ADTrust -Filter *

Direction               : BiDirectional
DisallowTransivity      : False
DistinguishedName       : CN=LOGISTICS.INLANEFREIGHT.LOCAL,CN=System,DC=INLANEFREIGHT,DC=LOCAL
ForestTransitive        : False
IntraForest             : True
IsTreeParent            : False
IsTreeRoot              : False
Name                    : LOGISTICS.INLANEFREIGHT.LOCAL
ObjectClass             : trustedDomain
ObjectGUID              : f48a1169-2e58-42c1-ba32-a6ccb10057ec
SelectiveAuthentication : False
SIDFilteringForestAware : False
SIDFilteringQuarantined : False
Source                  : DC=INLANEFREIGHT,DC=LOCAL
Target                  : LOGISTICS.INLANEFREIGHT.LOCAL
TGTDelegation           : False
TrustAttributes         : 32
TrustedPolicy           :
TrustingPolicy          :
TrustType               : Uplevel
UplevelOnly             : False
UsesAESKeys             : False
UsesRC4Encryption       : False

Direction               : BiDirectional
DisallowTransivity      : False
DistinguishedName       : CN=FREIGHTLOGISTICS.LOCAL,CN=System,DC=INLANEFREIGHT,DC=LOCAL
ForestTransitive        : True
IntraForest             : False
IsTreeParent            : False
IsTreeRoot              : False
Name                    : FREIGHTLOGISTICS.LOCAL
ObjectClass             : trustedDomain
ObjectGUID              : 1597717f-89b7-49b8-9cd9-0801d52475ca
SelectiveAuthentication : False
SIDFilteringForestAware : False
SIDFilteringQuarantined : False
Source                  : DC=INLANEFREIGHT,DC=LOCAL
Target                  : FREIGHTLOGISTICS.LOCAL
TGTDelegation           : False
TrustAttributes         : 8
TrustedPolicy           :
TrustingPolicy          :
TrustType               : Uplevel
UplevelOnly             : False
UsesAESKeys             : False
UsesRC4Encryption       : False  
```

Este cmdlet imprimirá cualquier relación de confianza que tenga el dominio. Podemos determinar si son confianzas dentro de nuestro bosque o con dominios en otros bosques, el tipo de confianza, la dirección de la confianza y el nombre del dominio con el que se tiene la relación. Esto será útil más adelante cuando busquemos aprovechar las relaciones de confianza de hijo a padre y atacar a través de confianzas de bosque. A continuación, podemos recopilar información sobre grupos de AD utilizando el cmdlet [Get-ADGroup](https://docs.microsoft.com/en-us/powershell/module/activedirectory/get-adgroup?view=windowsserver2022-ps).

### Group Enumeration

```r
PS C:\htb> Get-ADGroup -Filter * | select name

name
----
Administrators
Users
Guests
Print Operators
Backup Operators
Replicator
Remote Desktop Users
Network Configuration Operators
Performance Monitor Users
Performance Log Users
Distributed COM Users
IIS_IUSRS
Cryptographic Operators
Event Log Readers
Certificate Service DCOM Access
RDS Remote Access Servers
RDS Endpoint Servers
RDS Management Servers
Hyper-V Administrators
Access Control Assistance Operators
Remote Management Users
Storage Replica Administrators
Domain Computers
Domain Controllers
Schema Admins
Enterprise Admins
Cert Publishers
Domain Admins

<SNIP>
```

Podemos tomar los resultados y alimentar nombres interesantes de nuevo en el cmdlet para obtener información más detallada sobre un grupo en particular de la siguiente manera:

### Detailed Group Info

```r
PS C:\htb> Get-ADGroup -Identity "Backup Operators"

DistinguishedName : CN=Backup Operators,CN=Builtin,DC=INLANEFREIGHT,DC=LOCAL
GroupCategory     : Security
GroupScope        : DomainLocal
Name              : Backup Operators
ObjectClass       : group
ObjectGUID        : 6276d85d-9c39-4b7c-8449-cad37e8abc38
SamAccountName    : Backup Operators
SID               : S-1-5-32-551
```

Ahora que sabemos más sobre el grupo, obtengamos una lista de miembros utilizando el cmdlet [Get-ADGroupMember](https://docs.microsoft.com/en-us/powershell/module/activedirectory/get-adgroupmember?view=windowsserver2022-ps).

### Group Membership

```r
PS C:\htb> Get-ADGroupMember -Identity "Backup Operators"

distinguishedName : CN=BACKUPAGENT,OU=Service Accounts,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
name              : BACKUPAGENT
objectClass       : user
objectGUID        : 2ec53e98-3a64-4706-be23-1d824ff61bed
SamAccountName    : backupagent
SID               : S-1-5-21-3842939050-3880317879-2865463114-5220
```

Podemos ver que una cuenta, `backupagent`, pertenece a este grupo. Vale la pena señalar esto porque si podemos tomar el control de esta cuenta de servicio a través de algún ataque, podríamos usar su membresía en el grupo de Backup Operators para tomar el control del dominio. Podemos realizar este proceso para los otros grupos para comprender completamente la configuración de membresía del dominio. Intente repetir el proceso con algunos grupos diferentes. Verá que este proceso puede ser tedioso y nos quedaremos con una enorme cantidad de datos para analizar. Debemos saber cómo hacer esto con herramientas integradas como el módulo ActiveDirectory PowerShell, pero veremos más adelante en esta sección cuán rápido puede acelerar este proceso BloodHound y hacer que nuestros resultados sean mucho más precisos y organizados.

Utilizar el módulo ActiveDirectory en un host puede ser una forma más sigilosa de realizar acciones que dejar caer una herramienta en un host o cargarla en la memoria e intentar usarla. De esta manera, nuestras acciones podrían potencialmente mezclarse más. A continuación, revisaremos la herramienta PowerView, que tiene muchas características para simplificar la enumeración y profundizar en el dominio.

---

## PowerView

[PowerView](https://github.com/PowerShellMafia/PowerSploit/tree/master/Recon) es una herramienta escrita en PowerShell para ayudarnos a obtener conocimiento situacional dentro de un entorno de AD. Al igual que BloodHound, proporciona una manera de identificar dónde están los usuarios conectados en una red, enumerar información del dominio como usuarios, computadoras, grupos, ACLS, confianzas, buscar recursos compartidos de archivos y contraseñas, realizar Kerberoasting y más. Es una herramienta altamente versátil que puede proporcionarnos una gran visión de la postura de seguridad del dominio de nuestro cliente. Requiere más trabajo manual para determinar configuraciones incorrectas y relaciones dentro del dominio que BloodHound, pero cuando se usa correctamente, puede ayudarnos a identificar configuraciones incorrectas sutiles.

Examinemos algunas de las capacidades de PowerView y veamos qué datos devuelve. La tabla a continuación describe algunas de las funciones más útiles que ofrece PowerView.

Claro, aquí tienes la tabla arreglada para markdown:

| **Command**                 | **Description**                                                                                                  |
|-----------------------------|------------------------------------------------------------------------------------------------------------------|
| `Export-PowerViewCSV`       | Anexar resultados a un archivo CSV                                                                               |
| `ConvertTo-SID`             | Convertir un nombre de usuario o grupo a su valor SID                                                            |
| `Get-DomainSPNTicket`       | Solicita el ticket Kerberos para una cuenta SPN especificada                                                     |
| **Domain/LDAP Functions:**  |                                                                                                                  |
| `Get-Domain`                | Devuelve el objeto AD para el dominio actual (o especificado)                                                    |
| `Get-DomainController`      | Devuelve una lista de los controladores de dominio para el dominio especificado                                  |
| `Get-DomainUser`            | Devuelve todos los usuarios o objetos de usuarios específicos en AD                                              |
| `Get-DomainComputer`        | Devuelve todas las computadoras u objetos de computadora específicos en AD                                       |
| `Get-DomainGroup`           | Devuelve todos los grupos u objetos de grupo específicos en AD                                                   |
| `Get-DomainOU`              | Busca todos los objetos OU o específicos en AD                                                                   |
| `Find-InterestingDomainAcl` | Encuentra ACLs de objetos en el dominio con derechos de modificación establecidos en objetos no integrados       |
| `Get-DomainGroupMember`     | Devuelve los miembros de un grupo de dominio específico                                                          |
| `Get-DomainFileServer`      | Devuelve una lista de servidores que probablemente funcionen como servidores de archivos                         |
| `Get-DomainDFSShare`        | Devuelve una lista de todos los sistemas de archivos distribuidos para el dominio actual (o especificado)        |
| **GPO Functions:**          |                                                                                                                  |
| `Get-DomainGPO`             | Devuelve todos los GPOs u objetos GPO específicos en AD                                                          |
| `Get-DomainPolicy`          | Devuelve la política de dominio predeterminada o la política del controlador de dominio para el dominio actual   |
| **Computer Enumeration Functions:** |                                                                                                            |
| `Get-NetLocalGroup`         | Enumera los grupos locales en la máquina local o remota                                                          |
| `Get-NetLocalGroupMember`   | Enumera los miembros de un grupo local específico                                                                |
| `Get-NetShare`              | Devuelve recursos compartidos abiertos en la máquina local (o remota)                                            |
| `Get-NetSession`            | Devuelve información de sesión para la máquina local (o remota)                                                  |
| `Test-AdminAccess`          | Prueba si el usuario actual tiene acceso administrativo a la máquina local (o remota)                            |
| **Threaded 'Meta'-Functions:** |                                                                                                               |
| `Find-DomainUserLocation`   | Encuentra máquinas donde los usuarios específicos están conectados                                               |
| `Find-DomainShare`          | Encuentra recursos compartidos accesibles en máquinas del dominio                                                |
| `Find-InterestingDomainShareFile` | Busca archivos que coincidan con criterios específicos en recursos compartidos legibles en el dominio       |
| `Find-LocalAdminAccess`     | Encuentra máquinas en el dominio local donde el usuario actual tiene acceso de administrador local               |
| **Domain Trust Functions:** |                                                                                                                  |
| `Get-DomainTrust`           | Devuelve relaciones de confianza de dominio para el dominio actual o un dominio especificado                     |
| `Get-ForestTrust`           | Devuelve todas las relaciones de confianza de bosque para el bosque actual o un bosque especificado              |
| `Get-DomainForeignUser`     | Enumera usuarios que están en grupos fuera del dominio del usuario                                               |
| `Get-DomainForeignGroupMember` | Enumera grupos con usuarios fuera del dominio del grupo y devuelve cada miembro extranjero                     |
| `Get-DomainTrustMapping`    | Enumera todas las relaciones de confianza para el dominio actual y cualquier otro visto.                         |

Esta tabla no es exhaustiva para lo que ofrece PowerView, pero incluye muchas de las funciones que utilizaremos repetidamente. Para más información sobre PowerView, consulte el [Active Directory PowerView module](https://academy.hackthebox.com/course/preview/active-directory-powerview). A continuación, experimentaremos con algunas de ellas.

Primero está la función [Get-DomainUser](https://powersploit.readthedocs.io/en/latest/Recon/Get-DomainUser/). Esto nos proporcionará información sobre todos los usuarios o usuarios específicos que especifiquemos. A continuación, utilizaremos para obtener información sobre un usuario específico, `mmorgan`.

### Domain User Information

```r
PS C:\htb> Get-DomainUser -Identity mmorgan -Domain inlanefreight.local | Select-Object -Property name,samaccountname,description,memberof,whencreated,pwdlastset,lastlogontimestamp,accountexpires,admincount,userprincipalname,serviceprincipalname,useraccountcontrol

name                 : Matthew Morgan
samaccountname       : mmorgan
description          :
memberof             : {CN=VPN Users,OU=Security Groups,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL, CN=Shared Calendar
                       Read,OU=Security Groups,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL, CN=Printer Access,OU=Security
                       Groups,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL, CN=File Share H Drive,OU=Security
                       Groups,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL...}
whencreated          : 10/27/2021 5:37:06 PM
pwdlastset           : 11/18/2021 10:02:57 AM
lastlogontimestamp   : 2/27/2022 6:34:25 PM
accountexpires       : NEVER
admincount           : 1
userprincipalname    : mmorgan@inlanefreight.local
serviceprincipalname :
mail                 :
useraccountcontrol   : NORMAL_ACCOUNT, DONT_EXPIRE_PASSWORD, DONT_REQ_PREAUTH
```

Vimos información básica de usuarios con PowerView. Ahora enumeremos información sobre grupos de dominio. Podemos utilizar la función [Get-DomainGroupMember](https://powersploit.readthedocs.io/en/latest/Recon/Get-DomainGroupMember/) para recuperar información específica del grupo. Agregar el interruptor `-Recurse` le dice a PowerView que si encuentra algún grupo que sea parte del grupo objetivo (membresía de grupo anidado) enumere los miembros de esos grupos. Por ejemplo, la salida a continuación muestra que el grupo `Secadmins` es parte del grupo `Domain Admins` a través de la membresía de grupo anidado. En este caso, podremos ver a todos los miembros de ese grupo que heredan derechos de administrador de dominio a través de su membresía en el grupo.

### Recursive Group Membership

```r
PS C:\htb>  Get-DomainGroupMember -Identity "Domain Admins" -Recurse

GroupDomain             : INLANEFREIGHT.LOCAL
GroupName               : Domain Admins
GroupDistinguishedName  : CN=Domain Admins,CN=Users,DC=INLANEFREIGHT,DC=LOCAL
MemberDomain            : INLANEFREIGHT.LOCAL
MemberName              : svc_qualys
MemberDistinguishedName : CN=svc_qualys,OU=Service Accounts,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
MemberObjectClass       : user
MemberSID               : S-1-5-21-3842939050-3880317879-2865463114-5613

GroupDomain             : INLANEFREIGHT.LOCAL
GroupName               : Domain Admins
GroupDistinguishedName  : CN=Domain Admins,CN=Users,DC=INLANEFREIGHT,DC=LOCAL
MemberDomain            : INLANEFREIGHT.LOCAL
MemberName              : sp-admin
MemberDistinguishedName : CN=Sharepoint Admin,OU=Service Accounts,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
MemberObjectClass       : user
MemberSID               : S-1-5-21-3842939050-3880317879-2865463114-5228

GroupDomain             : INLANEFREIGHT.LOCAL
GroupName               : Secadmins
GroupDistinguishedName  : CN=Secadmins,OU=Security Groups,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
MemberDomain            : INLANEFREIGHT.LOCAL
MemberName              : spong1990
MemberDistinguishedName : CN=Maggie
                          Jablonski,OU=Operations,OU=Logistics-HK,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
MemberObjectClass       : user
MemberSID               : S-1-5-21-3842939050-3880317879-2865463114-1965

<SNIP>  
```

Arriba realizamos una búsqueda recursiva en el grupo `Domain Admins` para enumerar sus miembros. Ahora sabemos a quién apuntar para una posible elevación de privilegios. Al igual que con el módulo AD PowerShell, también podemos enumerar mapeos de confianza de dominio.

### Trust Enumeration

```r
PS C:\htb> Get-DomainTrustMapping

SourceName      : INLANEFREIGHT.LOCAL
TargetName      : LOGISTICS.INLANEFREIGHT.LOCAL
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : WITHIN_FOREST
TrustDirection  : Bidirectional
WhenCreated     : 11/1/2021 6:20:22 PM
WhenChanged     : 2/26/2022 11:55:55 PM

SourceName      : INLANEFREIGHT.LOCAL
TargetName      : FREIGHTLOGISTICS.LOCAL
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : FOREST_TRANSITIVE
TrustDirection  : Bidirectional
WhenCreated     : 11/1/2021 8:07:09 PM
WhenChanged     : 2/27/2022 12:02:39 AM

SourceName      : LOGISTICS.INLANEFREIGHT.LOCAL
TargetName      : INLANEFREIGHT.LOCAL
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : WITHIN_FOREST
TrustDirection  : Bidirectional
WhenCreated     : 11/1/2021 6:20:22 PM
WhenChanged     : 2/26/2022 11:55:55 PM 
```

Podemos utilizar la función [Test-AdminAccess](https://powersploit.readthedocs.io/en/latest/Recon/Test-AdminAccess/) para probar el acceso de administrador local en la máquina actual o en una remota.

### Testing for Local Admin Access

```r
PS C:\htb> Test-AdminAccess -ComputerName ACADEMY-EA-MS01

ComputerName    IsAdmin
------------    -------
ACADEMY-EA-MS01    True 
```

Arriba, determinamos que el usuario que estamos utilizando actualmente es administrador en el host ACADEMY-EA-MS01. Podemos realizar la misma función para cada host para ver dónde tenemos acceso administrativo. Veremos más adelante qué tan bien BloodHound realiza este tipo de verificación. Ahora podemos buscar usuarios con el atributo SPN configurado, lo que indica que la cuenta puede estar sujeta a un ataque de Kerberoasting.

### Finding Users With SPN Set

```r
PS C:\htb> Get-DomainUser -SPN -Properties samaccountname,ServicePrincipalName

serviceprincipalname                          samaccountname
--------------------                          --------------
adfsconnect/azure01.inlanefreight.local       adfs
backupjob/veam001.inlanefreight.local         backupagent
d0wngrade/kerberoast.inlanefreight.local      d0wngrade
kadmin/changepw                               krbtgt
MSSQLSvc/DEV-PRE-SQL.inlanefreight.local:1433 sqldev
MSSQLSvc/SPSJDB.inlanefreight.local:1433      sqlprod
MSSQLSvc/SQL-CL01-01inlanefreight.local:49351 sqlqa
sts/inlanefreight.local                       solarwindsmonitor
testspn/kerberoast.inlanefreight.local        testspn
testspn2/kerberoast.inlanefreight.local       testspn2
```

Pruebe algunas funciones más de la herramienta hasta que se sienta cómodo usándola. Veremos PowerView bastantes veces más a medida que avancemos en este módulo.

---

## SharpView

PowerView es parte del ahora obsoleto kit de herramientas ofensivo PowerSploit PowerShell. La herramienta ha estado recibiendo actualizaciones por BC-Security como parte de su marco [Empire 4](https://github.com/BC-SECURITY/Empire/blob/master/empire/server/data/module_source/situational_awareness/network/powerview.ps1). Empire 4 es el fork de BC-Security del proyecto original de Empire y se mantiene activamente a partir de abril de 2022. Mostramos ejemplos a lo largo de este módulo utilizando la versión de desarrollo de PowerView porque es una excelente herramienta para el reconocimiento en un entorno de Active Directory, y aún es extremadamente poderosa y útil en redes modernas de AD aunque la versión original no se mantenga. La versión de BC-SECURITY de [PowerView](https://github.com/BC-SECURITY/Empire/blob/master/empire/server/data/module_source/situational_awareness/network/powerview.ps1) tiene algunas nuevas funciones como `Get-NetGmsa`, utilizada para buscar [Group Managed Service Accounts](https://docs.microsoft.com/en-us/windows-server/security/group-managed-service-accounts/group-managed-service-accounts-overview), que está fuera del alcance de este módulo. Vale la pena jugar con ambas versiones para ver las sutiles diferencias entre la versión antigua y la mantenida actualmente.

Otra herramienta que vale la pena experimentar es SharpView, un port de .NET de PowerView. Muchas de las mismas funciones compatibles con PowerView se pueden utilizar con SharpView. Podemos escribir un nombre de método con `-Help` para obtener una lista de argumentos.

```r
PS C:\htb> .\SharpView.exe Get-DomainUser -Help

Get_DomainUser -Identity <String[]> -DistinguishedName <String[]> -SamAccountName <String[]> -Name <String[]> -MemberDistinguishedName <String[]> -MemberName <String[]> -SPN <Boolean> -AdminCount <Boolean> -AllowDelegation <Boolean> -DisallowDelegation <Boolean> -TrustedToAuth <Boolean> -PreauthNotRequired <Boolean> -KerberosPreauthNotRequired <Boolean> -NoPreauth <Boolean> -Domain <String> -LDAPFilter <String> -Filter <String> -Properties <String[]> -SearchBase <String> -ADSPath <String> -Server <String> -DomainController <String> -SearchScope <SearchScope> -ResultPageSize <Int32> -ServerTimeLimit <Nullable`1> -SecurityMasks <Nullable`1> -Tombstone <Boolean> -FindOne <Boolean> -ReturnOne <Boolean> -Credential <NetworkCredential> -Raw <Boolean> -UACFilter <UACEnum> 
```

Aquí podemos usar SharpView para enumerar información sobre un usuario específico, como el usuario `forend`, que controlamos.

```r
PS C:\htb> .\SharpView.exe Get-DomainUser -Identity forend

[Get-DomainSearcher] search base: LDAP://ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL/DC=INLANEFREIGHT,DC=LOCAL
[Get-DomainUser] filter string: (&(samAccountType=805306368)(|(samAccountName=forend)))
objectsid                      : {S-1-5-21-3842939050-3880317879-2865463114-5614}
samaccounttype                 : USER_OBJECT
objectguid                     : 53264142-082a-4cb8-8714-8158b4974f3b
useraccountcontrol             : NORMAL_ACCOUNT
accountexpires                 : 12/31/1600 4:00:00 PM
lastlogon                      : 4/18/2022 1:01:21 PM
lastlogontimestamp             : 4/9/2022 1:33:21 PM
pwdlastset                     : 2/28/2022 12:03:45 PM
lastlogoff                     : 12/31/1600 4:00:00 PM
badPasswordTime                : 4/5/2022 7:09:07 AM
name                           : forend
distinguishedname              : CN=forend,OU=IT Admins,OU=IT,OU=HQ-NYC,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
whencreated                    : 2/28/2022 8:03:45 PM
whenchanged                    : 4/9/2022 8:33:21 PM
samaccountname                 : forend
memberof                       : {CN=VPN Users,OU=Security Groups,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL, CN=Shared Calendar Read,OU=Security Groups,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL, CN=Printer Access,OU=Security Groups,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL, CN=File Share H Drive,OU=Security Groups,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL, CN=File Share G Drive,OU=Security Groups,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL}
cn                             : {forend}
objectclass                    : {top, person, organizationalPerson, user}
badpwdcount                    : 0
countrycode                    : 0
usnchanged                     : 3259288
logoncount                     : 26618
primarygroupid                 : 513
objectcategory                 : CN=Person,CN=Schema,CN=Configuration,DC=INLANEFREIGHT,DC=LOCAL
dscorepropagationdata          : {3/24/2022 3:58:07 PM, 3/24/2022 3:57:44 PM, 3/24/2022 3:52:58 PM, 3/24/2022 3:49:31 PM, 7/14/1601 10:36:49 PM}
usncreated                     : 3054181
instancetype                   : 4
codepage                       : 0
```

Experimente con SharpView en el host MS01 y recree tantos ejemplos de PowerView como sea posible. Aunque la evasión no está dentro del alcance de este módulo, SharpView puede ser útil cuando un cliente ha endurecido contra el uso de PowerShell o necesitamos evitar usar PowerShell.

---

## Shares

Los recursos compartidos permiten a los usuarios en un dominio acceder rápidamente a información relevante para sus roles diarios y compartir contenido con su organización. Cuando se configuran correctamente, los recursos compartidos de dominio requerirán que un usuario esté unido al dominio y sea necesario autenticarse al acceder al sistema. También se establecerán permisos para garantizar que los usuarios solo puedan acceder y ver lo que es necesario para su rol diario. Los recursos compartidos excesivamente permisivos pueden causar la divulgación accidental de información sensible, especialmente aquellos que contienen datos médicos, legales, de personal, de RRHH, etc. En un ataque, obtener control sobre un usuario de dominio estándar que puede acceder a recursos compartidos como los recursos compartidos de TI/infraestructura podría conducir a la divulgación de datos sensibles como archivos de configuración o archivos de autenticación como claves SSH o contraseñas almacenadas de manera insegura. Queremos identificar cualquier problema como estos para garantizar que el cliente no esté exponiendo ningún dato a usuarios que no necesitan acceder a él para sus trabajos diarios y que están cumpliendo con cualquier requisito legal/regulatorio al que estén sujetos (HIPAA, PCI, etc.). Podemos usar PowerView para buscar recursos compartidos y luego ayudarnos a examinarlos o usar varios comandos manuales para buscar cadenas comunes como archivos con `pass` en el nombre. Este puede ser un proceso tedioso, y podemos perder cosas, especialmente en grandes entornos. Ahora, tomemos un tiempo para explorar la herramienta `Snaffler` y ver cómo puede ayudarnos a identificar estos problemas de manera más precisa y eficiente.

---

## Snaffler

[Snaffler](https://github.com/SnaffCon/Snaffler) es una herramienta que puede ayudarnos a adquirir credenciales u otros datos sensibles en un entorno de Active Directory. Snaffler funciona obteniendo una lista de hosts dentro del dominio y luego enumerando esos hosts en busca de recursos compartidos y directorios legibles. Una vez hecho esto, itera a través de cualquier directorio legible por nuestro usuario y busca archivos que puedan mejorar nuestra posición dentro de la evaluación. Snaffler requiere que se ejecute desde un host unido al dominio o en un contexto de usuario de dominio.

Para ejecutar Snaffler, podemos usar el siguiente comando:

### Snaffler Execution

```r
Snaffler.exe -s -d inlanefreight.local -o snaffler.log -v data
```

El `-s` le indica que imprima los resultados en la consola para nosotros, el `-d` especifica el dominio en el que buscar, y el `-o` le dice a Snaffler que escriba los resultados en un archivo de registro. La opción `-v` es el nivel de verbosidad. Típicamente `data` es lo mejor ya que solo muestra resultados en la pantalla, por lo que es más fácil comenzar a revisar las ejecuciones de la herramienta. Snaffler puede producir una cantidad considerable de datos, por lo que generalmente deberíamos volcar a archivo y dejar que se ejecute y luego volver más tarde. También puede

 ser útil proporcionar la salida en bruto de Snaffler a los clientes como datos complementarios durante una prueba de penetración, ya que puede ayudarles a centrarse en recursos compartidos de alto valor que deben bloquearse primero.

### Snaffler in Action

```r
PS C:\htb> .\Snaffler.exe  -d INLANEFREIGHT.LOCAL -s -v data

 .::::::.:::.    :::.  :::.    .-:::::'.-:::::':::    .,:::::: :::::::..
;;;`    ``;;;;,  `;;;  ;;`;;   ;;;'''' ;;;'''' ;;;    ;;;;'''' ;;;;``;;;;
'[==/[[[[, [[[[[. '[[ ,[[ '[[, [[[,,== [[[,,== [[[     [[cccc   [[[,/[[['
  '''    $ $$$ 'Y$c$$c$$$cc$$$c`$$$'`` `$$$'`` $$'     $$""   $$$$$$c
 88b    dP 888    Y88 888   888,888     888   o88oo,.__888oo,__ 888b '88bo,
  'YMmMY'  MMM     YM YMM   ''` 'MM,    'MM,  ''''YUMMM''''YUMMMMMMM   'W'
                         by l0ss and Sh3r4 - github.com/SnaffCon/Snaffler

2022-03-31 12:16:54 -07:00 [Share] {Black}(\\ACADEMY-EA-MS01.INLANEFREIGHT.LOCAL\ADMIN$)
2022-03-31 12:16:54 -07:00 [Share] {Black}(\\ACADEMY-EA-MS01.INLANEFREIGHT.LOCAL\C$)
2022-03-31 12:16:54 -07:00 [Share] {Green}(\\ACADEMY-EA-MX01.INLANEFREIGHT.LOCAL\address)
2022-03-31 12:16:54 -07:00 [Share] {Green}(\\ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL\Department Shares)
2022-03-31 12:16:54 -07:00 [Share] {Green}(\\ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL\User Shares)
2022-03-31 12:16:54 -07:00 [Share] {Green}(\\ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL\ZZZ_archive)
2022-03-31 12:17:18 -07:00 [Share] {Green}(\\ACADEMY-EA-CA01.INLANEFREIGHT.LOCAL\CertEnroll)
2022-03-31 12:17:19 -07:00 [File] {Black}<KeepExtExactBlack|R|^\.kdb$|289B|3/31/2022 12:09:22 PM>(\\ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL\Department Shares\IT\Infosec\GroupBackup.kdb) .kdb
2022-03-31 12:17:19 -07:00 [File] {Red}<KeepExtExactRed|R|^\.key$|299B|3/31/2022 12:05:33 PM>(\\ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL\Department Shares\IT\Infosec\ShowReset.key) .key
2022-03-31 12:17:19 -07:00 [Share] {Green}(\\ACADEMY-EA-FILE.INLANEFREIGHT.LOCAL\UpdateServicesPackages)
2022-03-31 12:17:19 -07:00 [File] {Black}<KeepExtExactBlack|R|^\.kwallet$|302B|3/31/2022 12:04:45 PM>(\\ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL\Department Shares\IT\Infosec\WriteUse.kwallet) .kwallet
2022-03-31 12:17:19 -07:00 [File] {Red}<KeepExtExactRed|R|^\.key$|298B|3/31/2022 12:05:10 PM>(\\ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL\Department Shares\IT\Infosec\ProtectStep.key) .key
2022-03-31 12:17:19 -07:00 [File] {Black}<KeepExtExactBlack|R|^\.ppk$|275B|3/31/2022 12:04:40 PM>(\\ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL\Department Shares\IT\Infosec\StopTrace.ppk) .ppk
2022-03-31 12:17:19 -07:00 [File] {Red}<KeepExtExactRed|R|^\.key$|301B|3/31/2022 12:09:17 PM>(\\ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL\Department Shares\IT\Infosec\WaitClear.key) .key
2022-03-31 12:17:19 -07:00 [File] {Red}<KeepExtExactRed|R|^\.sqldump$|312B|3/31/2022 12:05:30 PM>(\\ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL\Department Shares\IT\Development\DenyRedo.sqldump) .sqldump
2022-03-31 12:17:19 -07:00 [File] {Red}<KeepExtExactRed|R|^\.sqldump$|310B|3/31/2022 12:05:02 PM>(\\ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL\Department Shares\IT\Development\AddPublish.sqldump) .sqldump
2022-03-31 12:17:19 -07:00 [Share] {Green}(\\ACADEMY-EA-FILE.INLANEFREIGHT.LOCAL\WsusContent)
2022-03-31 12:17:19 -07:00 [File] {Red}<KeepExtExactRed|R|^\.keychain$|295B|3/31/2022 12:08:42 PM>(\\ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL\Department Shares\IT\Infosec\SetStep.keychain) .keychain
2022-03-31 12:17:19 -07:00 [File] {Black}<KeepExtExactBlack|R|^\.tblk$|279B|3/31/2022 12:05:25 PM>(\\ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL\Department Shares\IT\Development\FindConnect.tblk) .tblk
2022-03-31 12:17:19 -07:00 [File] {Black}<KeepExtExactBlack|R|^\.psafe3$|301B|3/31/2022 12:09:33 PM>(\\ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL\Department Shares\IT\Development\GetUpdate.psafe3) .psafe3
2022-03-31 12:17:19 -07:00 [File] {Red}<KeepExtExactRed|R|^\.keypair$|278B|3/31/2022 12:09:09 PM>(\\ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL\Department Shares\IT\Infosec\UnprotectConvertTo.keypair) .keypair
2022-03-31 12:17:19 -07:00 [File] {Black}<KeepExtExactBlack|R|^\.tblk$|280B|3/31/2022 12:05:17 PM>(\\ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL\Department Shares\IT\Development\ExportJoin.tblk) .tblk
2022-03-31 12:17:19 -07:00 [File] {Red}<KeepExtExactRed|R|^\.mdf$|305B|3/31/2022 12:09:27 PM>(\\ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL\Department Shares\IT\Development\FormatShow.mdf) .mdf
2022-03-31 12:17:19 -07:00 [File] {Red}<KeepExtExactRed|R|^\.mdf$|299B|3/31/2022 12:09:14 PM>(\\ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL\Department Shares\IT\Development\LockConfirm.mdf) .mdf

<SNIP>
```

Podemos encontrar contraseñas, claves SSH, archivos de configuración u otros datos que se pueden usar para ampliar nuestro acceso. Snaffler codifica en colores la salida para nosotros y nos proporciona un resumen de los tipos de archivos encontrados en los recursos compartidos.

Ahora que tenemos una gran cantidad de datos sobre el dominio INLANEFREIGHT.LOCAL (¡y notas claras y salida de archivos de registro!), necesitamos una forma de correlacionarlos y visualizarlos. Vamos a profundizar en `BloodHound` y ver qué tan poderosa puede ser esta herramienta durante cualquier evaluación de seguridad enfocada en AD.

---

### BloodHound

Como se discutió en la sección anterior, `Bloodhound` es una herramienta excepcional de código abierto que puede identificar rutas de ataque dentro de un entorno de AD analizando las relaciones entre objetos. Tanto los pentesters como los blue teamers pueden beneficiarse de aprender a usar BloodHound para visualizar las relaciones en el dominio. Cuando se usa correctamente y junto con consultas personalizadas de Cipher, BloodHound puede encontrar fallos de alto impacto pero difíciles de descubrir que han estado presentes en el dominio durante años.

Primero, debemos autenticarnos como usuario de dominio desde un host de ataque en Windows posicionado dentro de la red (pero no unido al dominio) o transferir la herramienta a un host unido al dominio. Hay muchas maneras de lograr esto cubiertas en el módulo [File Transfer](https://academy.hackthebox.com/course/preview/file-transfers). Para nuestros propósitos, trabajaremos con SharpHound.exe ya en el host de ataque, pero vale la pena experimentar con transferir la herramienta al host de ataque desde Pwnbox o nuestra propia VM utilizando métodos como un servidor HTTP de Python, smbserver.py de Impacket, etc.

Si ejecutamos SharpHound con la opción `--help`, podemos ver las opciones disponibles para nosotros.

### SharpHound in Action

```r
PS C:\htb>  .\SharpHound.exe --help

SharpHound 1.0.3
Copyright (C) 2022 SpecterOps

  -c, --collectionmethods    (Default: Default) Collection Methods: Container, Group, LocalGroup, GPOLocalGroup,
                             Session, LoggedOn, ObjectProps, ACL, ComputerOnly, Trusts, Default, RDP, DCOM, DCOnly

  -d, --domain               Specify domain to enumerate

  -s, --searchforest         (Default: false) Search all available domains in the forest

  --stealth                  Stealth Collection (Prefer DCOnly whenever possible!)

  -f                         Add an LDAP filter to the pregenerated filter.

  --distinguishedname        Base DistinguishedName to start the LDAP search at

  --computerfile             Path to file containing computer names to enumerate
  
  <SNIP>
```

Comenzaremos ejecutando el recolector SharpHound.exe desde el host de ataque MS01.

```r
PS C:\htb> .\SharpHound.exe -c All --zipfilename ILFREIGHT

2022-04-18T13:58:22.1163680-07:00|INFORMATION|Resolved Collection Methods: Group, LocalAdmin, GPOLocalGroup, Session, LoggedOn, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote
2022-04-18T13:58:22.1163680-07:00|INFORMATION|Initializing SharpHound at 1:58 PM on 4/18/2022
2022-04-18T13:58:22.6788709-07:00|INFORMATION|Flags: Group, LocalAdmin, GPOLocalGroup, Session, LoggedOn, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote
2022-04-18T13:58:23.0851206-07:00|INFORMATION|Beginning LDAP search for INLANEFREIGHT.LOCAL
2022-04-18T13:58:53.9132950-07:00|INFORMATION|Status: 0 objects finished (+0 0)/s -- Using 67 MB RAM
2022-04-18T13:59:15.7882419-07:00|INFORMATION|Producer has finished, closing LDAP channel
2022-04-18T13:59:16.1788930-07:00|INFORMATION|LDAP channel closed, waiting for consumers
2022-04-18T13:59:23.9288698-07:00|INFORMATION|Status: 3793 objects finished (+3793 63.21667)/s -- Using 112 MB RAM
2022-04-18T13:59:45.4132561-07:00|INFORMATION|Consumers finished, closing output channel
Closing writers
2022-04-18T13:59:45.4601086-07:00|INFORMATION|Output channel closed, waiting for output task to complete
2022-04-18T13:59:45.8663528-07:00|INFORMATION|Status: 3809 objects finished (+16 46.45122)/s -- Using 110 MB RAM
2022-04-18T13:59:45.8663528-07:00|INFORMATION|Enumeration finished in 00:01:22.7919186
2022-04-18T13:59:46.3663660-07:00|INFORMATION|SharpHound Enumeration Completed at 1:59 PM on 4/18/2022! Happy Graphing
```

A continuación, podemos exfiltrar el conjunto de datos a nuestra propia VM o ingerirlo en la herramienta GUI de BloodHound en MS01. Podemos hacerlo en MS01 escribiendo `bloodhound` en una consola CMD o PowerShell. Las credenciales deberían estar guardadas, pero ingrese `neo4j: HTB_@cademy_stdnt!` si aparece un aviso. A continuación, haga clic en el botón `Upload Data` en el lado derecho, seleccione el archivo zip recién generado y haga clic en `Open`. Aparecerá una ventana de `Upload Progress`. Una vez que todos los archivos .json muestren 100% completados, haga clic en la X en la parte superior de esa ventana.

Podemos comenzar escribiendo `domain:` en la barra de búsqueda en la parte superior izquierda y eligiendo `INLANEFREIGHT.LOCAL` en los resultados. Tómese un momento para navegar por la pestaña de información del nodo. Como podemos ver, esta sería una empresa bastante grande con más de 550 hosts para atacar y confianzas con dos otros dominios.

Ahora, revisemos algunas consultas preconstruidas en la pestaña `Analysis`. La consulta `Find Computers with Unsupported Operating Systems` es excelente para encontrar sistemas operativos obsoletos y no compatibles que ejecutan software heredado. Estos sistemas son relativamente comunes de encontrar dentro de redes empresariales (especialmente en entornos más antiguos), ya que a menudo ejecutan algún producto que no puede ser actualizado o reemplazado por el momento. Mantener estos hosts puede ahorrar dinero, pero también pueden agregar vulnerabilidades innecesarias a la red. Los hosts más antiguos pueden ser susceptibles a vulnerabilidades de ejecución remota de código más antiguas como [MS08-067](https://support.microsoft.com/en-us/topic/ms08-067-vulnerability-in-server-service-could-allow-remote-code-execution-ac7878fc-be69-7143-472d-2507a179cd15). Si encontramos estos hosts más antiguos durante una evaluación, debemos tener cuidado antes de atacarlos (o incluso verificar con nuestro cliente) ya que pueden ser frágiles y ejecutar una aplicación o servicio crítico. Podemos aconsejar a nuestro cliente que segmente estos hosts del resto de la red tanto como sea posible si aún no pueden eliminarlos, pero también recomendar que comiencen a elaborar un plan para desmantelarlos y reemplazarlos.

Esta consulta muestra dos hosts, uno ejecutando Windows 7 y otro ejecutando Windows Server 2008 (ambos de los cuales no están "activos" en nuestro laboratorio). A veces veremos hosts que ya no están encendidos pero que aún aparecen como registros en AD. Siempre debemos validar si están "activos" o no antes de hacer recomendaciones en nuestros informes. Podemos redactar un hallazgo de alto riesgo para sistemas operativos heredados o una recomendación de mejores prácticas para limpiar registros antiguos en AD.

### Unsupported Operating Systems

![text](https://academy.hackthebox.com/storage/modules/143/unsupported.png)

A menudo veremos usuarios con derechos de administrador local en su host (quizás temporalmente para instalar un software, y los derechos nunca se eliminaron), o ocupan un rol lo suficientemente alto en la organización como para exigir estos derechos (ya sea que los necesiten o no). Otras veces veremos derechos de administrador local excesivos otorgados en toda la organización, como múltiples grupos en el departamento de TI con administrador local sobre grupos de servidores o incluso el grupo de Domain Users con administrador local sobre uno o más hosts. Esto puede beneficiarnos si tomamos el control de una cuenta de usuario con estos derechos sobre una o más máquinas. Podemos ejecutar la consulta `Find Computers where Domain Users are Local Admin` para ver rápidamente si hay algún host donde todos los usuarios tienen derechos de administrador local. Si este es el caso, cualquier cuenta que controlemos puede usarse típicamente para acceder al/los host(s) en cuestión, y podemos recuperar credenciales de la memoria o encontrar otros datos sensibles.

### Local Admins

![text](https://academy.hackthebox.com/storage/modules/143/local-admin.png)

Esto es solo una instantánea de las consultas útiles que podemos ejecutar. A medida que continuemos con este módulo, verá varias más que pueden ser útiles para encontrar otras debilidades en el dominio. Para un estudio más profundo sobre BloodHound, consulte el módulo [Active Directory Bloodhound](https://academy.hackthebox.com/course/preview/active-directory-bloodhound). Tómese un tiempo y pruebe cada una de las consultas en la pestaña `Analysis` para familiarizarse más con la herramienta. También vale la pena experimentar con [consultas Cypher personalizadas](https://hausec.com/2019/09/09/bloodhound-cypher-cheatsheet/) pegándolas en el cuadro `Raw Query` en la parte inferior de la pantalla.

Tenga en cuenta que a medida que avanzamos en el compromiso, debemos documentar cada archivo que se transfiera hacia y desde los hosts en el dominio y dónde se colocaron en el disco. Esto es una buena práctica si tenemos que desacoplar nuestras acciones con el cliente. Además, dependiendo del alcance del compromiso, queremos asegurarnos de cubrir nuestras huellas y limpiar cualquier cosa que pongamos en el entorno al concluir el compromiso.

---

Tenemos una gran imagen del diseño, fortalezas y debilidades del dominio. Tenemos credenciales para varios usuarios y hemos enumerado una gran cantidad de información como usuarios, grupos, computadoras, GPOs, ACLs, derechos de administrador local, derechos de acceso (RDP, WinRM, etc.), cuentas configuradas con nombres principales de servicio (SPNs), y más. Tenemos notas detalladas y una gran cantidad de salida y hemos experimentado con muchas herramientas diferentes para practicar la enumeración de AD con y sin credenciales desde hosts de ataque en Linux y Windows. ¿Qué pasa si estamos restringidos con el shell que tenemos o no tenemos la capacidad de importar herramientas? Nuestro cliente puede pedirnos que realicemos todo el trabajo desde un host gestionado dentro de su red sin acceso a Internet y sin forma de cargar nuestras herramientas. Podríamos aterrizar en un host como `SYSTEM` después de un ataque exitoso, pero estar en una posición donde es muy difícil o no es posible cargar herramientas. ¿Qué hacemos entonces? En la siguiente sección, veremos cómo realizar acciones mientras "Living Off The Land".
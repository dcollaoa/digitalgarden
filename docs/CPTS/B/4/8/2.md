Vamos a sumergirnos en la enumeración de ACLs utilizando PowerView y repasando algunas representaciones gráficas usando BloodHound. Luego cubriremos algunos escenarios/ataques donde los ACEs que enumeramos pueden ser aprovechados para obtener más acceso en el entorno interno.

---

## Enumerating ACLs with PowerView

Podemos usar PowerView para enumerar ACLs, pero la tarea de revisar _todos_ los resultados será extremadamente laboriosa y probablemente inexacta. Por ejemplo, si ejecutamos la función `Find-InterestingDomainAcl` recibiremos una cantidad masiva de información que necesitaríamos revisar para entenderla:

### Using Find-InterestingDomainAcl

```r
PS C:\htb> Find-InterestingDomainAcl

ObjectDN                : DC=INLANEFREIGHT,DC=LOCAL
AceQualifier            : AccessAllowed
ActiveDirectoryRights   : ExtendedRight
ObjectAceType           : ab721a53-1e2f-11d0-9819-00aa0040529b
AceFlags                : ContainerInherit
AceType                 : AccessAllowedObject
InheritanceFlags        : ContainerInherit
SecurityIdentifier      : S-1-5-21-3842939050-3880317879-2865463114-5189
IdentityReferenceName   : Exchange Windows Permissions
IdentityReferenceDomain : INLANEFREIGHT.LOCAL
IdentityReferenceDN     : CN=Exchange Windows Permissions,OU=Microsoft Exchange Security 
                          Groups,DC=INLANEFREIGHT,DC=LOCAL
IdentityReferenceClass  : group

ObjectDN                : DC=INLANEFREIGHT,DC=LOCAL
AceQualifier            : AccessAllowed
ActiveDirectoryRights   : ExtendedRight
ObjectAceType           : 00299570-246d-11d0-a768-00aa006e0529
AceFlags                : ContainerInherit
AceType                 : AccessAllowedObject
InheritanceFlags        : ContainerInherit
SecurityIdentifier      : S-1-5-21-3842939050-3880317879-2865463114-5189
IdentityReferenceName   : Exchange Windows Permissions
IdentityReferenceDomain : INLANEFREIGHT.LOCAL
IdentityReferenceDN     : CN=Exchange Windows Permissions,OU=Microsoft Exchange Security 
                          Groups,DC=INLANEFREIGHT,DC=LOCAL
IdentityReferenceClass  : group

<SNIP>
```

Si intentamos revisar todos estos datos durante una evaluación con tiempo limitado, probablemente nunca los revisaremos todos o encontraremos algo interesante antes de que termine la evaluación. Ahora bien, hay una manera de usar una herramienta como PowerView de manera más efectiva: realizando una enumeración dirigida comenzando con un usuario sobre el cual tenemos control. Centrémonos en el usuario `wley`, que obtuvimos después de resolver la última pregunta en la sección `LLMNR/NBT-NS Poisoning - from Linux`. Vamos a profundizar y ver si este usuario tiene algún derecho ACL interesante que podríamos aprovechar. Primero necesitamos obtener el SID de nuestro usuario objetivo para buscar de manera efectiva.

```r
PS C:\htb> Import-Module .\PowerView.ps1
PS C:\htb> $sid = Convert-NameToSid wley
```

Luego podemos usar la función `Get-DomainObjectACL` para realizar nuestra búsqueda dirigida. En el siguiente ejemplo, estamos usando esta función para encontrar todos los objetos de dominio sobre los cuales nuestro usuario tiene derechos, mapeando el SID del usuario usando la variable `$sid` a la propiedad `SecurityIdentifier` que nos dice _quién_ tiene el derecho dado sobre un objeto. Una cosa importante a tener en cuenta es que si buscamos sin la flag `ResolveGUIDs`, veremos resultados como los siguientes, donde el derecho `ExtendedRight` no nos da una imagen clara de qué entrada ACE tiene el usuario `wley` sobre `damundsen`. Esto se debe a que la propiedad `ObjectAceType` está devolviendo un valor GUID que no es legible por humanos.

Nota que este comando tardará un rato en ejecutarse, especialmente en un entorno grande. Puede tardar de 1 a 2 minutos en obtener un resultado en nuestro laboratorio.

### Using Get-DomainObjectACL

```r
PS C:\htb> Get-DomainObjectACL -Identity * | ? {$_.SecurityIdentifier -eq $sid}

ObjectDN               : CN=Dana Amundsen,OU=DevOps,OU=IT,OU=HQ-NYC,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
ObjectSID              : S-1-5-21-3842939050-3880317879-2865463114-1176
ActiveDirectoryRights  : ExtendedRight
ObjectAceFlags         : ObjectAceTypePresent
ObjectAceType          : 00299570-246d-11d0-a768-00aa006e0529
InheritedObjectAceType : 00000000-0000-0000-0000-000000000000
BinaryLength           : 56
AceQualifier           : AccessAllowed
IsCallback             : False
OpaqueLength           : 0
AccessMask             : 256
SecurityIdentifier     : S-1-5-21-3842939050-3880317879-2865463114-1181
AceType                : AccessAllowedObject
AceFlags               : ContainerInherit
IsInherited            : False
InheritanceFlags       : ContainerInherit
PropagationFlags       : None
AuditFlags             : None
```

Podríamos buscar en Google el valor GUID `00299570-246d-11d0-a768-00aa006e0529` y descubrir [esta](https://docs.microsoft.com/en-us/windows/win32/adschema/r-user-force-change-password) página que muestra que el usuario tiene el derecho de forzar el cambio de contraseña de otro usuario. Alternativamente, podríamos hacer una búsqueda inversa usando PowerShell para mapear el nombre del derecho al valor GUID.

### Performing a Reverse Search & Mapping to a GUID Value

```r
PS C:\htb> $guid= "00299570-246d-11d0-a768-00aa006e0529"
PS C:\htb> Get-ADObject -SearchBase "CN=Extended-Rights,$((Get-ADRootDSE).ConfigurationNamingContext)" -Filter {ObjectClass -like 'ControlAccessRight'} -Properties * |Select Name,DisplayName,DistinguishedName,rightsGuid| ?{$_.rightsGuid -eq $guid} | fl

Name              : User-Force-Change-Password
DisplayName       : Reset Password
DistinguishedName : CN=User-Force-Change-Password,CN=Extended-Rights,CN=Configuration,DC=INLANEFREIGHT,DC=LOCAL
rightsGuid        : 00299570-246d-11d0-a768-00aa006e0529
```

Esto nos dio nuestra respuesta, pero sería muy ineficiente durante una evaluación. PowerView tiene la flag `ResolveGUIDs`, que hace esto mismo por nosotros. Observa cómo cambia la salida cuando incluimos esta flag para mostrar el formato legible por humanos de la propiedad `ObjectAceType` como `User-Force-Change-Password`.

### Using the -ResolveGUIDs Flag

```r
PS C:\htb> Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $sid} 

AceQualifier           : AccessAllowed
ObjectDN               : CN=Dana Amundsen,OU=DevOps,OU=IT,OU=HQ-NYC,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
ActiveDirectoryRights  : ExtendedRight
ObjectAceType          : User-Force-Change-Password
ObjectSID              : S-1-5-21-3842939050-3880317879-2865463114-1176
InheritanceFlags       : ContainerInherit
BinaryLength           : 56
AceType                : AccessAllowedObject
ObjectAceFlags         : ObjectAceTypePresent
IsCallback             : False
PropagationFlags       : None
SecurityIdentifier     : S-1-5-21-3842939050-3880317879-2865463114-1181
AccessMask             : 256
AuditFlags             : None
IsInherited            : False
AceFlags               : ContainerInherit
InheritedObjectAceType : All
OpaqueLength           : 0
```

`¿Por qué repasamos este ejemplo cuando podríamos haber buscado usando ResolveGUIDs primero?`

Es esencial que entendamos qué están haciendo nuestras herramientas y tengamos métodos alternativos en nuestro conjunto de herramientas en caso de que una herramienta falle o sea bloqueada. Antes de continuar, echemos un vistazo rápido a cómo podríamos hacer esto usando los cmdlets [Get-Acl](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.security/get-acl?view=powershell-7.2) y [Get-ADUser](https://docs.microsoft.com/en-us/powershell/module/activedirectory/get-aduser?view=windowsserver2022-ps) que podríamos encontrar disponibles en un sistema cliente. Saber cómo realizar este tipo de búsqueda sin usar una herramienta como PowerView es muy beneficioso y podría diferenciarnos de nuestros compañeros. Podríamos usar este conocimiento para lograr resultados cuando un cliente nos haga trabajar desde uno de sus sistemas, y estemos restringidos a las herramientas disponibles en el sistema sin la capacidad de traer ninguna de nuestras propias herramientas.

Este ejemplo no es muy eficiente, y el comando puede tardar mucho tiempo en ejecutarse, especialmente en un entorno grande. Tomará mucho más tiempo que el comando equivalente usando PowerView. En este comando, primero hemos hecho una lista de todos los usuarios de dominio con el siguiente comando:

### Creating a List of Domain Users

```r
PS C:\htb> Get-ADUser -Filter * | Select-Object -ExpandProperty SamAccountName > ad_users.txt
```

Luego leemos cada línea del archivo usando un bucle `foreach`, y usamos el cmdlet `Get-Acl` para recuperar información de ACL para cada usuario de dominio alimentando cada línea del archivo `ad_users.txt` al cmdlet `Get-ADUser`. Luego seleccionamos solo la propiedad `Access`, que nos dará información sobre los derechos de acceso. Finalmente, establecemos la propiedad `IdentityReference` en el usuario que controlamos (o buscando ver qué derechos tienen), en nuestro caso, `wley`.

### A Useful foreach Loop

```r
PS C:\htb> foreach($line in [System.IO.File]::ReadLines("C:\Users\htb-student\Desktop\ad_users.txt")) {get-acl  "AD:\$(Get-ADUser $line)" | Select-Object Path -ExpandProperty Access | Where-Object {$_.IdentityReference -match 'INLANEFREIGHT\\wley'}}

Path                  : Microsoft.ActiveDirectory.Management.dll\ActiveDirectory:://RootDSE/CN=Dana 
                        Amundsen,OU=DevOps,OU=IT,OU=HQ-NYC,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
ActiveDirectoryRights : ExtendedRight
InheritanceType       : All
ObjectType            : 00299570-246d-11d0-a768-00aa006e0529
InheritedObjectType   : 00000000-0000-0000-0000-000000000000
ObjectFlags           : ObjectAceTypePresent
AccessControlType     : Allow
IdentityReference     : INLANEFREIGHT\wley
IsInherited           : False
InheritanceFlags      : ContainerInherit
PropagationFlags      : None
```

Una vez que tengamos estos datos, podríamos seguir los mismos métodos mostrados anteriormente para convertir el GUID a un formato legible por humanos para entender qué derechos tenemos sobre el usuario objetivo.

Entonces, para recapitular, comenzamos con el usuario `wley` y ahora tenemos control sobre el usuario `damundsen` a través del derecho extendido `User-Force-Change-Password`. Usemos Powerview para buscar dónde, si en algún lugar, el control sobre la cuenta `damundsen` podría llevarnos.

### Further Enumeration of Rights Using damundsen

```r
PS C:\htb> $sid2 = Convert-NameToSid damundsen
PS C:\htb> Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $sid2} -Verbose

AceType               : AccessAllowed
ObjectDN              : CN=Help Desk Level 1,OU=Security Groups,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
ActiveDirectoryRights : ListChildren, ReadProperty, GenericWrite
OpaqueLength          : 0
ObjectSID             : S-1-5-21-3842939050-3880317879-2865463114-4022
InheritanceFlags      : ContainerInherit
BinaryLength          : 36
IsInherited           : False
IsCallback            : False
PropagationFlags      : None
SecurityIdentifier    : S-1-5-21-3842939050-3880317879-2865463114-1176
AccessMask            : 131132
AuditFlags            : None
AceFlags              : ContainerInherit
AceQualifier          : AccessAllowed
```

Ahora podemos ver que nuestro usuario `damundsen` tiene privilegios `GenericWrite` sobre el grupo `Help Desk Level 1`. Esto significa, entre otras cosas, que podemos agregar cualquier usuario (o nosotros mismos) a este grupo y heredar cualquier derecho que este grupo tenga aplicado. Una búsqueda de derechos conferidos a este grupo no devuelve nada interesante.

Veamos si este grupo está anidado en otros grupos, recordando que la membresía de grupo anidada significará que cualquier usuario en el grupo A heredará todos los derechos de cualquier grupo en el que el grupo A esté anidado (miembro de). Una búsqueda rápida nos muestra que el grupo `Help Desk Level 1` está anidado en el grupo `Information Technology`, lo que significa que podemos obtener cualquier derecho que el grupo `Information Technology` otorgue a sus miembros si solo nos agregamos al grupo `Help Desk Level 1` donde nuestro usuario `damundsen` tiene privilegios `GenericWrite`.

### Investigating the Help Desk Level 1 Group with Get-DomainGroup

```r
PS C:\htb> Get-DomainGroup -Identity "Help Desk Level 1" | select memberof

memberof                                                                      
--------                                                                      
CN=Information Technology,OU=Security Groups,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
```

¡Esto es mucho para digerir! Recapitulemos dónde estamos:

- Tenemos control sobre el usuario `wley` cuyo hash recuperamos anteriormente en el módulo (evaluación) usando Responder y crackeamos offline usando Hashcat para revelar el valor de la contraseña en texto claro.
- Enumeramos los objetos sobre los cuales el usuario `wley` tiene control y encontramos que podíamos forzar el cambio de contraseña del usuario `damundsen`.
- Desde aquí, encontramos que el usuario `damundsen` puede agregar un miembro al grupo `Help Desk Level 1` usando privilegios `GenericWrite`.
- El grupo `Help Desk Level 1` está anidado en el grupo `Information Technology`, que otorga a los miembros de ese grupo cualquier derecho proporcionado al grupo `Information Technology`.

Ahora veamos alrededor y veamos si los miembros del grupo `Information Technology` pueden hacer algo interesante. Una vez más, al hacer nuestra búsqueda usando `Get-DomainObjectACL` vemos que los miembros del grupo `Information Technology` tienen derechos `GenericAll` sobre el usuario `adunn`, lo que significa que podríamos:

- Modificar la membresía de grupo
- Forzar el cambio de una contraseña
- Realizar un ataque Kerberoasting dirigido y tratar de crackear la contraseña del usuario si es débil

### Investigating the Information Technology Group

```r
PS C:\htb> $itgroupsid = Convert-NameToSid "Information Technology"
PS C:\htb> Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $itgroupsid} -Verbose

AceType               : AccessAllowed
ObjectDN              : CN=Angela Dunn,OU=Server Admin,OU=IT,OU=HQ-NYC,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
ActiveDirectoryRights : GenericAll
OpaqueLength          : 0
ObjectSID             : S-1-5-21-3842939050-3880317879-2865463114-1164
InheritanceFlags      : ContainerInherit
BinaryLength          : 36
IsInherited           : False
IsCallback            : False
PropagationFlags      : None
SecurityIdentifier    : S-1-5-21-3842939050-3880317879-2865463114-4016
AccessMask            : 983551
AuditFlags            : None
AceFlags              : ContainerInherit
AceQualifier          : AccessAllowed

```

Finalmente, veamos si el usuario `adunn` tiene algún tipo de acceso interesante que podamos aprovechar para acercarnos a nuestro objetivo.

### Looking for Interesting Access

```r
PS C:\htb> $adunnsid = Convert-NameToSid adunn 
PS C:\htb> Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $adunnsid} -Verbose

AceQualifier           : AccessAllowed
ObjectDN               : DC=INLANEFREIGHT,DC=LOCAL
ActiveDirectoryRights  : ExtendedRight
ObjectAceType          : DS-Replication-Get-Changes-In-Filtered-Set
ObjectSID              : S-1-5-21-3842939050-3880317879-2865463114
InheritanceFlags       : ContainerInherit
BinaryLength           : 56
AceType                : AccessAllowedObject
ObjectAceFlags         : ObjectAceTypePresent
IsCallback             : False
PropagationFlags       : None
SecurityIdentifier     : S-1-5-21-3842939050-3880317879-2865463114-1164
AccessMask             : 256
AuditFlags             : None
IsInherited            : False
AceFlags               : ContainerInherit
InheritedObjectAceType : All
OpaqueLength           : 0

AceQualifier           : AccessAllowed
ObjectDN               : DC=INLANEFREIGHT,DC=LOCAL
ActiveDirectoryRights  : ExtendedRight
ObjectAceType          : DS-Replication-Get-Changes
ObjectSID              : S-1-5-21-3842939050-3880317879-2865463114
InheritanceFlags       : ContainerInherit
BinaryLength           : 56
AceType                : AccessAllowedObject
ObjectAceFlags         : ObjectAceTypePresent
IsCallback             : False
PropagationFlags       : None
SecurityIdentifier     : S-1-5-21-3842939050-3880317879-2865463114-1164
AccessMask             : 256
AuditFlags             : None
IsInherited            : False
AceFlags               : ContainerInherit
InheritedObjectAceType : All
OpaqueLength           : 0

<SNIP>
```

La salida anterior muestra que nuestro usuario `adunn` tiene derechos `DS-Replication-Get-Changes` y `DS-Replication-Get-Changes-In-Filtered-Set` sobre el objeto de dominio. Esto significa que este usuario puede ser aprovechado para realizar un ataque DCSync. Cubriremos este ataque en profundidad en la sección `DCSync`.

---

## Enumerating ACLs with BloodHound

Ahora que hemos enumerado la ruta de ataque utilizando métodos más manuales como PowerView y cmdlets integrados de PowerShell, veamos cómo habría sido mucho más fácil identificar esto utilizando la poderosa herramienta BloodHound. Tomemos los datos que recopilamos anteriormente con el ingestor SharpHound y carguémoslos en BloodHound. Luego, podemos establecer el usuario `wley` como nuestro nodo de inicio, seleccionar la pestaña `Node Info` y desplazarnos hacia abajo hasta `Outbound Control Rights`. Esta opción nos mostrará los objetos sobre los cuales tenemos control directamente, a través de la membresía de grupo, y la cantidad de objetos que nuestro usuario podría llevarnos a

 controlar a través de rutas de ataque ACL bajo `Transitive Object Control`. Si hacemos clic en el `1` junto a `First Degree Object Control`, veremos el primer conjunto de derechos que enumeramos, `ForceChangePassword` sobre el usuario `damundsen`.

### Viewing Node Info through BloodHound

![image](https://academy.hackthebox.com/storage/modules/143/wley_damundsen.png)

Si hacemos clic derecho en la línea entre los dos objetos, aparecerá un menú. Si seleccionamos `Help`, se nos presentará ayuda sobre cómo abusar de este ACE, incluyendo:

- Más información sobre el derecho específico, herramientas y comandos que se pueden usar para llevar a cabo este ataque.
- Consideraciones de Seguridad Operacional (Opsec).
- Referencias externas.

Exploraremos este menú más adelante.

### Investigating ForceChangePassword Further

![image](https://academy.hackthebox.com/storage/modules/143/help_edge.png)

Si hacemos clic en el `16` junto a `Transitive Object Control`, veremos toda la ruta que enumeramos meticulosamente anteriormente. Desde aquí, podríamos aprovechar los menús de ayuda para cada borde para encontrar formas de llevar a cabo cada ataque.

### Viewing Potential Attack Paths through BloodHound

![image](https://academy.hackthebox.com/storage/modules/143/wley_path.png)

Finalmente, podemos usar las consultas pre-construidas en BloodHound para confirmar que el usuario `adunn` tiene derechos de DCSync.

### Viewing Pre-Build queries through BloodHound

![image](https://academy.hackthebox.com/storage/modules/143/adunn_dcsync.png)

Ahora hemos enumerado estas rutas de ataque de múltiples maneras. El siguiente paso será realizar esta cadena de ataque de principio a fin. ¡Vamos a profundizar!
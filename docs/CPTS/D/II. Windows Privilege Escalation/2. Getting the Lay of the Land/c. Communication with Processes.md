## Access Tokens

En Windows, los [access tokens](https://docs.microsoft.com/en-us/windows/win32/secauthz/access-tokens) se utilizan para describir el contexto de seguridad (atributos o reglas de seguridad) de un proceso o hilo. El token incluye información sobre la identidad y privilegios de la cuenta de usuario relacionados con un proceso o hilo específico. Cuando un usuario se autentica en un sistema, su contraseña se verifica contra una base de datos de seguridad, y si se autentica correctamente, se le asignará un access token. Cada vez que un usuario interactúa con un proceso, se presentará una copia de este token para determinar su nivel de privilegio.

---

## Enumerating Network Services

La forma más común en que las personas interactúan con los procesos es a través de un socket de red (DNS, HTTP, SMB, etc.). El comando [netstat](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/netstat) mostrará las conexiones TCP y UDP activas, lo que nos dará una mejor idea de qué servicios están escuchando en qué puerto(s) tanto localmente como accesibles desde el exterior. Podemos encontrar un servicio vulnerable accesible solo al localhost (cuando se ha iniciado sesión en el host) que podemos explotar para escalar privilegios.

### Display Active Network Connections

```r
C:\htb> netstat -ano

Active Connections

  Proto  Local Address          Foreign Address        State           PID
  TCP    0.0.0.0:21             0.0.0.0:0              LISTENING       3812
  TCP    0.0.0.0:80             0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       836
  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:3389           0.0.0.0:0              LISTENING       936
  TCP    0.0.0.0:5985           0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:8080           0.0.0.0:0              LISTENING       5044
  TCP    0.0.0.0:47001          0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:49664          0.0.0.0:0              LISTENING       528
  TCP    0.0.0.0:49665          0.0.0.0:0              LISTENING       996
  TCP    0.0.0.0:49666          0.0.0.0:0              LISTENING       1260
  TCP    0.0.0.0:49668          0.0.0.0:0              LISTENING       2008
  TCP    0.0.0.0:49669          0.0.0.0:0              LISTENING       600
  TCP    0.0.0.0:49670          0.0.0.0:0              LISTENING       1888
  TCP    0.0.0.0:49674          0.0.0.0:0              LISTENING       616
  TCP    10.129.43.8:139        0.0.0.0:0              LISTENING       4
  TCP    10.129.43.8:3389       10.10.14.3:63191       ESTABLISHED     936
  TCP    10.129.43.8:49671      40.67.251.132:443      ESTABLISHED     1260
  TCP    10.129.43.8:49773      52.37.190.150:443      ESTABLISHED     2608
  TCP    10.129.43.8:51580      40.67.251.132:443      ESTABLISHED     3808
  TCP    10.129.43.8:54267      40.67.254.36:443       ESTABLISHED     3808
  TCP    10.129.43.8:54268      40.67.254.36:443       ESTABLISHED     1260
  TCP    10.129.43.8:54269      64.233.184.189:443     ESTABLISHED     2608
  TCP    10.129.43.8:54273      216.58.210.195:443     ESTABLISHED     2608
  TCP    127.0.0.1:14147        0.0.0.0:0              LISTENING       3812

<SNIP>

  TCP    192.168.20.56:139      0.0.0.0:0              LISTENING       4
  TCP    [::]:21                [::]:0                 LISTENING       3812
  TCP    [::]:80                [::]:0                 LISTENING       4
  TCP    [::]:135               [::]:0                 LISTENING       836
  TCP    [::]:445               [::]:0                 LISTENING       4
  TCP    [::]:3389              [::]:0                 LISTENING       936
  TCP    [::]:5985              [::]:0                 LISTENING       4
  TCP    [::]:8080              [::]:0                 LISTENING       5044
  TCP    [::]:47001             [::]:0                 LISTENING       4
  TCP    [::]:49664             [::]:0                 LISTENING       528
  TCP    [::]:49665             [::]:0                 LISTENING       996
  TCP    [::]:49666             [::]:0                 LISTENING       1260
  TCP    [::]:49668             [::]:0                 LISTENING       2008
  TCP    [::]:49669             [::]:0                 LISTENING       600
  TCP    [::]:49670             [::]:0                 LISTENING       1888
  TCP    [::]:49674             [::]:0                 LISTENING       616
  TCP    [::1]:14147            [::]:0                 LISTENING       3812
  UDP    0.0.0.0:123            *:*                                    1104
  UDP    0.0.0.0:500            *:*                                    1260
  UDP    0.0.0.0:3389           *:*                                    936

<SNIP>
```

Lo principal a buscar con Active Network Connections son las entradas que escuchan en direcciones de loopback (`127.0.0.1` y `::1`) que no están escuchando en la dirección IP (`10.129.43.8`) o broadcast (`0.0.0.0`, `::/0`). La razón de esto es que los sockets de red en localhost a menudo son inseguros debido a la creencia de que "no son accesibles desde la red". El que destaca de inmediato será el puerto `14147`, que se utiliza para la interfaz administrativa de FileZilla. Al conectarse a este puerto, puede ser posible extraer contraseñas FTP además de crear un FTP Share en c:\ como el usuario del servidor de FileZilla (potencialmente Administrador).

### More Examples

Uno de los mejores ejemplos de este tipo de escalada de privilegios es el `Splunk Universal Forwarder`, instalado en los endpoints para enviar logs a Splunk. La configuración predeterminada de Splunk no tenía ninguna autenticación en el software y permitía a cualquiera desplegar aplicaciones, lo que podría llevar a la ejecución de código. Nuevamente, la configuración predeterminada de Splunk era ejecutarlo como SYSTEM$ y no como un usuario de bajo privilegio. Para obtener más información, consulte [Splunk Universal Forwarder Hijacking](https://airman604.medium.com/splunk-universal-forwarder-hijacking-5899c3e0e6b2) y [SplunkWhisperer2](https://clement.notin.org/blog/2019/02/25/Splunk-Universal-Forwarder-Hijacking-2-SplunkWhisperer2/).

Otro vector de escalada de privilegios locales común pero pasado por alto es el `Erlang Port` (25672). Erlang es un lenguaje de programación diseñado en torno a la computación distribuida y tendrá un puerto de red que permite que otros nodos de Erlang se unan al clúster. El secreto para unirse a este clúster se llama cookie. Muchas aplicaciones que utilizan Erlang usarán una cookie débil (RabbitMQ utiliza `rabbit` por defecto) o colocarán la cookie en un archivo de configuración que no está bien protegido. Algunos ejemplos de aplicaciones Erlang son SolarWinds, RabbitMQ y CouchDB. Para más información, consulte el [blogpost de Erlang-arce de Mubix](https://malicious.link/post/2018/erlang-arce/).

---

## Named Pipes

La otra forma en que los procesos se comunican entre sí es a través de Named Pipes. Las pipes son esencialmente archivos almacenados en memoria que se borran después de ser leídos. Cobalt Strike utiliza Named Pipes para cada comando (excluyendo [BOF](https://www.cobaltstrike.com/help-beacon-object-files)). Esencialmente, el flujo de trabajo se ve así:

1. Beacon inicia una named pipe de \\.\pipe\msagent_12
2. Beacon inicia un nuevo proceso e inyecta un comando en ese proceso dirigiendo la salida a \\.\pipe\msagent_12
3. El servidor muestra lo que se escribió en \\.\pipe\msagent_12

Cobalt Strike hizo esto porque si el comando que se ejecutaba era detectado por un antivirus o se bloqueaba, no afectaría al beacon (proceso que ejecuta el comando). A menudo, los usuarios de Cobalt Strike cambiarán sus named pipes para hacerse pasar por otro programa. Uno de los ejemplos más comunes es mojo en lugar de msagent. Uno de mis hallazgos favoritos fue encontrar una named pipe que comenzaba con mojo, pero la computadora en sí no tenía Chrome instalado. Afortunadamente, resultó ser el red team interno de la empresa. Dice mucho cuando un consultor externo encuentra el red team, pero el blue team interno no lo hace.

### More on Named Pipes

Las pipes se utilizan para la comunicación entre dos aplicaciones o procesos utilizando memoria compartida. Hay dos tipos de pipes, [named pipes](https://docs.microsoft.com/en-us/windows/win32/ipc/named-pipes) y anonymous pipes. Un ejemplo de named pipe es \\.\PipeName\\ExampleNamedPipeServer. Los sistemas Windows usan una implementación cliente-servidor para la comunicación por pipes. En este tipo de implementación, el proceso que crea una named pipe es el servidor, y el proceso que se comunica con la named pipe es el cliente. Las named pipes pueden comunicarse usando half-duplex, o un canal unidireccional con el cliente solo pudiendo escribir datos al servidor, o duplex, que es un canal de comunicación bidireccional que permite al cliente escribir datos sobre la pipe, y al servidor responder con datos sobre esa pipe. Cada conexión activa a un servidor de named pipe resulta en la creación de una nueva named pipe. Todas comparten el mismo nombre de pipe pero se comunican usando un buffer de datos diferente.

Podemos usar la herramienta [PipeList](https://docs.microsoft.com/en-us/sysinternals/downloads/pipelist) de la Sysinternals Suite para enumerar instancias de named pipes.

### Listing Named Pipes with Pipelist

```r
C:\htb> pipelist.exe /accepteula

PipeList v1.02 - Lists open named pipes
Copyright (C) 2005-2016 Mark Russinovich
Sysinternals - www.sysinternals.com

Pipe Name                                    Instances       Max Instances
---------                                    ---------       -------------
InitShutdown                                      3               -1
lsass                                             4               -1
ntsvcs                                            3               -1
scerpc                                            3               -1
Winsock2\CatalogChangeListener-340-0              1                1
Winsock2\CatalogChangeListener-414-0              1                1
epmapper                                          3               -1
Winsock2\CatalogChangeListener-3ec-0              1                1
Winsock2\CatalogChangeListener-44c-0              1                1
LSM_API_service                                   3               -1
atsvc                                             3               -1
Winsock2\CatalogChangeListener-5e0-0              1                1
eventlog                                          3               -1
Winsock2\CatalogChangeListener-6a8-0              1                1
spoolss                                           3               -1
Winsock2\CatalogChangeListener-ec0-0              1                1
wkssvc                                            4               -1
trkwks                                            3               -1
vmware-usbarbpipe                                 5               -1
srvsvc                                            4               -1
ROUTER                                            3               -1
vmware-authdpipe                                  1                1

<SNIP>
```

Además, podemos usar PowerShell para listar named pipes usando `gci` (`Get-ChildItem`).

### Listing Named Pipes with PowerShell

```r
PS C:\htb>  gci \\.\pipe\


    Directory: \\.\pipe


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
------       12/31/1600   4:00 PM              3 InitShutdown
------       12/31/1600   4:00 PM              4 lsass
------       12/31/1600   4:00 PM              3 ntsvcs
------       12/31/1600   4:00 PM              3 scerpc


    Directory: \\.\pipe\Winsock2


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
------       12/31/1600   4:00 PM              1 Winsock2\CatalogChangeListener-34c-0


    Directory: \\.\pipe


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
------       12/31/1600   4:00 PM              3 epmapper

<SNIP>

```

Después de obtener una lista de named pipes, podemos usar [Accesschk](https://docs.microsoft.com/en-us/sysinternals/downloads/accesschk) para enumerar los permisos asignados a una named pipe específica revisando la Discretionary Access List (DACL), que nos muestra quién tiene permisos para modificar, escribir, leer o ejecutar un recurso. Veamos el proceso `LSASS`. También podemos revisar los DACLs de todas las named pipes usando el comando `.\accesschk.exe /accepteula \pipe\`.

### Reviewing LSASS Named Pipe Permissions

```r
C:\htb> accesschk.exe /accepteula \\.\Pipe\lsass -v

Accesschk v6.12 - Reports effective permissions for securable objects
Copyright (C) 2006-2017 Mark Russinovich
Sysinternals - www.sysinternals.com

\\.\Pipe\lsass
  Untrusted Mandatory Level [No-Write-Up]
  RW Everyone
        FILE_READ_ATTRIBUTES
        FILE_READ_DATA
        FILE_READ_EA
        FILE_WRITE_ATTRIBUTES
        FILE_WRITE_DATA
        FILE_WRITE_EA
        SYNCHRONIZE
        READ_CONTROL
  RW NT AUTHORITY\ANONYMOUS LOGON
        FILE_READ_ATTRIBUTES
        FILE_READ_DATA
        FILE_READ_EA
        FILE_WRITE_ATTRIBUTES
        FILE_WRITE_DATA
        FILE_WRITE_EA
        SYNCHRONIZE
        READ_CONTROL
  RW APPLICATION PACKAGE AUTHORITY\Your Windows credentials
        FILE_READ_ATTRIBUTES
        FILE_READ_DATA
        FILE_READ_EA
        FILE_WRITE_ATTRIBUTES
        FILE_WRITE_DATA
        FILE_WRITE_EA
        SYNCHRONIZE
        READ_CONTROL
  RW BUILTIN\Administrators
        FILE_ALL_ACCESS
```

En la salida anterior, podemos ver que solo los administradores tienen acceso completo al proceso LSASS, como era de esperar.

---

## Named Pipes Attack Example

Veamos un ejemplo de cómo aprovechar una named pipe expuesta para escalar privilegios. Este [WindscribeService Named Pipe Privilege Escalation](https://www.exploit-db.com/exploits/48021) es un gran ejemplo. Usando `accesschk` podemos buscar todas las named pipes que permiten acceso de escritura con un comando como `accesschk.exe -w \pipe\* -v` y notar que la named pipe `WindscribeService` permite `READ` y `WRITE` acceso al grupo `Everyone`, lo que significa todos los usuarios autenticados.

### Checking WindscribeService Named Pipe Permissions

Confirmando con `accesschk` vemos que el grupo Everyone efectivamente tiene `FILE_ALL_ACCESS` (Todos los derechos de acceso posibles) sobre la pipe.

```r
C:\htb> accesschk.exe -accepteula -w \pipe\WindscribeService -v

Accesschk v6.13 - Reports effective permissions for securable objects
Copyright ⌐ 2006-2020 Mark Russinovich
Sysinternals - www.sysinternals.com

\\.\Pipe\WindscribeService
  Medium Mandatory Level (Default) [No-Write-Up]
  RW Everyone
        FILE_ALL_ACCESS
```

A partir de aquí, podríamos aprovechar estos permisos laxos para escalar privilegios en el host a SYSTEM.
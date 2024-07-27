Credentials pueden abrir muchas puertas durante nuestras evaluaciones. Podemos encontrar credentials durante nuestra enumeración de escalada de privilegios que pueden llevarnos directamente a acceso de administrador local, darnos un punto de apoyo en el entorno del Active Directory domain, o incluso ser utilizados para escalar privilegios dentro del domain. Hay muchos lugares donde podemos encontrar credentials en un sistema, algunos más obvios que otros.

---

## Application Configuration Files

### Searching for Files

Contrario a las mejores prácticas, las aplicaciones a menudo almacenan passwords en archivos de configuración (config files) en texto claro. Supongamos que obtenemos ejecución de comandos en el contexto de una cuenta de usuario no privilegiada. En ese caso, podemos encontrar credentials para su cuenta de administrador o para otra cuenta local o de domain con privilegios. Podemos usar la utilidad [findstr](https://ss64.com/nt/findstr.html) para buscar esta información sensible.

```r
PS C:\htb> findstr /SIM /C:"password" *.txt *.ini *.cfg *.config *.xml
```

Información sensible de IIS como credentials puede estar almacenada en un archivo `web.config`. Para el sitio web predeterminado de IIS, esto podría estar ubicado en `C:\inetpub\wwwroot\web.config`, pero puede haber múltiples versiones de este archivo en diferentes ubicaciones, que podemos buscar de forma recursiva.

---

## Dictionary Files

### Chrome Dictionary Files

Otro caso interesante son los dictionary files. Por ejemplo, información sensible como passwords puede ser ingresada en un cliente de correo electrónico o una aplicación basada en navegador, que subraya cualquier palabra que no reconoce. El usuario puede agregar estas palabras a su diccionario para evitar la distracción del subrayado rojo.

```r
PS C:\htb> gc 'C:\Users\htb-student\AppData\Local\Google\Chrome\User Data\Default\Custom Dictionary.txt' | Select-String password

Password1234!
```

---

## Unattended Installation Files

Los archivos de instalación desatendida (Unattended installation files) pueden definir configuraciones de auto-logon o cuentas adicionales que se crearán como parte de la instalación. Los passwords en el `unattend.xml` se almacenan en texto claro (plaintext) o codificados en base64.

### Unattend.xml

```r
<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend">
    <settings pass="specialize">
        <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <AutoLogon>
                <Password>
                    <Value>local_4dmin_p@ss</Value>
                    <PlainText>true</PlainText>
                </Password>
                <Enabled>true</Enabled>
                <LogonCount>2</LogonCount>
                <Username>Administrator</Username>
            </AutoLogon>
            <ComputerName>*</ComputerName>
        </component>
    </settings>
```

Aunque estos archivos deben ser eliminados automáticamente como parte de la instalación, los sysadmins pueden haber creado copias del archivo en otras carpetas durante el desarrollo de la imagen y el archivo de respuestas.

---

## PowerShell History File

### Command to

A partir de Powershell 5.0 en Windows 10, PowerShell almacena el historial de comandos en el archivo:

- `C:\Users\<username>\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt`.

### Confirming PowerShell History Save Path

Como se ve en el PDF (útil) de Windows Commands, publicado por Microsoft [aquí](https://download.microsoft.com/download/5/8/9/58911986-D4AD-4695-BF63-F734CD4DF8F2/ws-commands.pdf), hay muchos comandos que pueden pasar credentials en la línea de comandos. Podemos ver en el ejemplo a continuación que el usuario especificó credentials administrativas locales para consultar el Application Event Log usando [wevutil](https://ss64.com/nt/wevtutil.html).

```r
PS C:\htb> (Get-PSReadLineOption).HistorySavePath

C:\Users\htb-student\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```

### Reading PowerShell History File

Una vez que conocemos la ubicación del archivo (la ruta predeterminada está arriba), podemos intentar leer su contenido usando `gc`.

```r
PS C:\htb> gc (Get-PSReadLineOption).HistorySavePath

dir
cd Temp
md backups
cp c:\inetpub\wwwroot\* .\backups\
Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://www.powershellgallery.com/packages/MrAToolbox/1.0.1/Content/Get-IISSite.ps1'))
. .\Get-IISsite.ps1
Get-IISsite -Server WEB02 -web "Default Web Site"
wevtutil qe Application "/q:*[Application [(EventID=3005)]]" /f:text /rd:true /u:WEB02\administrator /p:5erv3rAdmin! /r:WEB02
```

También podemos usar este comando de una sola línea para recuperar el contenido de todos los archivos de historial de PowerShell a los que podamos acceder como nuestro usuario actual. Esto también puede ser extremadamente útil como un paso posterior a la explotación. Siempre debemos volver a verificar estos archivos una vez que tengamos acceso de administrador local si nuestro acceso previo no nos permitía leer los archivos para algunos usuarios. Este comando asume que se está utilizando la ruta de guardado predeterminada.

```r
PS C:\htb> foreach($user in ((ls C:\users).fullname)){cat "$user\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt" -ErrorAction SilentlyContinue}

dir
cd Temp
md backups
cp c:\inetpub\wwwroot\* .\backups\
Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://www.powershellgallery.com/packages/MrAToolbox/1.0.1/Content/Get-IISSite.ps1'))
. .\Get-IISsite.ps1
Get-IISsite -Server WEB02 -web "Default Web Site"
wevtutil qe Application "/q:*[Application [(EventID=3005)]]" /f:text /rd:true /u:WEB02\administrator /p:5erv3rAdmin! /r:WEB02
```

---

## PowerShell Credentials

Las PowerShell credentials son a menudo utilizadas para tareas de scripting y automatización como una forma conveniente de almacenar credentials cifradas. Las credentials están protegidas usando [DPAPI](https://en.wikipedia.org/wiki/Data_Protection_API), lo que generalmente significa que solo pueden ser descifradas por el mismo usuario en la misma computadora en la que fueron creadas.

Por ejemplo, el siguiente script `Connect-VC.ps1`, que un sysadmin ha creado para conectarse fácilmente a un servidor vCenter.

```r
# Connect-VC.ps1
# Get-Credential | Export-Clixml -Path 'C:\scripts\pass.xml'
$encryptedPassword = Import-Clixml -Path 'C:\scripts\pass.xml'
$decryptedPassword = $encryptedPassword.GetNetworkCredential().Password
Connect-VIServer -Server 'VC-01' -User 'bob_adm' -Password $decryptedPassword
```

### Decrypting PowerShell Credentials

Si hemos obtenido ejecución de comandos en el contexto de este usuario o podemos abusar de DPAPI, entonces podemos recuperar las credentials en texto claro desde `encrypted.xml`. El siguiente ejemplo asume lo primero.

```r
PS C:\htb> $credential = Import-Clixml -Path 'C:\scripts\pass.xml'
PS C:\htb> $credential.GetNetworkCredential().username

bob


PS C:\htb> $credential.GetNetworkCredential().password

Str0ng3ncryptedP@ss!
```

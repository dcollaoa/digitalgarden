[Netsh](https://docs.microsoft.com/en-us/windows-server/networking/technologies/netsh/netsh-contexts) es una herramienta de línea de comandos de Windows que puede ayudar con la configuración de red de un sistema Windows en particular. Aquí hay solo algunas de las tareas relacionadas con la red que podemos usar `Netsh` para:

- `Finding routes`
- `Viewing the firewall configuration`
- `Adding proxies`
- `Creating port forwarding rules`

Tomemos un ejemplo del siguiente escenario donde nuestro host comprometido es una estación de trabajo de un administrador de TI basada en Windows 10 (`10.129.15.150`, `172.16.5.25`). Ten en cuenta que es posible en un engagement que podamos obtener acceso a la estación de trabajo de un empleado a través de métodos como la ingeniería social y el phishing. Esto nos permitiría pivotar aún más desde dentro de la red en la que se encuentra la estación de trabajo.

![](https://academy.hackthebox.com/storage/modules/158/88.png)

Podemos usar `netsh.exe` para reenviar todos los datos recibidos en un puerto específico (digamos 8080) a un host remoto en un puerto remoto. Esto se puede realizar usando el siguiente comando.

### Using Netsh.exe to Port Forward

```r
C:\Windows\system32> netsh.exe interface portproxy add v4tov4 listenport=8080 listenaddress=10.129.15.150 connectport=3389 connectaddress=172.16.5.25
```

### Verifying Port Forward

```r
C:\Windows\system32> netsh.exe interface portproxy show v4tov4

Listen on ipv4:             Connect to ipv4:

Address         Port        Address         Port
--------------- ----------  --------------- ----------
10.129.42.198   8080        172.16.5.25     3389
```

Después de configurar el `portproxy` en nuestro host de pivot basado en Windows, intentaremos conectarnos al puerto 8080 de este host desde nuestro host de ataque usando xfreerdp. Una vez que se envíe una solicitud desde nuestro host de ataque, el host de Windows enrutará nuestro tráfico de acuerdo con la configuración del proxy configurada por netsh.exe.

### Connecting to the Internal Host through the Port Forward

![](https://academy.hackthebox.com/storage/modules/158/netsh_pivot.png)

---

**Note**: Cuando inicies tu objetivo, te pedimos que esperes de 3 a 5 minutos hasta que todo el laboratorio con todas las configuraciones esté configurado para que la conexión a tu objetivo funcione sin problemas.
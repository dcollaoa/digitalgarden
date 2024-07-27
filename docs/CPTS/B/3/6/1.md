Durante una evaluación, puede haber momentos en los que estemos limitados a una red de Windows y no podamos usar SSH para pivotar. En estos casos, tendríamos que usar herramientas disponibles para sistemas operativos Windows. [SocksOverRDP](https://github.com/nccgroup/SocksOverRDP) es un ejemplo de una herramienta que utiliza `Dynamic Virtual Channels` (`DVC`) de la función de servicio de escritorio remoto de Windows. DVC es responsable de tunelizar paquetes sobre la conexión RDP. Algunos ejemplos del uso de esta característica serían la transferencia de datos del portapapeles y el intercambio de audio. Sin embargo, esta característica también puede usarse para tunelizar paquetes arbitrarios sobre la red. Podemos usar `SocksOverRDP` para tunelizar nuestros paquetes personalizados y luego hacer proxy a través de él. Usaremos la herramienta [Proxifier](https://www.proxifier.com/) como nuestro servidor proxy.

Podemos comenzar descargando los binarios apropiados a nuestro host de ataque para realizar este ataque. Tener los binarios en nuestro host de ataque nos permitirá transferirlos a cada objetivo cuando sea necesario. Necesitaremos:

1. [SocksOverRDP x64 Binaries](https://github.com/nccgroup/SocksOverRDP/releases)
2. [Proxifier Portable Binary](https://www.proxifier.com/download/#win-tab)

- Podemos buscar `ProxifierPE.zip`

Luego podemos conectarnos al objetivo usando xfreerdp y copiar el archivo `SocksOverRDPx64.zip` al objetivo. Desde el objetivo de Windows, necesitaremos cargar el SocksOverRDP.dll usando regsvr32.exe.

### Loading SocksOverRDP.dll using regsvr32.exe

```r
C:\Users\htb-student\Desktop\SocksOverRDP-x64> regsvr32.exe SocksOverRDP-Plugin.dll
```

![](https://academy.hackthebox.com/storage/modules/158/socksoverrdpdll.png)

Ahora podemos conectarnos a 172.16.5.19 sobre RDP usando `mstsc.exe`, y deberíamos recibir un mensaje indicando que el plugin SocksOverRDP está habilitado y escuchará en 127.0.0.1:1080. Podemos usar las credenciales `victor:pass@123` para conectarnos a 172.16.5.19.

![](https://academy.hackthebox.com/storage/modules/158/pivotingtoDC.png)

Necesitaremos transferir SocksOverRDPx64.zip o solo SocksOverRDP-Server.exe a 172.16.5.19. Luego, podemos iniciar SocksOverRDP-Server.exe con privilegios de administrador.

![](https://academy.hackthebox.com/storage/modules/158/executingsocksoverrdpserver.png)

Cuando regresemos a nuestro objetivo de acceso inicial y verifiquemos con Netstat, deberíamos ver nuestro listener SOCKS iniciado en 127.0.0.1:1080.

### Confirming the SOCKS Listener is Started

```r
C:\Users\htb-student\Desktop\SocksOverRDP-x64> netstat -antb | findstr 1080

  TCP    127.0.0.1:1080         0.0.0.0:0              LISTENING
```

Después de iniciar nuestro listener, podemos transferir Proxifier portable al objetivo Windows 10 (en la red 10.129.x.x) y configurarlo para reenviar todos nuestros paquetes a 127.0.0.1:1080. Proxifier enrutará el tráfico a través del host y puerto dados. Mira el clip a continuación para una guía rápida de configuración de Proxifier.

### Configuring Proxifier

![](https://academy.hackthebox.com/storage/modules/158/configuringproxifier.gif)

Con Proxifier configurado y en funcionamiento, podemos iniciar mstsc.exe, y usará Proxifier para pivotar todo nuestro tráfico a través de 127.0.0.1:1080, que lo tunelizará sobre RDP a 172.16.5.19, que luego lo enrutaría a 172.16.6.155 usando SocksOverRDP-server.exe.

![](https://academy.hackthebox.com/storage/modules/158/rdpsockspivot.png)

### RDP Performance Considerations

Cuando interactuamos con nuestras sesiones RDP en una evaluación, podemos encontrarnos lidiando con un rendimiento lento en una sesión dada, especialmente si estamos gestionando múltiples sesiones RDP simultáneamente. Si este es el caso, podemos acceder a la pestaña `Experience` en mstsc.exe y configurar `Performance` a `Modem`.

![](https://academy.hackthebox.com/storage/modules/158/rdpexpen.png)

---

**Note**: Cuando inicies tu objetivo, te pedimos que esperes de 3 a 5 minutos hasta que todo el laboratorio con todas las configuraciones esté configurado para que la conexión a tu objetivo funcione sin problemas.
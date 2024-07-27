[Plink](https://www.chiark.greenend.org.uk/~sgtatham/putty/latest.html), abreviatura de PuTTY Link, es una herramienta de línea de comandos SSH para Windows que viene como parte del paquete PuTTY cuando se instala. Similar a SSH, Plink también se puede usar para crear `dynamic port forwards` y `SOCKS proxies`. Antes del otoño de [2018](https://docs.microsoft.com/en-us/windows-server/administration/openssh/openssh_overview), Windows no incluía un cliente ssh nativo, por lo que los usuarios tenían que instalar el suyo propio. La herramienta preferida por muchos administradores de sistemas que necesitaban conectarse a otros hosts era [PuTTY](https://www.putty.org/).

Imagina que estamos en un pentest y obtenemos acceso a una máquina Windows. Rápidamente enumeramos el host y su postura de seguridad y determinamos que está moderadamente bloqueado. Necesitamos usar este host como un punto de pivote, pero es poco probable que podamos subir nuestras propias herramientas al host sin ser detectados. En su lugar, podemos `live off the land` y usar lo que ya está allí. Si el host es antiguo y tiene PuTTY presente (o podemos encontrar una copia en un recurso compartido de archivos), Plink puede ser nuestro camino a la victoria. Podemos usarlo para crear nuestro pivote y potencialmente evitar la detección un poco más.

Ese es solo un escenario potencial donde Plink podría ser beneficioso. También podríamos usar Plink si usamos un sistema Windows como nuestro host de ataque principal en lugar de un sistema basado en Linux.

---

## Getting To Know Plink

En la imagen a continuación, tenemos un host de ataque basado en Windows.

![](https://academy.hackthebox.com/storage/modules/158/66.png)

El host de ataque Windows inicia un proceso plink.exe con los siguientes argumentos de línea de comandos para iniciar un `dynamic port forward` sobre el servidor Ubuntu. Esto inicia una sesión SSH entre el host de ataque Windows y el servidor Ubuntu, y luego plink comienza a escuchar en el puerto 9050.

### Using Plink.exe

```r
plink -ssh -D 9050 ubuntu@10.129.15.50
```

Otra herramienta basada en Windows llamada [Proxifier](https://www.proxifier.com/) puede usarse para iniciar un `SOCKS tunnel` a través de la sesión SSH que creamos. Proxifier es una herramienta de Windows que crea una red tunelizada para aplicaciones cliente de escritorio y permite operar a través de un proxy SOCKS o HTTPS y permite el `proxy chaining`. Es posible crear un perfil donde podemos proporcionar la configuración para nuestro servidor SOCKS iniciado por Plink en el puerto 9050.

![](https://academy.hackthebox.com/storage/modules/158/reverse_shell_9.png)

Después de configurar el servidor SOCKS para `127.0.0.1` y el puerto 9050, podemos iniciar directamente `mstsc.exe` para iniciar una sesión RDP con un objetivo Windows que permita conexiones RDP.

**Note**: Podemos intentar esta técnica en cualquier sección interactiva de este módulo desde un host de ataque personal basado en Windows. Una vez que hayas completado este módulo desde un host de ataque basado en Linux, siéntete libre de intentar volver a hacerlo desde un host de ataque personal basado en Windows. Además, al generar tu objetivo, te pedimos que esperes de 3 a 5 minutos hasta que todo el laboratorio con todas las configuraciones esté configurado para que la conexión con tu objetivo funcione sin problemas.
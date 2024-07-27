Uno de los fallos más recientes y peligrosos del [Simple Mail Transfer Protocol (SMTP)](https://en.wikipedia.org/wiki/Simple_Mail_Transfer_Protocol) que se ha hecho público fue descubierto en [OpenSMTPD](https://www.opensmtpd.org/) hasta la versión 6.6.2 en 2020. Esta vulnerabilidad fue asignada como [CVE-2020-7247](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-7247) y lleva a RCE. Ha sido explotable desde 2018. Este servicio se ha utilizado en muchas distribuciones de Linux diferentes, como Debian, Fedora, FreeBSD, y otras. Lo peligroso de esta vulnerabilidad es la posibilidad de ejecutar comandos del sistema de forma remota en el sistema y que explotarla no requiere autenticación.

Según [Shodan.io](https://www.shodan.io/), en el momento de escribir esto (abril de 2022), hay más de 5,000 servidores OpenSMTPD accesibles públicamente en todo el mundo, y la tendencia está creciendo. Sin embargo, esto no significa que esta vulnerabilidad afecte a cada servicio. En cambio, queremos mostrarte cuán significativo sería el impacto de un RCE en caso de que se descubriera esta vulnerabilidad ahora. Sin embargo, por supuesto, esto se aplica a todos los demás servicios también.

### Shodan Search

![OpenSMTPD](https://academy.hackthebox.com/storage/modules/116/opensmtpd.png)

### Shodan Trend

![OpenSMTPD Trend](https://academy.hackthebox.com/storage/modules/116/opensmtpd_trend.png)

---

## The Concept of the Attack

Como ya sabemos, con el servicio SMTP, podemos redactar correos electrónicos y enviarlos a las personas deseadas. La vulnerabilidad en este servicio radica en el código del programa, concretamente en la función que registra la dirección de correo electrónico del remitente. Esto ofrece la posibilidad de escapar de la función utilizando un punto y coma (`;`) y hacer que el sistema ejecute comandos arbitrarios de shell. Sin embargo, hay un límite de 64 caracteres que se pueden insertar como comando. Los detalles técnicos de esta vulnerabilidad se pueden encontrar [aquí](https://www.openwall.com/lists/oss-security/2020/01/28/3).

### The Concept of Attacks

![Concept of Attacks](https://academy.hackthebox.com/storage/modules/116/attack_concept2.png)

Aquí necesitamos inicializar primero una conexión con el servicio SMTP. Esto se puede automatizar mediante un script o ingresar manualmente. Una vez que se establece la conexión, se debe redactar un correo electrónico en el que definimos el remitente, el destinatario y el mensaje real para el destinatario. El comando del sistema deseado se inserta en el campo del remitente conectado a la dirección del remitente con un punto y coma (`;`). Tan pronto como terminemos de escribir, los datos ingresados son procesados por el proceso OpenSMTPD.

### Initiation of the Attack

|**Paso**|**Remote Code Execution**|**Concept of Attacks - Category**|
|---|---|---|
|`1.`|La fuente es la entrada del usuario que se puede ingresar manualmente o automatizar durante la interacción directa con el servicio.|`Source`|
|`2.`|El servicio tomará el correo electrónico con la información requerida.|`Process`|
|`3.`|Escuchar los puertos estandarizados de un sistema requiere privilegios de `root` en el sistema, y si estos puertos se utilizan, el servicio se ejecuta en consecuencia con privilegios elevados.|`Privileges`|
|`4.`|Como destino, la información ingresada se reenvía a otro proceso local.|`Destination`|

Es aquí donde el ciclo comienza de nuevo, pero esta vez para obtener acceso remoto al sistema objetivo.

### Trigger Remote Code Execution

|**Paso**|**Remote Code Execution**|**Concept of Attacks - Category**|
|---|---|---|
|`5.`|Esta vez, la fuente es toda la entrada, especialmente del área del remitente, que contiene nuestro comando del sistema.|`Source`|
|`6.`|El proceso lee toda la información, y el punto y coma (`;`) interrumpe la lectura debido a reglas especiales en el código fuente que llevan a la ejecución del comando del sistema ingresado.|`Process`|
|`7.`|Dado que el servicio ya se está ejecutando con privilegios elevados, otros procesos de OpenSMTPD se ejecutarán con los mismos privilegios. Con estos, también se ejecutará el comando del sistema que ingresamos.|`Privileges`|
|`8.`|El destino para el comando del sistema puede ser, por ejemplo, la red de vuelta a nuestro host a través del cual obtenemos acceso al sistema.|`Destination`|

Un [exploit](https://www.exploit-db.com/exploits/47984) se ha publicado en la plataforma [Exploit-DB](https://www.exploit-db.com/) para esta vulnerabilidad, que se puede usar para un análisis más detallado y la funcionalidad del desencadenante para la ejecución de comandos del sistema.

---

## Next Steps

Como hemos visto, los ataques de correo electrónico pueden llevar a la divulgación de datos sensibles a través del acceso directo a la bandeja de entrada de un usuario o combinando una mala configuración con un correo electrónico de phishing convincente. Hay otras formas de atacar servicios de correo electrónico que también pueden ser muy efectivas. Algunos retos de Hack The Box demuestran ataques de correo electrónico, como [Rabbit](https://www.youtube.com/watch?v=5nnJq_IWJog), que trata sobre forzar Outlook Web Access (OWA) y luego enviar un documento con una macro maliciosa para hacer phishing a un usuario, [SneakyMailer](https://0xdf.gitlab.io/2020/11/28/htb-sneakymailer.html), que tiene elementos de phishing y enumerar la bandeja de entrada de un usuario usando Netcat y un cliente IMAP, y [Reel](https://0xdf.gitlab.io/2018/11/10/htb-reel.html), que trató de forzar usuarios de SMTP y hacer phishing con un archivo RTF malicioso.

Vale la pena jugar estos retos, o al menos ver el video de Ippsec o leer un walkthrough para ver ejemplos de estos ataques en acción. Esto se aplica a cualquier ataque demostrado en este módulo (u otros). El sitio [ippsec.rocks](https://ippsec.rocks/?#) se puede usar para buscar términos comunes y mostrará en qué retos de HTB aparecen, lo que revelará una gran cantidad de objetivos para practicar.
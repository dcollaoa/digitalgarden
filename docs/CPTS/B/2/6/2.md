En 2019, se publicó una vulnerabilidad crítica en el servicio RDP (`TCP/3389`) que también llevó a la ejecución remota de código (`RCE`) con el identificador [CVE-2019-0708](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2019-0708). Esta vulnerabilidad es conocida como `BlueKeep`. No requiere acceso previo al sistema para explotar el servicio para nuestros propósitos. Sin embargo, la explotación de esta vulnerabilidad llevó y sigue llevando a muchos ataques de malware o ransomware. Grandes organizaciones como hospitales, cuyo software solo está diseñado para versiones y bibliotecas específicas, son particularmente vulnerables a tales ataques, ya que el mantenimiento de la infraestructura es costoso. Aquí tampoco entraremos en detalles sobre esta vulnerabilidad, sino que mantendremos el enfoque en el concepto.

---

## The Concept of the Attack

La vulnerabilidad se basa, al igual que SMB, en solicitudes manipuladas enviadas al servicio objetivo. Sin embargo, lo peligroso aquí es que la vulnerabilidad no requiere autenticación de usuario para ser activada. En su lugar, la vulnerabilidad ocurre después de inicializar la conexión cuando se intercambian configuraciones básicas entre el cliente y el servidor. Esto se conoce como una técnica de [Use-After-Free](https://cwe.mitre.org/data/definitions/416.html) (`UAF`) que utiliza memoria liberada para ejecutar código arbitrario.

### The Concept of Attacks

![](https://academy.hackthebox.com/storage/modules/116/attack_concept2.png)

Este ataque involucra muchos pasos diferentes en el kernel del sistema operativo, que no son de gran importancia aquí por el momento para entender el concepto detrás de él. Después de que la función ha sido explotada y la memoria ha sido liberada, se escriben datos en el kernel, lo que nos permite sobrescribir la memoria del kernel. Esta memoria se usa para escribir nuestras instrucciones en la memoria liberada y dejar que la CPU las ejecute. Si queremos ver el análisis técnico de la vulnerabilidad BlueKeep, este [artículo](https://unit42.paloaltonetworks.com/exploitation-of-windows-cve-2019-0708-bluekeep-three-ways-to-write-data-into-the-kernel-with-rdp-pdu/) proporciona una buena visión general.

### Initiation of the Attack

|**Step**|**BlueKeep**|**Concept of Attacks - Category**|
|---|---|---|
|`1.`|Aquí, la fuente es la solicitud de inicialización del intercambio de configuraciones entre el servidor y el cliente que el atacante ha manipulado.|`Source`|
|`2.`|La solicitud lleva a una función utilizada para crear un canal virtual que contiene la vulnerabilidad.|`Process`|
|`3.`|Dado que este servicio es adecuado para [administering](https://docs.microsoft.com/en-us/windows/win32/ad/the-localsystem-account) el sistema, se ejecuta automáticamente con los privilegios de la [LocalSystem Account](https://docs.microsoft.com/en-us/windows/win32/ad/the-localsystem-account) del sistema.|`Privileges`|
|`4.`|La manipulación de la función nos redirige a un proceso del kernel.|`Destination`|

Aquí es cuando el ciclo comienza de nuevo, pero esta vez para obtener acceso remoto al sistema objetivo.

### Trigger Remote Code Execution

|**Step**|**BlueKeep**|**Concept of Attacks - Category**|
|---|---|---|
|`5.`|La fuente esta vez es el payload creado por el atacante que se inserta en el proceso para liberar la memoria en el kernel y colocar nuestras instrucciones.|`Source`|
|`6.`|El proceso en el kernel se activa para liberar la memoria del kernel y dejar que la CPU apunte a nuestro código.|`Process`|
|`7.`|Dado que el kernel también se ejecuta con los privilegios más altos posibles, las instrucciones que colocamos en la memoria del kernel liberada aquí también se ejecutan con los privilegios de la [LocalSystem Account](https://docs.microsoft.com/en-us/windows/win32/ad/the-localsystem-account).|`Privileges`|
|`8.`|Con la ejecución de nuestras instrucciones desde el kernel, se envía una reverse shell a través de la red a nuestro host.|`Destination`|

No todas las variantes más nuevas de Windows son vulnerables a Bluekeep, según Microsoft. Las actualizaciones de seguridad para las versiones actuales de Windows están disponibles, y Microsoft también ha proporcionado actualizaciones para muchas versiones más antiguas de Windows que ya no son compatibles. No obstante, se identificaron `950,000` sistemas Windows como vulnerables a los ataques de `Bluekeep` en un escaneo inicial en mayo de 2019, y hoy en día, alrededor de `un cuarto` de esos hosts aún son vulnerables.

**Nota**: Esta es una falla con la que probablemente nos encontraremos durante nuestras pruebas de penetración, pero puede causar inestabilidad en el sistema, incluyendo una "pantalla azul de la muerte (BSoD)", y debemos tener cuidado antes de usar el exploit asociado. En caso de duda, es mejor hablar primero con nuestro cliente para que entiendan los riesgos y luego decidir si desean que ejecutemos el exploit o no.
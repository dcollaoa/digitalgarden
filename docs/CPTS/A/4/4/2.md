La aplicación OpenVAS Greenbone Security Assistant tiene varias pestañas con las que puedes interactuar. Para esta sección, profundizaremos en los escaneos. Si navegas a la pestaña `Scans` que se muestra a continuación, verás los escaneos que se han ejecutado en el pasado. También podrás ver cómo crear una nueva tarea para ejecutar un escaneo. Las tareas funcionan a partir de las configuraciones de escaneo que el usuario configura.

**Nota:** Los escaneos mostrados en esta sección ya se han ejecutado previamente para ahorrarte el tiempo de esperar a que terminen. Si vuelves a ejecutar el escaneo, es mejor revisar las vulnerabilidades a medida que aparecen, en lugar de esperar a que el escaneo termine, ya que pueden tardar entre 1-2 horas en completarse.

![Scans](https://academy.hackthebox.com/storage/modules/108/openvas/creatingscan1.png)

**Nota:** Para este módulo, el objetivo de Windows será `172.16.16.100` y el objetivo de Linux será `172.16.16.160`.

![Scansconfigs](https://academy.hackthebox.com/storage/modules/108/openvas/scanconfigs.png)

---

## Configuration

Antes de configurar cualquier escaneo, es mejor configurar los objetivos para el escaneo. Si navegas a la pestaña `Configurations` y seleccionas `Targets`, verás los objetivos que ya se han añadido a la aplicación.

![targetstab](https://academy.hackthebox.com/storage/modules/108/openvas/targets.png)

Para añadir los tuyos, haz clic en el icono resaltado a continuación y añade un objetivo individual o una lista de hosts. También puedes configurar otras opciones como los puertos, autenticación y métodos para identificar si el host es alcanzable. Para el `Alive Test`, la opción `Scan Config Default` de OpenVAS utiliza el `NVT Ping Host` en la `NVT Family`. Puedes aprender sobre la NVT Family [aquí](https://docs.greenbone.net/GSM-Manual/gos-6/en/scanning.html#vulnerabilitymanagement-create-target).

![createtarget](https://academy.hackthebox.com/storage/modules/108/openvas/addingtarget.png)

Típicamente, un `authenticated scan` utiliza un usuario con altos privilegios como `root` o `Administrator`. Dependiendo del nivel de permisos del usuario, si es el nivel más alto de permisos, obtendrás la máxima cantidad de información del host en cuanto a las vulnerabilidades presentes, ya que tendrías acceso completo.

**Nota:** Para ejecutar un escaneo con credenciales en el objetivo, utiliza las siguientes credenciales: `htb-student_adm`:`HTB_@cademy_student!` para Linux, y `administrator`:`Academy_VA_adm1!` para Windows. Estos escaneos ya han sido configurados en el objetivo de OpenVAS para ahorrarte tiempo.

Una vez que hayas añadido tu objetivo, aparecerán en la lista a continuación: ![targetsview](https://academy.hackthebox.com/storage/modules/108/openvas/targetsview.png)

---

## Setting Up a Scan

Varias configuraciones de escaneo utilizan las OpenVAS Network Vulnerability Test (NVT) Families, que consisten en muchas categorías diferentes de vulnerabilidades, como las de Windows, Linux, aplicaciones web, etc. Puedes ver algunos tipos diferentes de familias a continuación: ![nvt](https://academy.hackthebox.com/storage/modules/108/openvas/nvt2.png)

OpenVAS tiene varias configuraciones de escaneo para elegir al escanear una red. Recomendamos utilizar solo las siguientes, ya que otras opciones podrían causar interrupciones en un sistema en una red:

- `Base`: Esta configuración de escaneo está destinada a enumerar información sobre el estado del host y la información del sistema operativo. Esta configuración de escaneo no busca vulnerabilidades.
    
- `Discovery`: Esta configuración de escaneo está destinada a enumerar información sobre el sistema. La configuración identifica los servicios del host, hardware, puertos accesibles y software utilizado en el sistema. Esta configuración de escaneo tampoco busca vulnerabilidades.
    
- `Host Discovery`: Esta configuración de escaneo solo prueba si el host está activo y determina qué dispositivos están `active` en la red. Esta configuración de escaneo tampoco busca vulnerabilidades. _OpenVAS utiliza ping para identificar si el host está activo._
    
- `System Discovery`: Este escaneo enumera el host objetivo más allá del 'Discovery Scan' e intenta identificar el sistema operativo y hardware asociado con el host.
    
- `Full and fast`: Esta configuración es recomendada por OpenVAS como la opción más segura y utiliza inteligencia para usar los mejores controles NVT para los host(s) basados en los puertos accesibles.
    

Puedes crear tu propio escaneo navegando a la pestaña 'Scans' y haciendo clic en el icono del asistente. ![Scans2](https://academy.hackthebox.com/storage/modules/108/openvas/creatingscan2.png)

Una vez que haces clic en el icono del asistente, aparecerá el panel que se muestra a continuación y te permitirá configurar tu escaneo.

![CreateScan](https://academy.hackthebox.com/storage/modules/108/openvas/Newscan.png)

Configuraremos el escaneo con las opciones a continuación, que tienen como objetivo `172.16.16.160` y luego ejecutaremos nuestro escaneo, que puede tardar entre `30-60 minutos` en completarse.

![linux_basic](https://academy.hackthebox.com/storage/modules/108/openvas/linux_basic.png)

![linux_target_unauth](https://academy.hackthebox.com/storage/modules/108/openvas/linux_unauthedtarget.png)

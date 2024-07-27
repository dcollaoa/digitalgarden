## Notetaking Sample Structure

La toma de notas es fundamental durante cualquier evaluación. Nuestras notas, acompañadas por las salidas de herramientas y logs, son los insumos brutos para nuestro borrador de informe, que es típicamente la única parte de nuestra evaluación que ve el cliente. Aunque usualmente mantenemos nuestras notas para nosotros mismos, debemos mantenerlas organizadas y desarrollar un proceso repetible para ahorrar tiempo y facilitar el proceso de reporte. Las notas detalladas también son esenciales en caso de un problema de red o una pregunta del cliente (es decir, ¿escaneaste X host en Y día?), por lo que ser demasiado detallado en la toma de notas nunca está de más. Cada persona tendrá su propio estilo con el que se sienta cómodo y debe trabajar con sus herramientas y estructura organizativa preferidas para asegurar los mejores resultados posibles. En este módulo, cubriremos los elementos mínimos que, según nuestra experiencia profesional, deben anotarse durante una evaluación (o incluso mientras se trabaja en un módulo grande, jugando una caja en HTB o tomando un examen) para ahorrar tiempo y energía al momento de reportar o como guía de referencia en el futuro. Si eres parte de un equipo más grande donde alguien puede tener que cubrir una reunión con el cliente por ti, notas claras y consistentes son esenciales para asegurar que tu compañero pueda hablar con confianza y precisión sobre las actividades realizadas o no realizadas.

## Notetaking Sample Structure

No existe una solución o estructura universal para la toma de notas, ya que cada proyecto y tester es diferente. La estructura a continuación es la que hemos encontrado útil, pero debe adaptarse a tu flujo de trabajo personal, tipo de proyecto y las circunstancias específicas que encontraste durante tu proyecto. Por ejemplo, algunas de estas categorías pueden no ser aplicables para una evaluación enfocada en aplicaciones y pueden incluso requerir categorías adicionales no listadas aquí.

- `Attack Path` - Un esquema del camino completo si obtienes un acceso inicial durante un external penetration test o comprometes uno o más hosts (o el AD domain) durante un internal penetration test. Esquematiza el camino tan detalladamente como sea posible utilizando capturas de pantalla y salidas de comandos, lo que facilitará pegarlo en el informe más tarde y solo tendrás que preocuparte por el formato.
    
- `Credentials` - Un lugar centralizado para guardar tus credenciales y secretos comprometidos a medida que avanzas.
    
- `Findings` - Recomendamos crear una subcarpeta para cada hallazgo y luego escribir nuestra narrativa y guardarla en la carpeta junto con cualquier evidencia (capturas de pantalla, salida de comandos). También vale la pena mantener una sección en tu herramienta de toma de notas para registrar información sobre los hallazgos para ayudar a organizarlos para el informe.
    
- `Vulnerability Scan Research` - Una sección para tomar notas sobre las cosas que has investigado y probado con tus vulnerability scans (para que no termines rehaciendo el trabajo que ya hiciste).
    
- `Service Enumeration Research` - Una sección para tomar notas sobre qué servicios has investigado, intentos de explotación fallidos, vulnerabilidades/malconfiguraciones prometedoras, etc.
    
- `Web Application Research` - Una sección para anotar aplicaciones web interesantes encontradas a través de varios métodos, como subdomain brute-forcing. Siempre es bueno realizar una enumeración exhaustiva de subdominios externamente, escanear puertos web comunes en evaluaciones internas y ejecutar una herramienta como Aquatone o EyeWitness para capturar capturas de pantalla de todas las aplicaciones. A medida que revisas el informe de capturas de pantalla, anota aplicaciones de interés, pares de credenciales comunes/predeterminadas que probaste, etc.
    
- `AD Enumeration Research` - Una sección para mostrar, paso a paso, qué enumeración de Active Directory ya has realizado. Anota cualquier área de interés que necesites investigar más adelante en la evaluación.
    
- `OSINT` - Una sección para mantener un registro de la información interesante que has recopilado mediante OSINT, si es aplicable al engagement.
    
- `Administrative Information` - Algunas personas pueden encontrar útil tener un lugar centralizado para almacenar información de contacto de otros stakeholders del proyecto, como Project Managers (PMs) o client Points of Contact (POCs), objetivos únicos/banderas definidas en las Rules of Engagement (RoE) y otros elementos que te encuentras a menudo referenciando durante el proyecto. También se puede utilizar como una lista de tareas pendientes. A medida que surgen ideas para pruebas que necesitas realizar o quieres probar pero no tienes tiempo para ello, sé diligente en anotarlas aquí para que puedas volver a ellas más tarde.
    
- `Scoping Information` - Aquí podemos almacenar información sobre IP addresses/CIDR ranges in-scope, URLs de aplicaciones web y cualquier credencial para aplicaciones web, VPN o AD proporcionada por el cliente. También podría incluir cualquier otra cosa pertinente al scope de la evaluación para no tener que volver a abrir la información del scope y asegurar que no nos desviemos del scope de la evaluación.
    
- `Activity Log` - Un seguimiento a alto nivel de todo lo que hiciste durante la evaluación para posible correlación de eventos.
    
- `Payload Log` - Similar al activity log, el seguimiento de los payloads que estás utilizando (y un hash de archivo para cualquier cosa cargada y la ubicación de la carga) en un entorno del cliente es crucial. Más sobre esto más adelante.

---

## Notetaking Tools

Hay muchas herramientas disponibles para la toma de notas, y la elección es muy personal. Aquí hay algunas de las opciones disponibles:

||||
|---|---|---|
|[CherryTree](https://www.giuspen.com/cherrytree/)|[Visual Studio Code](https://code.visualstudio.com/)|[Evernote](https://evernote.com/)|
|[Notion](https://www.notion.so/)|[GitBook](https://www.gitbook.com/)|[Sublime Text](https://www.sublimetext.com/)|
|[Notepad++](https://notepad-plus-plus.org/downloads/)|[OneNote](https://www.onenote.com/?public=1)|[Outline](https://www.getoutline.com/)|
|[Obsidian](https://obsidian.md/)|[Cryptpad](https://cryptpad.fr/)|[Standard Notes](https://standardnotes.com/)|

Como equipo, hemos tenido muchas discusiones sobre los pros y los contras de varias herramientas de toma de notas. Un factor clave es distinguir entre soluciones locales y en la nube antes de elegir una herramienta. Una solución en la nube es probablemente aceptable para cursos de capacitación, CTFs, laboratorios, etc., pero una vez que entramos en engagements y manejamos datos de clientes, debemos ser más cuidadosos con la solución que elegimos. Tu empresa probablemente tendrá algún tipo de política o obligaciones contractuales sobre el almacenamiento de datos, por lo que es mejor consultar con tu gerente o líder de equipo si el uso de una herramienta de toma de notas específica está permitido. `Obsidian` es una excelente solución para almacenamiento local, y `Outline` es excelente para la nube, pero también tiene una [versión autohospedada](https://github.com/outline/outline). Ambas herramientas se pueden exportar a Markdown e importar en cualquier otra herramienta que acepte este formato conveniente.

### Obsidian

![image](https://academy.hackthebox.com/storage/modules/162/notetaking.png)

De nuevo, las herramientas son preferencias personales de una persona a otra. Los requisitos típicamente varían de empresa a empresa, por lo que experimenta con diferentes opciones y encuentra una con la que te sientas cómodo y practica con diferentes configuraciones y formatos mientras trabajas en módulos de la Academia, cajas de HTB, Pro Labs y otras formaciones para familiarizarte con tu estilo de toma de notas mientras eres lo más detallado posible.

---

## Logging

Es esencial que registremos todos los intentos de escaneo y ataque y mantengamos la salida bruta de las herramientas siempre que sea posible. Esto nos ayudará enormemente al momento de reportar. Aunque nuestras notas deben ser claras y extensas, podemos pasar por alto algo, y tener nuestros logs como respaldo puede ayudarnos cuando agregamos más evidencia a un informe o respondemos a una pregunta del cliente.

### Exploitation Attempts

[Tmux logging](https://github.com/tmux-plugins/tmux-logging) es una excelente opción para el logging de terminales, y absolutamente deberíamos estar usando `Tmux` junto con logging, ya que esto guardará todo lo que escribimos en un panel de Tmux en un archivo de log. También es esencial hacer un seguimiento de los intentos de explotación en caso de que el cliente necesite correlacionar eventos más adelante (o en una situación donde haya muy pocos hallazgos y tengan preguntas sobre el trabajo realizado). Es extremadamente vergonzoso si no puedes producir esta información, y puede hacer que parezcas inexperto y poco profesional como penetration tester. También puede ser una buena práctica llevar un registro de las cosas que intentaste durante la evaluación pero que no funcionaron. Esto es especialmente útil en aquellos casos en los que tenemos pocos o ningún hallazgo en tu informe. En este caso, podemos redactar una narrativa de los tipos de pruebas realizadas para que el lector pueda entender los tipos de cosas contra las que están adecuadamente protegidos. Podemos configurar el logging de Tmux en nuestro sistema de la siguiente manera:

Primero, clona el [Tmux Plugin Manager](https://github.com/tmux-plugins/tpm) repo en tu directorio home (en nuestro caso `/home/htb-student` o simplemente `~`).



```r
git clone https://github.com/tmux-plugins/tpm ~/.tmux/plugins/tpm
```

A continuación, crea un archivo `.tmux.conf` en el directorio

 home.



```r
touch .tmux.conf
```

El archivo de configuración debe tener el siguiente contenido:



```r
cat .tmux.conf 

# List of plugins

set -g @plugin 'tmux-plugins/tpm'
set -g @plugin 'tmux-plugins/tmux-sensible'
set -g @plugin 'tmux-plugins/tmux-logging'

# Initialize TMUX plugin manager (keep at bottom)
run '~/.tmux/plugins/tpm/tpm'
```

Después de crear este archivo de configuración, necesitamos ejecutarlo en nuestra sesión actual para que los ajustes en el archivo `.tmux.conf` surtan efecto. Podemos hacer esto con el comando [source](https://www.geeksforgeeks.org/source-command-in-linux-with-examples/).



```r
tmux source ~/.tmux.conf 
```

A continuación, podemos iniciar una nueva sesión de Tmux (es decir, `tmux new -s setup`).

Una vez en la sesión, escribe `[Ctrl] + [B]` y luego presiona `[Shift] + [I]` (o `prefix` + `[Shift] + [I]` si no estás utilizando la tecla de prefijo predeterminada), y el plugin se instalará (esto podría tomar alrededor de 5 segundos en completarse).

Una vez que el plugin esté instalado, comienza a registrar la sesión actual (o panel) escribiendo `[Ctrl] + [B]` seguido de `[Shift] + [P]` (`prefix` + `[Shift] + [P]`) para comenzar el logging. Si todo salió según lo planeado, la parte inferior de la ventana mostrará que el logging está habilitado y el archivo de salida. Para detener el logging, repite la combinación de teclas `prefix` + `[Shift] + [P]` o escribe `exit` para finalizar la sesión. Ten en cuenta que el archivo de log solo se llenará una vez que detengas el logging o salgas de la sesión de Tmux.

Una vez que el logging esté completo, puedes encontrar todos los comandos y la salida en el archivo de log asociado. Consulta la demostración a continuación para una breve visualización sobre cómo iniciar y detener el logging de Tmux y ver los resultados.

![image](https://academy.hackthebox.com/storage/modules/162/tmux_log_enable.gif)

Si olvidamos habilitar el logging de Tmux y estamos profundamente inmersos en un proyecto, podemos realizar un logging retroactivo escribiendo `[Ctrl] + [B]` y luego presionando `[Alt] + [Shift] + [P]` (`prefix` + `[Alt] + [Shift] + [P]`), y todo el panel se guardará. La cantidad de datos guardados depende del `history-limit` de Tmux o del número de líneas mantenidas en el buffer de scrollback de Tmux. Si esto se deja en el valor predeterminado y tratamos de realizar un logging retroactivo, probablemente perderemos datos de principios de la evaluación. Para protegernos contra esta situación, podemos agregar las siguientes líneas al archivo `.tmux.conf` (ajustando el número de líneas a nuestro gusto):

### Tmux.conf



```r
set -g history-limit 50000
```

Otro truco útil es la capacidad de capturar una captura de pantalla de la ventana actual de Tmux o de un panel individual. Digamos que estamos trabajando con una ventana dividida (2 paneles), una con `Responder` y otra con `ntlmrelayx.py`. Si intentamos copiar/pegar la salida de un panel, tomaremos datos del otro panel junto con ella, lo que se verá muy desordenado y requerirá limpieza. Podemos evitar esto tomando una captura de pantalla de la siguiente manera: `[Ctrl] + [B]` seguido de `[Alt] + [P]` (`prefix` + `[Alt] + [P]`). Veamos una demostración rápida.

Aquí podemos ver que estamos trabajando con dos paneles. Si intentamos copiar texto de un panel, tomaremos texto del otro panel, lo que haría un desastre de la salida. Pero, con el logging de Tmux habilitado, podemos capturar el panel y salida de forma ordenada a un archivo.

![image](https://academy.hackthebox.com/storage/modules/162/tmux_pane_capture.gif)

Para recrear el ejemplo anterior, primero inicia una nueva sesión de tmux: `tmux new -s sessionname`. Una vez en la sesión, escribe `[Ctrl] + [B]` + `[Shift] + [%]` (`prefix` + `[Shift] + [%]`) para dividir los paneles verticalmente (reemplaza el `[%]` con `["]` para hacer una división horizontal). Luego podemos movernos de panel a panel escribiendo `[Ctrl] + [B]` + `[O]` (`prefix` + `[O]`).

Finalmente, podemos borrar el historial del panel escribiendo `[Ctrl] + [B]` seguido de `[Alt] + [C]` (`prefix` + `[Alt] + [C]`).

Hay muchas otras cosas que podemos hacer con Tmux, personalizaciones que podemos hacer con el logging de Tmux (es decir, [cambiar la ruta de logging predeterminada](https://github.com/tmux-plugins/tmux-logging/blob/master/docs/configuration.md), cambiar las combinaciones de teclas, ejecutar múltiples ventanas dentro de sesiones y paneles dentro de esas ventanas, etc.). Vale la pena leer todas las capacidades que ofrece Tmux y descubrir cómo la herramienta se adapta mejor a tu flujo de trabajo. Finalmente, aquí hay algunos plugins adicionales que nos gustan:

- [tmux-sessionist](https://github.com/tmux-plugins/tmux-sessionist) - Nos da la capacidad de manipular sesiones de Tmux desde dentro de una sesión: cambiar a otra sesión, crear una nueva sesión con nombre, matar una sesión sin desconectar Tmux, promover el panel actual a una nueva sesión, y más.
    
- [tmux-pain-control](https://github.com/tmux-plugins/tmux-pain-control) - Un plugin para controlar paneles y proporcionar combinaciones de teclas más intuitivas para moverse, redimensionar y dividir paneles.
    
- [tmux-resurrect](https://github.com/tmux-plugins/tmux-resurrect) - Este plugin extremadamente útil nos permite restaurar nuestro entorno de Tmux después de que nuestro host se reinicie. Algunas características incluyen restaurar todas las sesiones, ventanas, paneles y su orden, restaurar programas en ejecución en un panel, restaurar sesiones de Vim, y más.
    

Consulta la lista completa de [plugins de tmux](https://github.com/tmux-plugins/list) para ver si otros encajan bien en tu flujo de trabajo. Para más información sobre Tmux, consulta este excelente [video](https://www.youtube.com/watch?v=Lqehvpe_djs) por Ippsec y este [cheat sheet](https://mavericknerd.github.io/knowledgebase/ippsec/tmux/) basado en el video.

---

## Artifacts Left Behind

Como mínimo, debemos llevar un seguimiento de cuándo se utilizó un payload, en qué host se utilizó, en qué ruta de archivo se colocó en el objetivo y si se eliminó o necesita ser eliminado por el cliente. También se recomienda un hash de archivo para facilitar la búsqueda por parte del cliente. Es una buena práctica proporcionar esta información incluso si eliminamos cualquier web shell, payload o herramienta.

### Account Creation/System Modifications

Si creamos cuentas o modificamos configuraciones del sistema, debería ser evidente que necesitamos llevar un registro de esas cosas en caso de que no podamos revertirlas una vez que la evaluación esté completa. Algunos ejemplos de esto incluyen:

- Dirección IP del host(s)/nombre(s) del host donde se realizó el cambio
- Marca de tiempo del cambio
- Descripción del cambio
- Ubicación en el host(s) donde se realizó el cambio
- Nombre de la aplicación o servicio que se modificó
- Nombre de la cuenta (si creaste una) y quizás la contraseña en caso de que se te solicite entregarla

Debería ser innecesario decirlo, pero como profesional y para evitar crear enemigos en el equipo de infraestructura, debes obtener aprobación por escrito del cliente antes de hacer estos tipos de cambios en el sistema o realizar cualquier tipo de prueba que pueda causar un problema con la estabilidad o disponibilidad del sistema. Esto generalmente se puede resolver durante la llamada de inicio del proyecto para determinar el umbral más allá del cual el cliente está dispuesto a tolerar sin ser notificado.

---

## Evidence

No importa el tipo de evaluación, a nuestro cliente (típicamente) no le importa las cadenas de exploits geniales que realizamos o qué tan fácilmente "pwned" su red. En última instancia, están pagando por el deliverable del informe, que debería comunicar claramente los problemas descubiertos y la evidencia que se puede usar para la validación y reproducción. Sin evidencia clara, puede ser difícil para los equipos de seguridad internos, sysadmins, desarrolladores, etc., reproducir nuestro trabajo mientras trabajan para implementar una solución o incluso para entender la naturaleza del problema.

### What to Capture

Como sabemos, cada hallazgo necesitará tener evidencia. También puede ser prudente recopilar evidencia de pruebas que se realizaron sin éxito en caso de que el cliente cuestione tu exhaustividad. Si estás trabajando en la línea de comandos, los logs de Tmux pueden ser una evidencia suficiente para pegar en el informe como salida literal del terminal, pero pueden estar horriblemente formateados. Por esta razón, capturar la salida del terminal para pasos significativos a medida que avanzas y llevar un seguimiento separado junto con tus hallazgos es una buena idea. Para todo lo demás, se deben tomar capturas de pantalla.

### Storage

Al igual que con nuestra estructura de toma de notas, es una buena idea idear un marco para cómo organizamos los datos recopilados durante una evaluación. Esto puede parecer excesivo en evaluaciones más pequeñas, pero si estamos probando en un entorno grande y no tenemos una manera estructurada de llevar un seguimiento de las cosas, terminaremos olvidando algo, violando las reglas del engagement y

 probablemente haciendo cosas más de una vez, lo que puede ser una gran pérdida de tiempo, especialmente durante una evaluación con límite de tiempo. A continuación se muestra una estructura de carpeta base sugerida, pero puede ser necesario adaptarla según el tipo de evaluación que estés realizando o las circunstancias únicas.

- `Admin`
    
    - Scope of Work (SoW) con el que estás trabajando, tus notas de la reunión de inicio del proyecto, informes de estado, notificaciones de vulnerabilidad, etc.
- `Deliverables`
    
    - Carpeta para guardar tus entregables a medida que trabajas en ellos. Esto a menudo será tu informe, pero puede incluir otros elementos como hojas de cálculo suplementarias y presentaciones de diapositivas, dependiendo de los requisitos específicos del cliente.
- `Evidence`
    
    - Findings
        - Sugerimos crear una carpeta para cada hallazgo que planeas incluir en el informe para mantener tu evidencia de cada hallazgo en un contenedor y facilitar el armado del informe cuando escribas el informe.
    - Scans
        - Vulnerability scans
            - Archivos de exportación de tu vulnerability scanner (si es aplicable para el tipo de evaluación) para archivar.
        - Service Enumeration
            - Archivos de exportación de herramientas que usas para enumerar servicios en el entorno objetivo, como Nmap, Masscan, Rumble, etc.
        - Web
            - Archivos de exportación de herramientas como ZAP o Burp state files, EyeWitness, Aquatone, etc.
        - AD Enumeration
            - Archivos JSON de BloodHound, archivos CSV generados a partir de PowerView o ADRecon, datos de Ping Castle, archivos de log de Snaffler, logs de CrackMapExec, datos de herramientas de Impacket, etc.
    - Notes
        - Una carpeta para guardar tus notas.
    - OSINT
        - Cualquier salida de OSINT de herramientas como Intelx y Maltego que no encaje bien en tu documento de notas.
    - Wireless
        - Opcional si las pruebas inalámbricas están en scope, puedes usar esta carpeta para la salida de herramientas de pruebas inalámbricas.
    - Logging output
        - Salida de logging de Tmux, Metasploit y cualquier otra salida de log que no encaje en los subdirectorios de `Scan` listados arriba.
    - Misc Files
        - Web shells, payloads, scripts personalizados y cualquier otro archivo generado durante la evaluación que sea relevante para el proyecto.
- `Retest`
    
    - Esta es una carpeta opcional si necesitas regresar después de la evaluación original y volver a probar los hallazgos descubiertos anteriormente. Puede que desees replicar la estructura de carpetas que utilizaste durante la evaluación inicial en este directorio para mantener tu evidencia de re-test separada de tu evidencia original.

Es una buena idea tener scripts y trucos para configurar al inicio de una evaluación. Podríamos tomar el siguiente comando para crear nuestros directorios y subdirectorios y adaptarlo aún más.



```r
mkdir -p ACME-IPT/{Admin,Deliverables,Evidence/{Findings,Scans/{Vuln,Service,Web,'AD Enumeration'},Notes,OSINT,Wireless,'Logging output','Misc Files'},Retest}
```



```r
tree ACME-IPT/

ACME-IPT/
├── Admin
├── Deliverables
├── Evidence
│   ├── Findings
│   ├── Logging output
│   ├── Misc Files
│   ├── Notes
│   ├── OSINT
│   ├── Scans
│   │   ├── AD Enumeration
│   │   ├── Service
│   │   ├── Vuln
│   │   └── Web
│   └── Wireless
└── Retest
```

Una característica interesante de una herramienta como Obsidian es que podemos combinar nuestra estructura de carpetas y estructura de toma de notas. De esta manera, podemos interactuar con las notas/carpetas directamente desde la línea de comandos o dentro de la herramienta Obsidian. Aquí podemos ver la estructura general de carpetas trabajando a través de Obsidian.

![image](https://academy.hackthebox.com/storage/modules/162/notetaking2.png)

Profundizando más, podemos ver los beneficios de combinar nuestra toma de notas y estructura de carpetas. Durante una evaluación real, podemos agregar páginas/carpetas adicionales o eliminar algunas, una página y una carpeta para cada hallazgo, etc.

![image](https://academy.hackthebox.com/storage/modules/162/notetaking3.png)

Echando un vistazo rápido a la estructura del directorio, podemos ver cada carpeta que creamos previamente y algunas ahora pobladas con páginas Markdown de Obsidian.



```r
tree
.
└── Inlanefreight Penetration Test
    ├── Admin
    ├── Deliverables
    ├── Evidence
    │   ├── Findings
    │   │   ├── H1 - Kerberoasting.md
    │   │   ├── H2 - ASREPRoasting.md
    │   │   ├── H3 - LLMNR&NBT-NS Response Spoofing.md
    │   │   └── H4 - Tomcat Manager Weak Credentials.md
    │   ├── Logging output
    │   ├── Misc files
    │   ├── Notes
    │   │   ├── 10. AD Enumeration Research.md
    │   │   ├── 11. Attack Path.md
    │   │   ├── 12. Findings.md
    │   │   ├── 1. Administrative Information.md
    │   │   ├── 2. Scoping Information.md
    │   │   ├── 3. Activity Log.md
    │   │   ├── 4. Payload Log.md
    │   │   ├── 5. OSINT Data.md
    │   │   ├── 6. Credentials.md
    │   │   ├── 7. Web Application Research.md
    │   │   ├── 8. Vulnerability Scan Research.md
    │   │   └── 9. Service Enumeration Research.md
    │   ├── OSINT
    │   ├── Scans
    │   │   ├── AD Enumeration
    │   │   ├── Service
    │   │   ├── Vuln
    │   │   └── Web
    │   └── Wireless
    └── Retest

16 directories, 16 files
```

Recordatorio: La estructura de carpetas y toma de notas mostrada anteriormente es la que ha funcionado para nosotros en nuestras carreras, pero diferirá de persona a persona y de engagement a engagement. Te animamos a probar esto como base, ver cómo funciona para ti y usarlo como base para crear un estilo que funcione para ti. Lo importante es que seamos minuciosos y organizados, y no hay una única manera de abordar esto. Obsidian es una gran herramienta, y este formato es limpio, fácil de seguir y fácilmente reproducible de engagement a engagement. Podrías crear un script para crear la estructura de directorios y los 10 archivos Markdown iniciales. Tendrás la oportunidad de jugar con esta estructura de muestra a través del acceso a una VM de Parrot al final de esta sección.

---

## Formatting and Redaction

Credentials y Personal Identifiable Information (`PII`) deben ser redactados en capturas de pantalla y cualquier cosa que sea moralmente objetable, como material gráfico o quizás comentarios y lenguaje obsceno. También puedes considerar lo siguiente:

- Agregar anotaciones a la imagen, como flechas o cuadros, para llamar la atención sobre los elementos importantes en la captura de pantalla, particularmente si hay mucho ocurriendo en la imagen (no hagas esto en MS Word).
    
- Agregar un borde mínimo alrededor de la imagen para que resalte contra el fondo blanco del documento.
    
- Recortar la imagen para mostrar solo la información relevante (por ejemplo, en lugar de una captura de pantalla completa, solo mostrar un formulario de inicio de sesión básico).
    
- Incluir la barra de direcciones en el navegador o alguna otra información que indique a qué URL o host estás conectado.
    

### Screenshots

Siempre que sea posible, debemos intentar usar la salida del terminal sobre capturas de pantalla del terminal. Es más fácil de redactar, resaltar las partes importantes (es decir, el comando que ejecutamos en texto azul y la parte de la salida a la que queremos llamar la atención en rojo), típicamente se ve más ordenado en el documento y puede evitar que el documento se convierta en un archivo enorme e inmanejable si tenemos muchos hallazgos. Debemos tener cuidado de no alterar la salida del terminal ya que queremos dar una representación exacta del comando que ejecutamos y el resultado. Está bien acortar/eliminar salida innecesaria y marcar la porción eliminada con `<SNIP>`, pero nunca alterar la salida o agregar cosas que no estaban en el comando o salida original. Usar figuras basadas en texto también facilita al cliente copiar/pegar para reproducir tus resultados. También es importante que el material fuente del que estás pegando _desde_ tenga todo el formato eliminado antes de colocarlo en tu documento de Word. Si estás pegando texto que tiene formato incrustado, es posible que termines pegando caracteres no codificados en UTF-8 en tus comandos (usualmente comillas o apóstrofes alternativos), lo que puede causar que el comando no funcione correctamente cuando el cliente intente reproducirlo.

Una forma común de redactar capturas de pantalla es mediante pixelación o desenfoque utilizando una herramienta como Greenshot. [Research](https://www.bleepingcomputer.com/news/security/researcher-reverses-redaction-extracts-words-from-pixelated-image/) ha demostrado que este método no es infalible y hay una alta probabilidad de que los datos originales puedan ser recuperados revirtiendo la técnica de pixelación/desenfoque. Esto se puede hacer con una herramienta como [Unredacter](https://github.com/bishopfox/unredacter). En su lugar, debemos evitar esta técnica y usar barras negras (u otra forma sólida) sobre el texto que deseamos redactar. Debemos editar la imagen directamente y no solo aplicar una forma en MS Word, ya que alguien con acceso al documento podría eliminar esto fácilmente. Como comentario aparte, si estás escribiendo una publicación de blog o algo publicado en la web con datos sensibles redactados, no confíes en el estilo HTML/CSS para intentar oscurecer el texto (es decir, texto negro con un fondo negro) ya que esto se puede ver fácilmente resaltando el texto o editando temporalmente la fuente de la página. En caso de duda, usa la salida de la consola, pero si debes usar una captura de pantalla del terminal, asegúrate de redactar la información de manera adecuada. A continuación, se muestran ejemplos de las dos técnicas:

### Blurring Password Data

![image](https://academy.hackthebox.com/storage/modules/162/blurred.png)

### Blanking Out Password with Solid Shape

![image](https://academy.hackthebox.com/storage/modules/162/boxes.png)

Finalmente, aquí hay una forma sugerida de presentar evidencia de terminal en un documento de informe. Aquí hemos preservado el comando y la salida originales pero mejorado para resaltar tanto el comando como la salida de interés (autenticación exitosa).

![image](https://academy.hackthebox.com/storage/modules/162/terminal_output.png)

La forma en que presentamos la evidencia diferirá de un informe a otro. Podemos encontrarnos en una situación en la que no podemos copiar/pegar la salida del terminal, por lo que debemos confiar en una captura de pantalla. Los consejos aquí están destinados a proporcionar opciones para crear un informe ordenado pero preciso con toda la evidencia representada adecuadamente.

### Terminal

Típicamente, lo único que necesita ser redactado de la salida del terminal son las credenciales (ya sea en el comando mismo o en la salida del comando). Esto incluye hashes de contraseñas. Para hashes de contraseñas, generalmente puedes simplemente eliminar el medio de ellos y dejar los primeros y últimos 3 o 4 caracteres para mostrar que

 realmente había un hash allí. Para credenciales en texto claro o cualquier otro contenido legible por humanos que necesite ser obfuscado, puedes simplemente reemplazarlo con un marcador `<REDACTED>` o `<PASSWORD REDACTED>`, o similar.

También debes considerar el resaltado con código de colores en la salida del terminal para resaltar el comando que se ejecutó y la salida interesante de ejecutar ese comando. Esto mejora la capacidad del lector para identificar las partes esenciales de la evidencia y qué buscar si intentan reproducirlo por su cuenta. Si estás trabajando en un payload web complejo, puede ser difícil detectar el payload en una enorme solicitud codificada en URL si no haces esto para ganarte la vida. Debemos aprovechar todas las oportunidades para hacer el informe más claro para nuestros lectores, que a menudo no tendrán una comprensión tan profunda del entorno (especialmente desde la perspectiva de un penetration tester) como nosotros al final de la evaluación.

---

## What Not to Archive

Cuando comenzamos una penetration test, nuestros clientes nos confían ingresar a su red y "no hacer daño" siempre que sea posible. Esto significa no derribar hosts ni afectar la disponibilidad de aplicaciones o recursos, no cambiar contraseñas (a menos que se permita explícitamente), hacer cambios de configuración significativos o difíciles de revertir, o ver o eliminar ciertos tipos de datos del entorno. Estos datos pueden incluir PII no redactada, información potencialmente criminal, cualquier cosa considerada legalmente "descubierta", etc. Por ejemplo, si obtienes acceso a un recurso compartido de red con datos sensibles, probablemente sea mejor simplemente capturar una captura de pantalla del directorio con los archivos en lugar de abrir archivos individuales y capturar el contenido del archivo. Si los archivos son tan sensibles como piensas, recibirán el mensaje y sabrán qué hay en ellos según el nombre del archivo. La recopilación de PII real y la extracción del entorno objetivo puede tener obligaciones significativas de cumplimiento para el almacenamiento y procesamiento de esos datos como GDPR y similares, y podría abrir una serie de problemas para nuestra empresa y para nosotros.

---

## Module Exercises

Hemos incluido un cuaderno de muestra de Obsidian parcialmente completado en el host de Parrot Linux que se puede generar al final de esta sección. Puedes acceder a él con las credenciales proporcionadas utilizando el siguiente comando:



```r
xfreerdp /v:10.129.203.82 /u:htb-student /p:HTB_@cademy_stdnt!
```

Una vez conectado, puedes abrir Obsidian desde el escritorio, navegar por el cuaderno de muestra y revisar la información que se ha pre-poblado con algunos datos de muestra basados en el laboratorio con el que trabajaremos más adelante en este módulo cuando trabajemos en algunos ejercicios opcionales (¡pero muy recomendados!). También proporcionamos una copia de este cuaderno de Obsidian que se puede descargar desde `Resources` en la parte superior derecha de cualquier sección en este módulo. Una vez descargado y descomprimido, puedes abrir esto en una copia local de Obsidian seleccionando `Open folder as vault`. Instrucciones detalladas para crear o abrir una bóveda se pueden encontrar [aquí](https://help.obsidian.md/Getting+started/Create+a+vault).

---

## Onwards

Ahora que hemos entendido bien nuestra estructura de toma de notas y organización de carpetas, y qué tipos de evidencia mantener y no mantener, y qué registrar para nuestros informes, hablemos de los varios tipos de informes que nuestros clientes pueden solicitar según el tipo de engagement.
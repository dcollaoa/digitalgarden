Reportar es una parte esencial del proceso de *penetration testing*, pero si se maneja mal, puede volverse muy tedioso y propenso a errores. Un aspecto clave de la elaboración de informes es que debemos comenzar a construir nuestro informe desde el inicio. Esto comienza con nuestra estructura organizativa/configuración de toma de notas, pero hay momentos en los que podemos estar ejecutando un escaneo de descubrimiento largo donde podríamos completar partes del informe predefinidas como información de contacto, nombre del cliente, alcance, etc. Durante la prueba, podemos escribir nuestra *Attack Chain* y cada hallazgo con todas las evidencias requeridas para no tener que apresurarnos a recapturar evidencia después de que termine la evaluación. Trabajar a medida que avanzamos garantizará que nuestro informe no se apresure y regrese de QA con muchos cambios en rojo.

---

## Templates

Esto debería ser obvio, pero no deberíamos reinventar la rueda con cada informe que escribimos. Es mejor tener una plantilla de informe en blanco para cada tipo de evaluación que realizamos (¡incluso las más raras!). Si no estamos utilizando una herramienta de informes y solo trabajamos en el antiguo MS Word, siempre podemos construir una plantilla de informe con macros y marcadores de posición para completar algunos de los datos que completamos para cada evaluación. Debemos trabajar con plantillas en blanco cada vez y no solo modificar un informe de un cliente anterior, ya que podríamos arriesgarnos a dejar el nombre de otro cliente en el informe u otros datos que no coinciden con nuestro entorno actual. Este tipo de error nos hace ver como amateurs y es fácilmente evitable.

---

## MS Word Tips & Tricks

Microsoft Word puede ser una molestia para trabajar, pero hay varias maneras de hacerlo funcionar para nosotros y facilitar nuestras vidas. Aquí hay algunos consejos y trucos que hemos recopilado a lo largo de los años en el camino para convertirnos en expertos en MS Word. Primero, algunos comentarios:

- Los consejos y trucos aquí descritos son para Microsoft Word. Es posible que algunas de las mismas funcionalidades también existan en LibreOffice, pero tendrás que utilizar tu `[motor de búsqueda preferido]` para averiguar si es posible.
- Hazte un favor y usa Word para Windows, evitando explícitamente usar Word para Mac. Si quieres usar una Mac como tu plataforma de pruebas, obtén una VM de Windows en la que puedas hacer tus informes. Mac Word carece de algunas características básicas que tiene Windows Word, no hay Editor de VB (en caso de que necesites usar macros) y no puede generar PDFs de forma nativa que se vean y funcionen correctamente (recorta los márgenes y rompe todos los hipervínculos en la tabla de contenido), por nombrar algunas.

Hay muchas características avanzadas como el ajuste de fuentes que puedes usar para hacer tu documento más atractivo si lo deseas, pero nos centraremos en las cosas que mejoran la eficiencia y dejaremos que el lector (o su departamento de marketing) determinen preferencias cosméticas específicas.

Vamos a cubrir lo básico:

- `Font styles`

  - Deberías acercarte lo más posible a un documento sin "formateo directo". Lo que quiero decir con formateo directo es resaltar el texto y hacer clic en el botón para ponerlo en negrita, cursiva, subrayado, coloreado, resaltado, etc. "Pero pensé que acabas de decir que solo nos vamos a centrar en cosas que mejoren la eficiencia". Lo hacemos. Si usas estilos de fuente y descubres que pasaste por alto una configuración en uno de tus encabezados que estropea la colocación o cómo se ve, si actualizas el estilo en sí, se actualizan todas las instancias de ese estilo utilizadas en todo el documento en lugar de tener que actualizarlas manualmente las 45 veces que usaste tu encabezado aleatorio (e incluso entonces, podrías olvidar algunas).

- `Table styles`

  - Toma todo lo que acabo de decir sobre estilos de fuente y aplícalo a las tablas. El mismo concepto aquí. Hace que los cambios globales sean mucho más fáciles y promueve la consistencia en todo el informe. También generalmente hace que todos los que usan el documento sean menos miserables, tanto como autores como en QA.

- `Captions`

  - Usa la capacidad de subtítulos integrada (haga clic con el botón derecho en una imagen o tabla resaltada y seleccione "Insert Caption...") si estás poniendo subtítulos en cosas. Usar esta funcionalidad hará que los subtítulos se renumeren automáticamente si tienes que agregar o eliminar algo del informe, lo cual es un dolor de cabeza GIGANTE. Esto generalmente tiene un estilo de fuente incorporado que te permite controlar cómo se ven los subtítulos.

- `Page numbers`

  - Los números de página facilitan mucho referirse a áreas específicas del documento cuando se colabora con el cliente para responder preguntas o aclarar el contenido del informe (por ejemplo, "¿Qué significa el segundo párrafo de la página 12?"). Lo mismo ocurre con los clientes que trabajan internamente con sus equipos para abordar los hallazgos.

- `Table of Contents`

  - Una tabla de contenido es un componente estándar de un informe profesional. La ToC predeterminada probablemente esté bien, pero si quieres algo personalizado, como ocultar números de página o cambiar el tabulador, puedes seleccionar una ToC personalizada y ajustar la configuración.

- `List of Figures/Tables`

  - Es discutible si una lista de figuras o tablas debería estar en el informe. Este es el mismo concepto que una tabla de contenido, pero solo enumera las figuras o tablas en el informe. Estos se activan con los subtítulos, por lo que si no estás usando subtítulos en uno u otro, o en ambos, esto no funcionará.

- `Bookmarks`

  - Los marcadores se utilizan más comúnmente para designar lugares en el documento a los que puedes crear hipervínculos (como un apéndice con un encabezado personalizado). Si planeas usar macros para combinar plantillas, también puedes usar marcadores para designar secciones enteras que se pueden eliminar automáticamente del informe.

- `Custom Dictionary`

  - Puedes pensar en un diccionario personalizado como una extensión de la función AutoCorrect incorporada de Word. Si descubres que escribes mal las mismas palabras cada vez que escribes un informe o quieres evitar errores tipográficos embarazosos como escribir "pubic" en lugar de "public", puedes agregar estas palabras a un diccionario personalizado y Word las reemplazará automáticamente por ti. Desafortunadamente, esta función no sigue a la plantilla, por lo que las personas tendrán que configurar las suyas propias.

- `Language Settings`

  - Lo principal que quieres usar configuraciones de idioma personalizadas es probablemente aplicarlas al estilo de fuente que creaste para tu evidencia basada en código/terminal/texto (¿lo creaste, verdad?). Puedes seleccionar la opción para ignorar la revisión ortográfica y gramatical dentro de la configuración de idioma para este (o cualquier otro) estilo de fuente. Esto es útil porque después de construir un informe con muchas figuras y quieres ejecutar la herramienta de revisión ortográfica, no tendrás que hacer clic en ignorar un millón de veces para omitir todo lo que está en tus figuras.

- `Custom Bullet/Numbering`

  - Puedes configurar una numeración personalizada para numerar automáticamente cosas como tus hallazgos, apéndices y cualquier otra cosa que pueda beneficiarse de la numeración automática.

- `Quick Access Toolbar Setup`

  - Hay muchas opciones y funciones que puedes agregar a tu barra de herramientas de acceso rápido que deberías explorar a tu conveniencia para determinar cuán útiles serán para tu flujo de trabajo, pero enumeraremos algunas útiles aquí. Selecciona `File > Options > Quick Access Toolbar` para acceder a la configuración.
    - Back: Es bueno hacer clic en los hipervínculos que creas para asegurarte de que te llevan al lugar correcto en el documento. La parte molesta es volver a donde estabas cuando hiciste clic para seguir trabajando. Este botón se encarga de eso.
    - Undo/Redo: Esto solo es útil si no usas los atajos de teclado en su lugar.
    - Save: Nuevamente, útil si no usas el atajo de teclado en su lugar.
    - Más allá de esto, puedes configurar el desplegable "Choose commands from:" en "Commands Not in the Ribbon" para explorar las funciones que son más difíciles de realizar.

- `Useful Hotkeys`

  - F4 aplicará la última acción que realizaste nuevamente. Por ejemplo, si resaltas algún texto y le aplicas un estilo de fuente, puedes resaltar otra cosa a la que quieras aplicar el mismo estilo de fuente y simplemente presionar F4, lo cual hará lo mismo.
  - Si estás usando una ToC y listas de figuras y tablas, puedes presionar Ctrl+A para seleccionar todo y F9 para actualizarlas simultáneamente. Esto también actualizará otros "campos" en el documento y a veces no funciona como se planeó, así que úsalo bajo tu propio riesgo.
  - Uno más comúnmente conocido es Ctrl+S para guardar. Solo lo menciono aquí porque deberías hacerlo a menudo en caso de que Word se bloquee para no perder datos.
  - Si necesitas mirar dos áreas diferentes del informe simultáneamente y no quieres desplazarte de un lado a otro, puedes usar Ctrl+Alt+S para dividir la ventana en dos paneles.
  - Esto puede parecer tonto, pero si accidentalmente golpeas tu teclado y no tienes idea de dónde está tu cursor (o dónde insertaste algún carácter deshonesto o escribiste accidentalmente algo no profesional en tu informe en lugar de en Discord), puedes presionar Shift+F5 para mover el cursor a donde se realizó la última revisión.
  -

 Hay muchos más enumerados [aquí](https://support.microsoft.com/en-us/office/keyboard-shortcuts-in-word-95ef89dd-7142-4b50-afb2-f762f663ceb2), pero estos son los que he encontrado más útiles que no son obvios.

---

## Automation

Al desarrollar plantillas de informes, puedes llegar a un punto en el que tienes un documento razonablemente maduro pero no suficiente tiempo o presupuesto para adquirir una plataforma de informes automatizada. Se puede ganar mucha automatización a través de macros en documentos de MS Word. Necesitarás guardar tus plantillas como archivos .dotm, y necesitarás estar en un entorno de Windows para aprovechar al máximo esto (el Editor de VB de Word para Mac puede no existir). Algunas de las cosas más comunes que puedes hacer con macros son:

- Crear una macro que genere una ventana emergente para que ingreses piezas clave de información que luego se insertarán automáticamente en la plantilla del informe donde se designan variables de marcador de posición:
    - Nombre del cliente
    - Fechas
    - Detalles del alcance
    - Tipo de prueba
    - Nombres de entornos o aplicaciones
- Puedes combinar diferentes plantillas de informes en un solo documento y tener una macro que recorra y elimine secciones enteras (que designes a través de marcadores) que no pertenecen a un tipo particular de evaluación.
    - Esto facilita la tarea de mantener tus plantillas, ya que solo tienes que mantener una en lugar de muchas.
- También puedes automatizar tareas de control de calidad corrigiendo errores cometidos con frecuencia. Dado que escribir macros de Word es básicamente un lenguaje de programación en sí mismo (y podría ser un curso por sí solo), dejamos al lector el uso de recursos en línea para aprender cómo lograr estas tareas.

---

## Reporting Tools/Findings Database

Una vez que realices varias evaluaciones, notarás que muchos de los entornos que atacas están afectados por los mismos problemas. Si no tienes una base de datos de hallazgos, perderás una cantidad tremenda de tiempo reescribiendo el mismo contenido repetidamente y correrás el riesgo de introducir inconsistencias en tus recomendaciones y en la forma en que describes el hallazgo en sí. Si multiplicas estos problemas por un equipo completo, la calidad de tus informes variará enormemente de un consultor a otro. Como mínimo, deberías mantener un documento dedicado con versiones sanitizadas de tus hallazgos que puedas copiar/pegar en tus informes. Como se discutió anteriormente, debemos esforzarnos constantemente por personalizar los hallazgos para un entorno de cliente siempre que tenga sentido, pero tener hallazgos predefinidos ahorra mucho tiempo.

Sin embargo, vale la pena investigar y configurar una de las plataformas disponibles diseñadas para este propósito. Algunas son gratuitas y otras deben pagarse, pero es muy probable que se paguen solas rápidamente en la cantidad de tiempo y dolores de cabeza que ahorran si puedes permitirte la inversión inicial.

|**Free**|**Paid**|
|---|---|
|[Ghostwriter](https://github.com/GhostManager/Ghostwriter)|[AttackForge](https://attackforge.com/)|
|[Dradis](https://dradisframework.com/ce/)|[PlexTrac](https://plextrac.com/)|
|[Security Risk Advisors VECTR](https://github.com/SecurityRiskAdvisors/VECTR)|[Rootshell Prism](https://www.rootshellsecurity.net/why-prism/)|
|[WriteHat](https://github.com/blacklanternsecurity/writehat)||

---

## Misc Tips/Tricks

Aunque hemos cubierto algunos de estos en otras secciones del módulo, aquí hay una lista de consejos y trucos que deberías tener a mano:

- Intenta contar una historia con tu informe. ¿Por qué es importante que pudiste realizar Kerberoasting y romper un hash? ¿Cuál fue el impacto de las credenciales predeterminadas en la aplicación X?
    
- Escribe a medida que avanzas. No dejes la elaboración del informe hasta el final. Tu informe no necesita ser perfecto mientras pruebas, pero documentar tanto como puedas y de la manera más clara posible durante la prueba te ayudará a ser lo más completo posible y no perder cosas o recortar esquinas mientras te apresuras en el último día de la ventana de prueba.
    
- Mantente organizado. Mantén las cosas en orden cronológico para que sea más fácil trabajar con tus notas. Haz que tus notas sean claras y fáciles de navegar para que proporcionen valor y no te causen trabajo extra.
    
- Muestra tanta evidencia como sea posible sin ser demasiado verboso. Muestra suficientes capturas de pantalla/salida de comandos para demostrar claramente y reproducir los problemas, pero no agregues montones de capturas de pantalla adicionales o salida de comandos innecesarios que llenen el informe.
    
- Muestra claramente lo que se presenta en las capturas de pantalla. Usa una herramienta como [Greenshot](https://getgreenshot.org/) para agregar flechas/cuadros de colores a las capturas de pantalla y agrega explicaciones debajo de la captura de pantalla si es necesario. Una captura de pantalla es inútil si tu audiencia tiene que adivinar lo que estás tratando de mostrar con ella.
    
- Redacta datos sensibles siempre que sea posible. Esto incluye contraseñas en texto claro, hashes de contraseñas, otros secretos y cualquier dato que pueda considerarse sensible para nuestros clientes. Los informes pueden enviarse por toda una empresa e incluso a terceros, por lo que queremos asegurarnos de haber hecho nuestra debida diligencia para no incluir ningún dato en el informe que pueda ser mal utilizado. Una herramienta como `Greenshot` puede usarse para ocultar partes de una captura de pantalla (¡usando formas sólidas y no difuminado!).
    
- Redacta la salida de herramientas siempre que sea posible para eliminar elementos que las personas no técnicas puedan interpretar como no profesionales (es decir, `(Pwn3d!)` de la salida de CrackMapExec). En el caso de CME, puedes cambiar ese valor en tu archivo de configuración para que imprima algo más en la pantalla, para no tener que cambiarlo en tu informe cada vez. Otras herramientas pueden tener personalizaciones similares.
    
- Revisa tu salida de Hashcat para asegurarte de que ninguna de las contraseñas candidatas sea grosera. Muchas listas de palabras tendrán palabras que pueden considerarse groseras/ofensivas, y si alguna de estas está presente en la salida de Hashcat, cámbialas por algo inocuo. Puede que pienses, "dijeron que nunca alteráramos la salida de comandos." Los dos ejemplos anteriores son algunas de las pocas veces que está bien. Generalmente, si estamos modificando algo que puede interpretarse como ofensivo o no profesional pero no cambiamos la representación general de la evidencia del hallazgo, entonces estamos bien, pero tómalo caso por caso y plantea problemas como este a un gerente o líder de equipo si tienes dudas.
    
- Verifica la gramática, ortografía y formato, asegúrate de que las fuentes y tamaños de fuente sean consistentes y escribe las siglas la primera vez que las uses en un informe.
    
- Asegúrate de que las capturas de pantalla sean claras y no capturen partes adicionales de la pantalla que inflen su tamaño. Si tu informe es difícil de interpretar debido a un mal formato o la gramática y ortografía son un desastre, esto restará valor a los resultados técnicos de la evaluación. Considera una herramienta como Grammarly o LanguageTool (pero ten en cuenta que estas herramientas pueden enviar algunos de tus datos a la nube para "aprender"), que es mucho más poderosa que la revisión ortográfica y gramatical integrada de Microsoft Word.
    
- Usa la salida de comandos en bruto siempre que sea posible, pero cuando necesites capturar una consola, asegúrate de que no sea transparente y muestre tu fondo/u otras herramientas (esto se ve terrible). La consola debería ser de un negro sólido con un tema razonable (fondo negro, texto blanco o verde, no un tema multicolor loco que dará dolor de cabeza al lector). Tu cliente puede imprimir el informe, por lo que puedes considerar un fondo claro con texto oscuro para no arruinar el cartucho de su impresora.
    
- Mantén tu nombre de host y nombre de usuario profesional. No muestres capturas de pantalla con un indicador como `azzkicker@clientsmasher`.
    
- Establece un proceso de QA. Tu informe debería pasar por al menos una, pero preferiblemente dos rondas de QA (dos revisores además de ti mismo). Nunca deberíamos revisar nuestro propio trabajo (donde sea posible) y queremos crear el mejor entregable posible, así que presta atención al proceso de QA. Como mínimo, si eres independiente, deberías dormir sobre ello por una noche y revisarlo nuevamente. Alejarte del informe por un tiempo a veces puede ayudarte a ver cosas que pasaste por alto después de mirarlo durante mucho tiempo.
    
- Establece una guía de estilo y síguela, para que todos en tu equipo sigan un formato similar y los informes se vean consistentes en todas las evaluaciones.
    
- Usa guardado automático con tu herramienta de toma de notas y MS Word. No quieres perder horas de trabajo porque un programa se bloquee. También, haz copias de seguridad de tus notas y otros datos a medida que avanzas, y no almacenes todo en una sola VM. Las VM pueden fallar, por lo que deberías mover evidencia a una ubicación secundaria a medida que avanzas. Esta es una tarea que se puede y debe automatizar.
    
- Script y automatiza siempre que sea posible. Esto asegurará que tu trabajo sea consistente en todas las evaluaciones

 que realices y no pierdas tiempo en tareas repetidas en cada evaluación.
    

---

## Client Communication

Las habilidades de comunicación escrita y verbal son fundamentales para cualquier persona en un rol de *penetration testing*. Durante nuestros compromisos (desde el alcance hasta la entrega y revisión del informe final), debemos mantenernos en contacto constante con nuestros clientes y servir adecuadamente en nuestro rol de asesores de confianza. Están contratando a nuestra empresa y pagando mucho dinero para que identifiquemos problemas en sus redes, demos consejos de remediación y también para educar a su personal sobre los problemas que encontramos a través de nuestro informe entregable. Al comienzo de cada compromiso, deberíamos enviar un correo electrónico de notificación de inicio que incluya información como:

- Nombre del probador
- Descripción del tipo/alcance del compromiso
- Dirección IP de origen para las pruebas (IP pública para un host de ataque externo o la IP interna de nuestro host de ataque si estamos realizando una prueba de penetración interna)
- Fechas anticipadas para las pruebas
- Información de contacto principal y secundaria (correo electrónico y teléfono)

Al final de cada día, deberíamos enviar una notificación de detención para señalar el fin de las actividades de prueba. Este puede ser un buen momento para dar un resumen de alto nivel de los hallazgos (especialmente si el informe tendrá más de 20 hallazgos de alto riesgo) para que el informe no tome completamente por sorpresa al cliente. También podemos reiterar las expectativas para la entrega del informe en este momento. Deberíamos, por supuesto, estar trabajando en el informe a medida que avanzamos y no dejarlo 100% para el último momento, pero puede tomar unos días escribir toda la cadena de ataques, el resumen ejecutivo, los hallazgos, las recomendaciones y realizar controles de auto-QA. Después de esto, el informe debería pasar por al menos una ronda de QA interna (y las personas responsables de QA probablemente tengan muchas otras cosas que hacer), lo cual puede tomar algo de tiempo.

Las notificaciones de inicio y detención también dan al cliente una ventana para cuando tus escaneos y actividades de prueba estaban teniendo lugar en caso de que necesiten rastrear alguna alerta.

Aparte de estas comunicaciones formales, es bueno mantener un diálogo abierto con nuestros clientes y construir y fortalecer la relación de asesor de confianza. ¿Descubriste una subred externa adicional o un subdominio? Consulta con el cliente para ver si les gustaría agregarlo al alcance (dentro de lo razonable y siempre que no exceda el tiempo asignado para las pruebas). ¿Descubriste una inyección SQL de alto riesgo o una falla de ejecución remota de código en un sitio web externo? Detén las pruebas y notifica formalmente al cliente y pregunta cómo les gustaría proceder. ¿Un host parece caído desde el escaneo? Sucede, y es mejor ser franco al respecto que intentar ocultarlo. ¿Conseguiste privilegios de Domain Admin/Enterprise Admin? Informa al cliente en caso de que vean alertas y se pongan nerviosos o para que puedan preparar a su gerencia para el informe pendiente. Además, en este punto, hazles saber que seguirás probando y buscando otros caminos, pero pregúntales si hay algo más en lo que les gustaría que te enfoques o servidores/bases de datos que aún deberían ser limitados incluso con privilegios de DA que puedas atacar.

También deberíamos discutir la importancia de notas detalladas y registro de herramientas/producción de herramientas. Si tu cliente pregunta si golpeaste un host específico en el día X, deberías poder, sin lugar a dudas, proporcionar evidencia documentada de tus actividades exactas. Es terrible ser culpado por una interrupción, pero es aún peor si te culpan por una y no tienes evidencia concreta para demostrar que no fue resultado de tus pruebas.

Mantener estos consejos de comunicación en mente ayudará mucho a construir buena voluntad con tu cliente y ganar negocios repetidos e incluso referencias. Las personas quieren trabajar con otros que los traten bien y trabajen diligente y profesionalmente, así que este es tu momento para brillar. Con habilidades técnicas y de comunicación excelentes, ¡serás imparable!

---

## Presenting Your Report - The Final Product

Una vez que el informe esté listo, debe pasar por revisión antes de la entrega. Una vez entregado, es habitual proporcionar al cliente una reunión de revisión del informe para repasar todo el informe, solo los hallazgos, o responder preguntas que puedan tener.

#### QA Process

Un informe descuidado pondrá en duda todo sobre nuestra evaluación. Si nuestro informe es un desastre desorganizado, ¿es siquiera posible que hayamos realizado una evaluación exhaustiva? ¿Fuimos descuidados y dejamos un rastro de destrucción que el cliente tendrá que gastar tiempo que no tiene en limpiar? Asegurémonos de que nuestro entregable del informe sea un testimonio de nuestro conocimiento y trabajo duro obtenidos con esfuerzo en la evaluación y refleje adecuadamente ambos. El cliente no va a ver la mayor parte de lo que hiciste durante la evaluación.

`¡El informe es tu destacable y, honestamente, por lo que el cliente está pagando!`

Podrías haber ejecutado la cadena de ataques más compleja y genial en la historia de las cadenas de ataques, pero si no puedes plasmarlo en papel de una manera que alguien más pueda entender, puede que también nunca haya sucedido en absoluto.

Si es posible, cada informe debería pasar por al menos una ronda de QA por alguien que no sea el autor. Algunos equipos también pueden optar por dividir el proceso de QA en múltiples pasos (por ejemplo, QA para precisión técnica y luego QA para estilo y cosmética adecuada). Dependerá de ti, tu equipo o tu organización elegir el enfoque correcto que funcione para el tamaño de tu equipo. Si recién comienzas por tu cuenta y no tienes el lujo de que alguien más revise tu informe, recomendaría encarecidamente alejarte de él por un tiempo o dormir sobre él y revisarlo nuevamente al menos. Una vez que leas un documento 45 veces, comienzas a pasar por alto cosas. Este mini-reinicio puede ayudarte a detectar cosas que no viste después de haberlo estado mirando durante días.

Es una buena práctica incluir una lista de verificación de QA como parte de tu plantilla de informe (eliminarla una vez que el informe esté finalizado). Esto debería consistir en todas las comprobaciones que el autor debe realizar en cuanto a contenido y formato y cualquier otra cosa que puedas tener en tu guía de estilo. Esta lista probablemente crecerá con el tiempo a medida que tú y los procesos de tu equipo se refinan y aprenden cuáles son los errores que las personas son más propensas a cometer. ¡Asegúrate de revisar la gramática, la ortografía y el formato! Una herramienta como Grammarly o LanguageTool es excelente para `esto` (pero asegúrate de tener aprobación). No envíes un informe descuidado a QA porque puede ser devuelto para que lo arregles antes de que el revisor siquiera lo mire, y puede ser una pérdida costosa de tiempo para ti y para otros.

Una nota rápida sobre herramientas de corrección gramatical en línea: Como medio para "aprender" más y mejorar la precisión de la herramienta, estas a menudo enviarán piezas de lo que sea que estén leyendo de vuelta "a casa", lo que significa que si estás escribiendo un informe con datos confidenciales de vulnerabilidades del cliente, podrías estar violando algún tipo de MSA o algo sin saberlo. Antes de usar herramientas como esta, es importante investigar su funcionalidad y si este tipo de comportamiento se puede desactivar.

Si tienes acceso a alguien que pueda realizar QA y comienzas a implementar un proceso, puede que pronto descubras que a medida que el equipo crece y aumenta el número de informes producidos, las cosas pueden volverse difíciles de rastrear. A un nivel básico, una hoja de Google o un equivalente podría usarse para ayudar a asegurarse de que las cosas no se pierdan, pero si tienes muchas más personas (como consultores y PMs) y tienes acceso a una herramienta como Jira, eso podría ser una solución mucho más escalable. Probablemente necesitarás un lugar central para almacenar tus informes para que otras personas puedan acceder a ellos para realizar el proceso de QA. Hay muchos disponibles que funcionarían, pero elegir el mejor está fuera del alcance de este curso.

Idealmente, la persona que realiza el QA NO debería ser responsable de realizar modificaciones significativas en el informe. Si hay errores menores, de redacción o de formato que se puedan abordar más rápidamente que enviando el informe de vuelta al autor para que lo cambie, eso probablemente esté bien. Para la evidencia faltante o mal ilustrada, los hallazgos faltantes, el contenido del resumen ejecutivo inutilizable, etc., el autor debe asumir la responsabilidad de llevar ese documento a una condición presentable.

Obviamente, quieres ser diligente al revisar los cambios realizados en tu informe (¡activa Track Changes!) para que puedas dejar de cometer los mismos errores en informes posteriores. Es absolutamente una oportunidad de aprendizaje, así que no la desperdicies. Si es algo que sucede con varias personas, puede que quieras considerar agregar ese elemento a tu lista de verificación de QA para recordar a las personas que aborden esos problemas antes de enviar informes a QA. No hay muchos mejores sentimientos en esta carrera que el día en que un informe que escribiste pasa por QA sin ningún cambio.

Puede considerarse estrictamente una formalidad, pero es razonablemente común emitir inicialmente una copia "Draft" del informe al cliente una vez que se haya completado el proceso de QA. Una vez que el cliente tenga el informe preliminar, se debe esperar que lo revise y te informe si le gustaría una oportunidad para repasar el informe contigo para discutir modificaciones y hacer preguntas. Si es necesario hacer cambios o actualizaciones en el informe después de esta conversación,

 se pueden hacer en el informe y emitir una versión "Final". El informe final a menudo será idéntico al informe preliminar (si el cliente no tiene cambios que necesiten hacerse), pero solo dirá "Final" en lugar de "Draft". Puede parecer frívolo, pero algunos auditores solo considerarán aceptar un informe final como artefacto, por lo que podría ser bastante importante para algunos clientes.

---

## Report Review Meeting

Una vez que se haya entregado el informe, es bastante habitual dar al cliente una semana más o menos para revisar el informe, reunir sus pensamientos y ofrecer una llamada para revisarlo con ellos para recopilar cualquier comentario que tengan sobre tu trabajo. Por lo general, esta llamada cubre los detalles técnicos de los hallazgos uno por uno y permite al cliente hacer preguntas sobre lo que encontraste y cómo lo encontraste. Estas llamadas pueden ser inmensamente útiles para mejorar tu capacidad de presentar este tipo de datos, así que presta mucha atención a la conversación. Si te encuentras respondiendo las mismas preguntas cada vez, eso podría indicar que necesitas ajustar tu flujo de trabajo o la información que proporcionas para ayudar a responder esas preguntas antes de que el cliente las haga.

Una vez que el informe ha sido revisado y aceptado por ambas partes, es habitual cambiar la designación `DRAFT` a `FINAL` y entregar la copia final al cliente. A partir de aquí, deberíamos archivar todos nuestros datos de prueba según las políticas de retención de nuestra empresa hasta que se realice al menos una nueva prueba de hallazgos remediados.

---

## Wrap Up

Estos son solo algunos consejos y trucos que hemos recopilado a lo largo de los años. Muchos de estos son sentido común. Este [post](https://blackhillsinfosec.com/how-to-not-suck-at-reporting-or-how-to-write-great-pentesting-reports/) del increíble equipo de Black Hills Information Security vale la pena leerlo. El objetivo aquí es presentar el entregable más profesional posible mientras contamos una historia clara basada en nuestro arduo trabajo durante una evaluación técnica. Pon tu mejor pie adelante y crea un entregable del que puedas estar orgulloso. Pasaste muchas horas persiguiendo incansablemente el *Domain Admin*. Aplica ese mismo celo a tu informe y serás una estrella de rock. En las últimas secciones de este módulo, discutiremos oportunidades para practicar nuestras habilidades de documentación e informes.

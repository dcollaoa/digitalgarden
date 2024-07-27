## Attack Path Recap

Es una buena idea escribir tu ruta de ataque desde el principio hasta el final para ayudarte a visualizar el camino tomado y qué hallazgos destacar. Esto también ayuda a agregar al informe para resumir la cadena de ataque. Este resumen es una buena manera de asegurarse de no haber perdido nada crítico en la cadena desde el acceso inicial hasta la **domain compromise**. Este resumen solo debe mostrar el camino de menor resistencia y no incluir los pasos adicionales tomados o todo el proceso de pensamiento de las pruebas, ya que esto puede desordenar las cosas y dificultar su seguimiento.

Algunas formas de penetración estructuran su informe en forma narrativa, dando un recorrido paso a paso de cada acción realizada desde el principio hasta el final y destacando los hallazgos específicos a lo largo del camino. El enfoque aquí diferirá de una empresa a otra. Independientemente, es una buena idea tener esta lista a mano para ayudar con la redacción del informe, y si el cliente se comunica para preguntar cómo lograste X.

---

## Structuring our Findings

Idealmente, hemos anotado los hallazgos a medida que probamos, incluyendo la mayor cantidad posible de salidas de comandos y evidencia en nuestra herramienta de toma de notas. Esto debe hacerse de manera estructurada, por lo que es fácil de incorporar al informe. Si no hemos estado haciendo esto, debemos asegurarnos de tener una lista de hallazgos priorizados y todas las salidas de comandos necesarias y capturas de pantalla antes de perder acceso a la red interna o cesar cualquier prueba externa. No queremos estar en la posición de pedir al cliente que nos conceda acceso nuevamente para recopilar alguna evidencia o realizar escaneos adicionales. Debemos haber estructurado nuestra lista de hallazgos de `highest to lowest risk` mientras probamos porque esta lista puede ser muy útil para enviar al cliente al final de la prueba y es muy útil al redactar nuestro informe.

Para más información sobre toma de notas y redacción de informes, consulta el [Documentation & Reporting module](https://academy.hackthebox.com/module/162/section/1533). Vale la pena seguir los consejos de ese módulo para configurar tu entorno de prueba y toma de notas y abordar la red en este módulo (Attacking Enterprise Networks) como una prueba de penetración del mundo real, documentando y registrando todo lo que hacemos en el camino. También es una excelente práctica utilizar el informe de muestra del `Documentation & Reporting` module y crear un informe basado en esta red. Esta red tiene muchas oportunidades para practicar todos los aspectos de la documentación y redacción de informes.

---

## Post-Engagement Cleanup

Si esta fuera una evaluación real, deberíamos anotar:

- `Every scan`
- `Attack attempt`
- `File placed on a system`
- `Changes made` (cuentas creadas, cambios menores de configuración, etc.)

Antes de que se cierre la evaluación, deberíamos eliminar todos los archivos que subimos (herramientas, shells, payloads, notas) y restaurar todo a como lo encontramos. Independientemente de si pudimos limpiar todo, aún deberíamos anotar en los apéndices de nuestro informe cada cambio, archivo subido, compromiso de cuenta y compromiso de host, junto con los métodos utilizados. También deberíamos conservar nuestros registros y un registro detallado de actividades durante un período después de que termine la evaluación en caso de que el cliente necesite correlacionar alguna de nuestras actividades de prueba con algunas alertas. Tratar la red en este módulo como una red de cliente del mundo real. `Go back through a second time` y `pentest it as if it were an actual production network`, tomando acciones mínimamente invasivas, anotando todas las acciones que puedan requerir limpieza y `clean up after yourself at the end!` Este es un gran hábito para desarrollar.

---

## Client Communication

Necesitamos absolutamente informar al cliente cuando las pruebas hayan terminado para que sepan cuándo cualquier actividad anormal que puedan estar viendo ya no está relacionada con nuestras pruebas. También debemos mantener una comunicación clara durante la fase de redacción del informe, proporcionando al cliente una fecha de entrega precisa del informe y un breve resumen de nuestros hallazgos si lo solicita. En este momento, nuestro gerente o el Gerente de Proyecto puede estar contactando al cliente para programar una reunión de revisión del informe, a la que debemos esperar asistir para revisar los resultados de nuestras pruebas. Si la re-prueba es parte del **Scope of Work**, debemos trabajar con el cliente en un cronograma para que sus actividades de remediación se completen. Sin embargo, es posible que aún no tengan una idea, por lo que pueden contactarnos más adelante respecto a la prueba post-remediación. El cliente puede contactarnos periódicamente durante los próximos días o semanas para correlacionar alertas que recibieron, por lo que debemos tener nuestras notas y registros a mano en caso de que necesitemos justificar o aclarar cualquiera de nuestras acciones.

---

## Internal Project Closeout

Una vez que se haya entregado el informe y se haya completado la reunión de cierre, tu empresa realizará diversas actividades para cerrar el proyecto, tales como:

- Archivar el informe y los datos del proyecto asociados en una unidad compartida de la empresa
- Realizar un debriefing de lecciones aprendidas
- Posiblemente completar un cuestionario post-compromiso para el equipo de ventas
- Realizar tareas administrativas como la facturación

Si bien es mejor que el probador original realice las pruebas post-remediación, los horarios pueden no coincidir. Es posible que necesitemos hacer una transferencia de conocimiento interna a otro compañero de equipo. Ahora deberíamos sentarnos, pensar en lo que salió bien y en lo que podría mejorarse durante la evaluación, y prepararnos para la próxima.

---

## Next Steps

Ahora que has completado este módulo, vale la pena volver a pasar por el laboratorio sin la guía o con una orientación mínima para probar tus habilidades. Haz una lista de todas las habilidades y módulos asociados cubiertos en este laboratorio y revisa los temas con los que aún tienes problemas. Usa este laboratorio para perfeccionar tu oficio, probar diferentes herramientas y técnicas para completar el laboratorio, practicar la documentación y redacción de informes, e incluso preparar una presentación para un colega o amigo para practicar tus habilidades de presentación oral. La siguiente sección proporciona más información sobre los pasos adicionales que podemos tomar después de finalizar este módulo (y el camino). También puede que desees considerar trabajar en uno o más Pro Labs, los cuales también recomendamos abordar como un pentest para practicar tus habilidades de compromiso tanto como sea posible.
El password spraying puede resultar en obtener acceso a sistemas y potencialmente ganar una posición en una red objetivo. El ataque implica intentar iniciar sesión en un servicio expuesto utilizando una contraseña común y una lista más larga de nombres de usuario o direcciones de correo electrónico. Los nombres de usuario y correos electrónicos pueden haberse recopilado durante la fase de OSINT del penetration test o nuestros intentos iniciales de enumeración. Recuerda que un penetration test no es estático, sino que estamos iterando constantemente a través de varias técnicas y repitiendo procesos a medida que descubrimos nuevos datos. A menudo trabajaremos en equipo o ejecutando múltiples TTPs a la vez para utilizar nuestro tiempo de manera efectiva. A medida que avanzamos en nuestra carrera, encontraremos que muchas de nuestras tareas, como escanear, intentar crackear hashes y otras, toman bastante tiempo. Debemos asegurarnos de usar nuestro tiempo de manera efectiva y creativa porque la mayoría de las evaluaciones tienen un límite de tiempo. Así que, mientras nuestros intentos de poisoning están en marcha, también podemos utilizar la información que tenemos para intentar obtener acceso mediante password spraying. Ahora cubramos algunas de las consideraciones para el password spraying y cómo crear nuestra lista de objetivos a partir de la información que tenemos.

---

## Story Time

El password spraying puede ser una forma muy efectiva de obtener una posición interna. Hay muchas veces que esta técnica me ha ayudado a obtener una posición durante mis evaluaciones. Ten en cuenta que estos ejemplos provienen de evaluaciones "grey box" no evasivas donde tenía acceso a la red interna con una VM de Linux y una lista de rangos de IP dentro del alcance y nada más.

### Scenario 1

En este primer ejemplo, realicé todas mis verificaciones estándar y no pude encontrar nada útil como una sesión NULL de SMB o una vinculación anónima de LDAP que me permitiera recuperar una lista de usuarios válidos. Así que decidí usar la herramienta `Kerbrute` para construir una lista de nombres de usuario objetivo enumerando usuarios de dominio válidos (una técnica que cubriremos más adelante en esta sección). Para crear esta lista, tomé la lista de nombres de usuario `jsmith.txt` del repositorio de GitHub [statistically-likely-usernames](https://github.com/insidetrust/statistically-likely-usernames) y la combiné con los resultados que obtuve de scraping en LinkedIn. Con esta lista combinada en mano, enumeré usuarios válidos con `Kerbrute` y luego usé la misma herramienta para hacer password spraying con la contraseña común `Welcome1`. Obtuve dos aciertos con esta contraseña para usuarios con muy bajos privilegios, pero esto me dio suficiente acceso dentro del dominio para ejecutar BloodHound y eventualmente identificar rutas de ataque que llevaron a la comprometer el dominio.

### Scenario 2

En la segunda evaluación, me enfrenté a una configuración similar, pero enumerar usuarios de dominio válidos con listas de nombres de usuario comunes y resultados de LinkedIn no dio ningún resultado. Me dirigí a Google y busqué PDFs publicados por la organización. Mi búsqueda generó muchos resultados, y confirmé en las propiedades del documento de 4 de ellos que la estructura de nombre de usuario interno estaba en el formato de `F9L8`, GUIDs generados aleatoriamente utilizando solo letras mayúsculas y números (`A-Z y 0-9`). Esta información se publicó con el documento en el campo `Author` y muestra la importancia de limpiar los metadatos del documento antes de publicar algo en línea. A partir de aquí, se podría usar un pequeño script de Bash para generar 16,679,616 combinaciones de nombres de usuario posibles.

```bash
#!/bin/bash

for x in {{A..Z},{0..9}}{{A..Z},{0..9}}{{A..Z},{0..9}}{{A..Z},{0..9}}
    do echo $x;
done
```

Luego utilicé la lista de nombres de usuario generada con `Kerbrute` para enumerar cada cuenta de usuario en el dominio. Este intento de dificultar la enumeración de nombres de usuario terminó permitiéndome enumerar cada cuenta en el dominio debido al predecible GUID en uso combinado con los metadatos del PDF que pude localizar, lo que facilitó enormemente el ataque. Típicamente, solo puedo identificar del 40 al 60% de las cuentas válidas utilizando una lista como `jsmith.txt`. En este ejemplo, aumenté significativamente mis posibilidades de un ataque de password spraying exitoso al comenzar el ataque con TODAS las cuentas de dominio en mi lista de objetivos. A partir de aquí, obtuve contraseñas válidas para algunas cuentas. Finalmente, pude seguir una cadena de ataque complicada que involucraba [Resource-Based Constrained Delegation (RBCD)](https://posts.specterops.io/another-word-on-delegation-10bdbe3cd94a) y el ataque [Shadow Credentials](https://www.fortalicesolutions.com/posts/shadow-credentials-workstation-takeover-edition) para finalmente obtener control sobre el dominio.

---
## Password Spraying Considerations

Si bien el password spraying es útil para un penetration tester o red teamer, su uso descuidado puede causar un daño considerable, como bloquear cientos de cuentas de producción. Un ejemplo es un intento de fuerza bruta para identificar la contraseña de una cuenta utilizando una larga lista de contraseñas. En contraste, el password spraying es un ataque más medido, utilizando contraseñas muy comunes en múltiples industrias. La siguiente tabla visualiza un password spray.

### Password Spray Visualization

|**Attack**|**Username**|**Password**|
|---|---|---|
|1|bob.smith@inlanefreight.local|Welcome1|
|1|john.doe@inlanefreight.local|Welcome1|
|1|jane.doe@inlanefreight.local|Welcome1|
|DELAY|||
|2|bob.smith@inlanefreight.local|Passw0rd|
|2|john.doe@inlanefreight.local|Passw0rd|
|2|jane.doe@inlanefreight.local|Passw0rd|
|DELAY|||
|3|bob.smith@inlanefreight.local|Winter2022|
|3|john.doe@inlanefreight.local|Winter2022|
|3|jane.doe@inlanefreight.local|Winter2022|

Involucra enviar menos solicitudes de inicio de sesión por nombre de usuario y es menos probable que bloquee cuentas que un ataque de fuerza bruta. Sin embargo, el password spraying aún presenta un riesgo de bloqueos, por lo que es esencial introducir un retraso entre los intentos de inicio de sesión. El password spraying interno puede usarse para moverse lateralmente dentro de una red, y se aplican las mismas consideraciones con respecto a los bloqueos de cuentas. Sin embargo, puede ser posible obtener la política de contraseñas del dominio con acceso interno, reduciendo significativamente este riesgo.

Es común encontrar una política de contraseñas que permita cinco intentos fallidos antes de bloquear la cuenta, con un umbral de auto-desbloqueo de 30 minutos. Algunas organizaciones configuran umbrales de bloqueo de cuenta más largos, incluso requiriendo que un administrador desbloquee las cuentas manualmente. Si no conoces la política de contraseñas, una buena regla general es esperar unas pocas horas entre intentos, lo cual debería ser suficiente para que el umbral de bloqueo de cuenta se restablezca. Es mejor obtener la política de contraseñas antes de intentar el ataque durante una evaluación interna, pero esto no siempre es posible. Podemos pecar de cautelosos y optar por hacer solo un intento de password spraying dirigido utilizando una contraseña débil/común como "hail mary" si todas las demás opciones para obtener una posición o avanzar en el acceso se han agotado. Dependiendo del tipo de evaluación, siempre podemos pedir al cliente que aclare la política de contraseñas. Si ya tenemos una posición o se nos proporcionó una cuenta de usuario como parte de la prueba, podemos enumerar la política de contraseñas de varias maneras. Practiquemos esto en la siguiente sección.
Las configuraciones incorrectas suelen ocurrir cuando un administrador de sistemas, soporte técnico o desarrollador no configura correctamente el marco de seguridad de una aplicación, sitio web, escritorio o servidor, lo que lleva a caminos abiertos peligrosos para usuarios no autorizados. Exploremos algunas de las configuraciones incorrectas más típicas de los servicios comunes.

---

## Authentication

En años anteriores (aunque todavía vemos esto a veces durante las evaluaciones), era común que los servicios incluyeran credenciales predeterminadas (nombre de usuario y contraseña). Esto presenta un problema de seguridad porque muchos administradores dejan las credenciales predeterminadas sin cambios. Hoy en día, la mayoría del software pide a los usuarios que configuren credenciales durante la instalación, lo cual es mejor que las credenciales predeterminadas. Sin embargo, ten en cuenta que todavía encontraremos proveedores que usan credenciales predeterminadas, especialmente en aplicaciones más antiguas.

Incluso cuando el servicio no tiene un conjunto de credenciales predeterminadas, un administrador puede usar contraseñas débiles o ninguna contraseña al configurar servicios con la idea de que cambiarán la contraseña una vez que el servicio esté configurado y funcionando.

Como administradores, necesitamos definir políticas de contraseñas que se apliquen al software probado o instalado en nuestro entorno. Los administradores deben cumplir con una complejidad mínima de contraseña para evitar combinaciones de usuario y contraseñas como:

```r
admin:admin
admin:password
admin:<blank>
root:12345678
administrator:Password
```

Una vez que obtengamos el banner del servicio, el siguiente paso debe ser identificar posibles credenciales predeterminadas. Si no hay credenciales predeterminadas, podemos probar las combinaciones de nombre de usuario y contraseña débiles mencionadas anteriormente.

### Anonymous Authentication

Otra configuración incorrecta que puede existir en servicios comunes es la autenticación anónima. El servicio puede estar configurado para permitir la autenticación anónima, permitiendo que cualquier persona con conectividad de red acceda al servicio sin ser solicitada para autenticarse.

### Misconfigured Access Rights

Imaginemos que recuperamos credenciales para un usuario cuyo rol es cargar archivos en el servidor FTP, pero se le dio el derecho de leer todos los documentos FTP. Las posibilidades son infinitas, dependiendo de lo que haya dentro del servidor FTP. Podemos encontrar archivos con información de configuración para otros servicios, credenciales en texto plano, nombres de usuario, información propietaria e información de identificación personal (PII).

Los derechos de acceso mal configurados ocurren cuando las cuentas de usuario tienen permisos incorrectos. El problema mayor podría ser dar acceso a personas de menor rango a información privada que solo los gerentes o administradores deberían tener.

Los administradores necesitan planificar su estrategia de derechos de acceso, y existen algunas alternativas como [Role-based access control (RBAC)](https://en.wikipedia.org/wiki/Role-based_access_control), [Access control lists (ACL)](https://en.wikipedia.org/wiki/Access-control_list). Si queremos conocer más detalles sobre los pros y los contras de cada método, podemos leer [Choosing the best access control strategy](https://authress.io/knowledge-base/role-based-access-control-rbac) de Warren Parad de Authress.

---

## Unnecessary Defaults

La configuración inicial de dispositivos y software puede incluir, pero no se limita a configuraciones, características, archivos y credenciales. Esos valores predeterminados suelen estar orientados a la usabilidad en lugar de la seguridad. Dejarlo predeterminado no es una buena práctica de seguridad para un entorno de producción. Los valores predeterminados innecesarios son aquellos que necesitamos cambiar para asegurar un sistema reduciendo su superficie de ataque.

Podríamos entregar la información personal de nuestra empresa en bandeja de plata si tomamos el camino fácil y aceptamos las configuraciones predeterminadas al configurar software o un dispositivo por primera vez. En realidad, los atacantes pueden obtener credenciales de acceso para equipos específicos o abusar de una configuración débil realizando una breve búsqueda en internet.

[Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) es parte de la [OWASP Top 10 list](https://owasp.org/Top10/). Veamos aquellas relacionadas con valores predeterminados:

- Características innecesarias habilitadas o instaladas (por ejemplo, puertos, servicios, páginas, cuentas o privilegios innecesarios).
- Cuentas predeterminadas y sus contraseñas todavía habilitadas y sin cambios.
- El manejo de errores revela trazas de pila u otros mensajes de error excesivamente informativos a los usuarios.
- Para sistemas actualizados, las últimas características de seguridad están deshabilitadas o no configuradas de manera segura.

---

## Preventing Misconfiguration

Una vez que hayamos comprendido nuestro entorno, la estrategia más simple para controlar el riesgo es asegurar la infraestructura más crítica y solo permitir el comportamiento deseado. Cualquier comunicación que no sea requerida por el programa debe ser deshabilitada. Esto puede incluir cosas como:

- Las interfaces de administración deben estar deshabilitadas.
- La depuración debe estar desactivada.
- Deshabilitar el uso de nombres de usuario y contraseñas predeterminados.
- Configurar el servidor para prevenir el acceso no autorizado, la lista de directorios y otros problemas.
- Realizar escaneos y auditorías regularmente para ayudar a descubrir futuras configuraciones incorrectas o arreglos faltantes.

El OWASP Top 10 proporciona una sección sobre cómo asegurar los procesos de instalación:

- Un proceso de endurecimiento repetible hace que sea rápido y fácil desplegar otro entorno que esté apropiadamente asegurado. Los entornos de desarrollo, QA y producción deben estar configurados de manera idéntica, con diferentes credenciales utilizadas en cada entorno. Además, este proceso debe ser automatizado para minimizar el esfuerzo requerido para configurar un nuevo entorno seguro.

- Una plataforma mínima sin características, componentes, documentación y ejemplos innecesarios. Eliminar o no instalar características y marcos no utilizados.

- Una tarea para revisar y actualizar las configuraciones apropiadas a todas las notas de seguridad, actualizaciones y parches como parte del proceso de gestión de parches (ver A06:2021-Vulnerable and Outdated Components). Revisar los permisos de almacenamiento en la nube (por ejemplo, permisos de buckets S3).

- Una arquitectura de aplicación segmentada proporciona una separación efectiva y segura entre componentes o inquilinos, con segmentación, contenedorización o grupos de seguridad en la nube (ACLs).

- Enviar directivas de seguridad a los clientes, por ejemplo, encabezados de seguridad.

- Un proceso automatizado para verificar la efectividad de las configuraciones y ajustes en todos los entornos.
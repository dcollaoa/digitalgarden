Podemos configurar una serie de ajustes avanzados para Nessus y sus escaneos, como políticas de escaneo, plugins y credenciales, todos los cuales cubriremos en esta sección.

---

## Scan Policies

Nessus nos da la opción de crear políticas de escaneo. Esencialmente, estos son escaneos personalizados que nos permiten definir opciones de escaneo específicas, guardar la configuración de la política y tenerlas disponibles bajo `Scan Templates` al crear un nuevo escaneo. Esto nos da la capacidad de crear escaneos dirigidos para una variedad de escenarios, como un escaneo más lento y evasivo, un escaneo enfocado en la web o un escaneo para un cliente particular utilizando uno o varios conjuntos de credenciales. Las políticas de escaneo pueden ser importadas desde otros escáneres Nessus o exportadas para ser importadas posteriormente en otro escáner Nessus.

![image](https://academy.hackthebox.com/storage/modules/108/nessus/nessus_policies.png)

---

## Creating a Scan Policy

Para crear una política de escaneo, podemos hacer clic en el botón `New Policy` en la parte superior derecha, y se nos presentará la lista de escaneos preconfigurados. Podemos elegir un escaneo, como el `Basic Network Scan`, luego personalizarlo, o podemos crear el nuestro. Elegiremos `Advanced Scan` para crear un escaneo totalmente personalizado sin recomendaciones preconfiguradas.

Después de elegir el tipo de escaneo como base, podemos darle un nombre y una descripción a la política de escaneo si es necesario: ![image](https://academy.hackthebox.com/storage/modules/108/nessus/policy.png)

Desde aquí, podemos configurar ajustes, agregar cualquier credencial necesaria y especificar cualquier estándar de cumplimiento contra el cual ejecutar el escaneo. También podemos optar por habilitar o deshabilitar familias de plugins enteras o plugins individuales.

Una vez que hayamos terminado de personalizar el escaneo, podemos hacer clic en `Save`, y la política recién creada aparecerá en la lista de políticas. A partir de aquí, cuando vayamos a crear un nuevo escaneo, habrá una nueva pestaña llamada `User Defined` bajo `Scan Templates` que mostrará todas nuestras políticas de escaneo personalizadas: ![image](https://academy.hackthebox.com/storage/modules/108/nessus/htb_policydefined.png)

---

## Nessus Plugins

Nessus trabaja con plugins escritos en el [Nessus Attack Scripting Language (NASL)](https://en.wikipedia.org/wiki/Nessus_Attack_Scripting_Language) y puede dirigirse a nuevas vulnerabilidades y CVEs. Estos plugins contienen información como el nombre de la vulnerabilidad, el impacto, la remediación y una manera de probar la presencia de un problema particular.

Los plugins se califican por nivel de severidad: `Critical`, `High`, `Medium`, `Low`, `Info`. En el momento de escribir esto, Tenable ha publicado `145,973` plugins que cubren `58,391` IDs de CVE y `30,696` IDs de [Bugtraq](https://en.wikipedia.org/wiki/Bugtraq). Una base de datos buscable de todos los plugins publicados está en el [sitio web de Tenable](https://www.tenable.com/plugins).

La pestaña `Plugins` proporciona más información sobre una detección particular, incluida la mitigación. Al realizar escaneos recurrentes, puede haber una vulnerabilidad/detección que, tras una mayor examinación, no se considere un problema. Por ejemplo, Microsoft DirectAccess (una tecnología que proporciona conectividad a la red interna a los clientes a través de Internet) permite suites de cifrado inseguras y nulas. El siguiente escaneo realizado con `sslscan` muestra un ejemplo de suites de cifrado inseguras y nulas:

```r
sslscan example.com

<SNIP>

Preferred TLSv1.0  128 bits  ECDHE-RSA-AES128-SHA          Curve 25519 DHE 253
Accepted  TLSv1.0  256 bits  ECDHE-RSA-AES256-SHA          Curve 25519 DHE 253
Accepted  TLSv1.0  128 bits  DHE-RSA-AES128-SHA            DHE 2048 bits
Accepted  TLSv1.0  256 bits  DHE-RSA-AES256-SHA            DHE 2048 bits
Accepted  TLSv1.0  128 bits  AES128-SHA                   
Accepted  TLSv1.0  256 bits  AES256-SHA                   

<SNIP>
```

Sin embargo, esto es por diseño. SSL/TLS no es [requerido](https://directaccess.richardhicks.com/2014/09/23/directaccess-ip-https-ssl-and-tls-insecure-cipher-suites/) en este caso, y su implementación resultaría en un impacto negativo en el rendimiento. Para excluir este falso positivo de los resultados del escaneo mientras se mantiene la detección activa para otros hosts, podemos crear una regla de plugin: ![image](https://academy.hackthebox.com/storage/modules/108/nessus/plugin_rules.png)

Bajo la sección `Resources`, podemos seleccionar `Plugin Rules`. En la nueva regla de plugin, ingresamos el host a excluir, junto con el ID del plugin para Microsoft DirectAccess, y especificamos la acción a realizar como `Hide this result`: ![image](https://academy.hackthebox.com/storage/modules/108/nessus/new-rule.png)

También es posible que queramos excluir ciertos problemas de los resultados del escaneo, como plugins para problemas que no son directamente explotables (por ejemplo, [SSL Self-Signed Certificate](https://www.tenable.com/plugins/nessus/57582)). Podemos hacer esto especificando el ID del plugin y los hosts a excluir: ![image](https://academy.hackthebox.com/storage/modules/108/nessus/plugins2.png)

---

## Scanning with Credentials

Nessus también soporta escaneos con credenciales y proporciona mucha flexibilidad al soportar hashes LM/NTLM, autenticación Kerberos y autenticación por contraseña.

Las credenciales se pueden configurar para autenticación basada en host vía SSH con una contraseña, clave pública, certificado o autenticación basada en Kerberos. También se puede configurar para autenticación basada en host de Windows con una contraseña, Kerberos, hash LM o hash NTLM: ![image](https://academy.hackthebox.com/storage/modules/108/nessus/creds.png)

Nessus también soporta autenticación para una variedad de tipos de bases de datos, incluyendo Oracle, PostgreSQL, DB2, MySQL, SQL Server, MongoDB y Sybase: ![image](https://academy.hackthebox.com/storage/modules/108/nessus/db_creds.png)

**Nota:** Para ejecutar un escaneo con credenciales en el objetivo, utiliza las siguientes credenciales: `htb-student_adm`:`HTB_@cademy_student!` para Linux, y `administrator`:`Academy_VA_adm1!` para Windows. Estos escaneos ya han sido configurados en el objetivo de Nessus para ahorrarte tiempo.

Además de eso, Nessus puede realizar autenticación en texto claro para servicios como FTP, HTTP, IMAP, IPMI, Telnet y más: ![image](https://academy.hackthebox.com/storage/modules/108/nessus/plaintext_auth.png)

Finalmente, podemos revisar la salida de Nessus para confirmar si la autenticación a la aplicación o servicio objetivo con las credenciales proporcionadas fue exitosa: ![image](https://academy.hackthebox.com/storage/modules/108/nessus/sqlserv.png)
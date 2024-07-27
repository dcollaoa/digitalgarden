Podemos encontrar miles de subdominios y dominios en la web. A menudo apuntan a proveedores de servicios externos que ya no están activos, como AWS, GitHub y otros, y, en el mejor de los casos, muestran un mensaje de error como confirmación de un servicio de terceros desactivado. Las grandes empresas y corporaciones también se ven afectadas una y otra vez. Las empresas suelen cancelar servicios de proveedores externos, pero se olvidan de eliminar los registros DNS asociados. Esto se debe a que no se incurren en costos adicionales por una entrada DNS. Muchas plataformas de bug bounty bien conocidas, como [HackerOne](https://www.hackerone.com/), ya enumeran explícitamente `Subdomain Takeover` como una categoría de recompensas. Con una simple búsqueda, podemos encontrar varias herramientas en GitHub, por ejemplo, que automatizan el descubrimiento de subdominios vulnerables o ayudan a crear Proof of Concepts (`PoC`) que luego pueden enviarse al programa de bug bounty de nuestra elección o a la empresa afectada. RedHuntLabs realizó un [estudio](https://redhuntlabs.com/blog/project-resonance-wave-1.html) sobre esto en 2020, y encontraron que más de 400,000 subdominios de 220 millones eran vulnerables a subdomain takeover. El 62% de ellos pertenecían al sector del comercio electrónico.

### RedHuntLabs Study

![](https://i0.wp.com/redhuntlabs.com/wp-content/uploads/2020/11/image-3.png) Source: https://redhuntlabs.com/blog/project-resonance-wave-1.html

---

## The Concept of the Attack

Uno de los mayores peligros de un subdomain takeover es que se puede lanzar una campaña de phishing que se considera parte del dominio oficial de la empresa objetivo. Por ejemplo, los clientes verían el enlace y verían que el dominio `customer-drive.inlanefreight.com` (que apunta a un bucket S3 inexistente de AWS) está detrás del dominio oficial `inlanefreight.com` y lo confiarían como cliente. Sin embargo, los clientes no saben que esta página ha sido clonada o creada por un atacante para provocar un inicio de sesión por parte de los clientes de la empresa, por ejemplo.

Por lo tanto, si un atacante encuentra un registro `CNAME` en los registros DNS de la empresa que apunta a un subdominio que ya no existe y devuelve un `HTTP 404 error`, es probable que este subdominio pueda ser tomado por nosotros mediante el uso del proveedor de servicios externo. Un subdomain takeover ocurre cuando un subdominio apunta a otro dominio usando el registro CNAME que actualmente no existe. Cuando un atacante registra este dominio inexistente, el subdominio apunta al registro de dominio por nosotros. Al hacer un solo cambio DNS, nos convertimos en el propietario de ese subdominio en particular, y después de eso, podemos gestionar el subdominio como elijamos.

### The Concept of Attacks

![](https://academy.hackthebox.com/storage/modules/116/attack_concept2.png)

Lo que sucede aquí es que el subdominio existente ya no apunta a un proveedor de servicios externo y, por lo tanto, ya no está ocupado por este proveedor. Prácticamente cualquiera puede registrar este subdominio como propio. Visitar este subdominio y la presencia del registro CNAME en el DNS de la empresa conduce, en la mayoría de los casos, a que las cosas funcionen como se espera. Sin embargo, el diseño y la función de este subdominio están en manos del atacante.

### Initiation of Subdomain Takeover

|**Step**|**Subdomain Takeover**|**Concept of Attacks - Category**|
|---|---|---|
|`1.`|La fuente, en este caso, es el nombre del subdominio que ya no utiliza la empresa que descubrimos.|`Source`|
|`2.`|El registro de este subdominio en el sitio del proveedor de servicios externo se realiza registrándolo y vinculándolo a nuestras propias fuentes.|`Process`|
|`3.`|Aquí, los privilegios están con el propietario del dominio principal y sus entradas en sus servidores DNS. En la mayoría de los casos, el proveedor de servicios externo no es responsable de si este subdominio es accesible a través de otros.|`Privileges`|
|`4.`|El registro y la vinculación exitosos se realizan en nuestro servidor, que es el destino en este caso.|`Destination`|

Aquí es cuando el ciclo comienza de nuevo, pero esta vez para activar la redirección al servidor que controlamos.

### Trigger the Forwarding

|**Step**|**Subdomain Takeover**|**Concept of Attacks - Category**|
|---|---|---|
|`5.`|El visitante del subdominio ingresa la URL en su navegador, y el registro DNS desactualizado (CNAME) que no se ha eliminado se usa como fuente.|`Source`|
|`6.`|El servidor DNS busca en su lista para ver si tiene conocimiento sobre este subdominio y, si es así, el usuario se redirige al subdominio correspondiente (que controlamos nosotros).|`Process`|
|`7.`|Los privilegios para esto ya están con los administradores que gestionan el dominio, ya que solo ellos están autorizados a cambiar el dominio y sus servidores DNS. Dado que este subdominio está en la lista, el servidor DNS considera el subdominio como confiable y redirige al visitante.|`Privileges`|
|`8.`|El destino aquí es la persona que solicita la dirección IP del subdominio donde desean ser redirigidos a través de la red.|`Destination`|

El subdomain takeover se puede usar no solo para phishing, sino también para muchos otros ataques. Estos incluyen, por ejemplo, el robo de cookies, cross-site request forgery (CSRF), abuso de CORS y eludir la content security policy (CSP). Podemos ver algunos ejemplos de subdomain takeovers en el [sitio web de HackerOne](https://hackerone.com/hacktivity?querystring=%22subdomain%20takeover%22), que han generado considerables pagos a los cazadores de recompensas.
Se puede configurar un nuevo escaneo de Nessus haciendo clic en `New Scan` y seleccionando un tipo de escaneo. Las plantillas de escaneo se dividen en tres categorías: `Discovery`, `Vulnerabilities` y `Compliance`.

**Nota:** Los escaneos mostrados en esta sección ya se han ejecutado previamente para ahorrarte el tiempo de esperar a que terminen. Si vuelves a ejecutar el escaneo, es mejor revisar las vulnerabilidades a medida que aparecen, en lugar de esperar a que el escaneo termine, ya que pueden tardar entre 1-2 horas en completarse.

---

## New Scan

Aquí tenemos opciones para un escaneo básico de `Host Discovery` para identificar hosts vivos/puertos abiertos o una variedad de tipos de escaneo como `Basic Network Scan`, `Advanced Scan`, `Malware Scan`, `Web Application Tests`, así como escaneos dirigidos a CVEs específicos y estándares de auditoría y cumplimiento. Una descripción de cada tipo de escaneo se puede encontrar [aquí](https://docs.tenable.com/nessus/Content/ScanAndPolicyTemplates.htm).

![image](https://academy.hackthebox.com/storage/modules/108/nessus/nessus_scan_types.png)

Para los propósitos de este ejercicio, elegiremos la opción `Basic Network Scan`, y podemos ingresar nuestros objetivos: ![image](https://academy.hackthebox.com/storage/modules/108/nessus/general.png)

**Nota:** Para este módulo, el objetivo de Windows será `172.16.16.100` y el objetivo de Linux será `172.16.16.160`.

---

## Discovery

En la sección `Discovery`, bajo `Host Discovery`, se nos presenta la opción de habilitar el escaneo de dispositivos frágiles. Escanear dispositivos como impresoras de red a menudo resulta en que impriman hojas y hojas de papel con texto basura, dejando los dispositivos inutilizables. Podemos dejar esta configuración deshabilitada: ![image](https://academy.hackthebox.com/storage/modules/108/nessus/options.png)

En `Port Scanning`, podemos elegir si escanear puertos comunes, todos los puertos, o un rango definido por nosotros, dependiendo de nuestros requisitos: ![image](https://academy.hackthebox.com/storage/modules/108/nessus/discovery.png)

Dentro de la subsección `Service Discovery`, la opción `Probe all ports to find services` está seleccionada por defecto. Es posible que una aplicación o servicio mal diseñado pueda fallar como resultado de esta sondeo, pero la mayoría de las aplicaciones deberían ser lo suficientemente robustas para manejar esto. Buscar servicios SSL/TLS también está habilitado por defecto en un escaneo personalizado, y Nessus puede ser instruido adicionalmente para identificar certificados que estén por expirar y certificados revocados.

---

## Assessment

Bajo la categoría `Assessment`, también se puede habilitar el escaneo de aplicaciones web si es necesario, y se puede especificar un agente de usuario personalizado y varias otras opciones de escaneo de aplicaciones web (por ejemplo, una URL para pruebas de Remote File Inclusion (RFI)): ![image](https://academy.hackthebox.com/storage/modules/108/nessus/webapp.png)

Si se desea, Nessus puede intentar autenticar contra las aplicaciones y servicios descubiertos utilizando las credenciales proporcionadas (si se ejecuta un escaneo con credenciales), o puede realizar un ataque de fuerza bruta con las listas de nombres de usuario y contraseñas proporcionadas: ![image](https://academy.hackthebox.com/storage/modules/108/nessus/hydra.png)

La enumeración de usuarios también se puede realizar utilizando varias técnicas, como RID Brute Forcing: ![image](https://academy.hackthebox.com/storage/modules/108/nessus/userenum.png)

Si optamos por realizar RID Brute Forcing, podemos establecer los UIDs de inicio y fin para cuentas de usuario tanto de dominio como locales: ![image](https://academy.hackthebox.com/storage/modules/108/nessus/ridbf.png)

---
## Advanced

En la pestaña `Advanced`, las comprobaciones seguras están habilitadas por defecto. Esto impide que Nessus ejecute comprobaciones que puedan afectar negativamente al dispositivo o red objetivo. También podemos optar por ralentizar o limitar el escaneo si Nessus detecta alguna congestión en la red, dejar de intentar escanear cualquier host que se vuelva no responsivo, e incluso optar por que Nessus escanee nuestra lista de IPs objetivo en orden aleatorio: ![image](https://academy.hackthebox.com/storage/modules/108/nessus/advanced.png)
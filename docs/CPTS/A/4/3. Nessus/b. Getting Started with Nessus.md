Vamos a ver cómo podemos descargar y configurar Nessus para su primer uso para que podamos comenzar a aprender sus diversas características. Siéntete libre de seguir estos pasos y configurar una instancia de Nessus en tu propia VM. Para las partes interactivas de este módulo, proporcionamos una instancia de laboratorio de Nessus y otra con OpenVAS instalado.

---

## Downloading Nessus

Para descargar Nessus, podemos navegar a su [Página de Descarga](https://www.tenable.com/downloads/nessus?loginAttempted=true) para descargar el binario correcto de Nessus para nuestro sistema. Descargaremos el paquete Debian para `Ubuntu` para este tutorial. ![](https://academy.hackthebox.com/storage/modules/108/openvas/deb.png)

---

## Requesting Free License

A continuación, podemos visitar la [Página del Código de Activación](https://www.tenable.com/products/nessus/activation-code) para solicitar un Código de Activación de Nessus, que es necesario para obtener la versión gratuita de Nessus: ![](https://academy.hackthebox.com/storage/modules/108/nessus/register.png)

![](https://academy.hackthebox.com/storage/modules/108/nessus/registrationcode.png)

---

## Installing Package

Con el binario y el código de activación en mano, ahora podemos instalar el paquete de Nessus:

```r
dpkg -i Nessus-8.15.1-ubuntu910_amd64.deb

Selecting previously unselected package nessus.
(Reading database ... 132030 files and directories currently installed.)
Preparing to unpack Nessus-8.15.1-ubuntu910_amd64.deb ...
Unpacking nessus (8.15.1) ...
Setting up nessus (8.15.1) ...
Unpacking Nessus Scanner Core Components...
Created symlink /etc/systemd/system/nessusd.service → /lib/systemd/system/nessusd.service.
Created symlink /etc/systemd/system/multi-user.target.wants/nessusd.service → /lib/systemd/system/nessusd.service.
```

---

## Starting Nessus

Una vez que hemos instalado Nessus, podemos iniciar el servicio de Nessus:

```r
sudo systemctl start nessusd.service
```

---
## Accessing Nessus

Para acceder a Nessus, podemos navegar a `https://localhost:8834`. Una vez que lleguemos a la página de configuración, debemos seleccionar `Nessus Essentials` para la versión gratuita, y luego podemos ingresar nuestro código de activación: ![](https://academy.hackthebox.com/storage/modules/108/nessus/essentials.png)

Una vez que ingresemos nuestro código de activación, podemos configurar un usuario con una contraseña `segura` para nuestra cuenta de Nessus. Luego, los plugins comenzarán a compilar una vez que este paso esté completado: ![](https://academy.hackthebox.com/storage/modules/108/nessus/init.png)

**Nota:** La VM proporcionada en la sección `Nessus Skills Assessment` tiene Nessus preinstalado y los objetivos en ejecución. Puedes ir a esa sección y arrancar la VM y usar Nessus a lo largo del módulo, el cual puede ser accesado en `https://< IP >:8834`. Las credenciales de Nessus son: `htb-student`:`HTB_@cademy_student!`. También puedes usar estas credenciales para hacer SSH en la VM objetivo para configurar Nessus.

Finalmente, una vez completada la configuración, podemos empezar a crear escaneos, políticas de escaneo, reglas de plugins y personalizar configuraciones. La página de `Settings` tiene una gran cantidad de opciones como configurar un Proxy Server o un servidor SMTP, opciones estándar de gestión de cuentas y configuraciones avanzadas para personalizar la interfaz de usuario, escaneo, registro, rendimiento y opciones de seguridad.

![image](https://academy.hackthebox.com/storage/modules/108/nessus/nessus_settings.png)

Ambos Burp y ZAP están disponibles para Windows, macOS y cualquier distribución de Linux. Ambos ya están instalados en tu instancia de PwnBox y se pueden acceder desde el dock inferior o el menú de la barra superior. Estas herramientas vienen preinstaladas en distribuciones de Linux comunes para Penetration Testing como Parrot o Kali. En esta sección, cubriremos el proceso de instalación y configuración para Burp y ZAP, lo cual será útil si deseamos instalar las herramientas en nuestra propia VM.

---
## **Burp Suite**

Si Burp no está preinstalado en nuestra VM, podemos comenzar descargándolo desde [Burp's Download Page](https://portswigger.net/burp/releases/). Una vez descargado, podemos ejecutar el instalador y seguir las instrucciones, que varían según el sistema operativo, pero deberían ser bastante sencillas. Hay instaladores para Windows, Linux y macOS.

Una vez instalado, Burp puede ser lanzado desde el terminal escribiendo `burpsuite`, o desde el menú de aplicaciones como se mencionó anteriormente. Otra opción es descargar el archivo `JAR` (que se puede usar en todos los sistemas operativos con un Java Runtime Environment (JRE) instalado) desde la página de descargas anterior. Podemos ejecutarlo con la siguiente línea de comando o haciendo doble clic en él:

```r
java -jar </path/to/burpsuite.jar>
```

**Nota**: Tanto Burp como ZAP dependen de Java Runtime Environment para ejecutarse, pero este paquete debería estar incluido en el instalador por defecto. Si no, podemos seguir las instrucciones encontradas en esta [página](https://docs.oracle.com/goldengate/1212/gg-winux/GDRAD/java.htm).

Una vez que iniciemos Burp, se nos pedirá que creemos un nuevo proyecto. Si estamos ejecutando la versión comunitaria, solo podremos usar proyectos temporales sin la capacidad de guardar nuestro progreso y continuar más tarde:

![Burp Community Project](https://academy.hackthebox.com/storage/modules/110/burp_project_community.jpg)

Si estamos usando la versión pro/enterprise, tendremos la opción de iniciar un nuevo proyecto o abrir un proyecto existente.

![Burp Pro Project](https://academy.hackthebox.com/storage/modules/110/burp_project_prof.jpg)

Es posible que necesitemos guardar nuestro progreso si estamos realizando pentesting en aplicaciones web grandes o ejecutando un `Active Web Scan`. Sin embargo, puede que no necesitemos guardar nuestro progreso y, en muchos casos, podemos iniciar un proyecto `temporal` cada vez.

Así que, seleccionemos `temporary project` y hagamos clic en continuar. Una vez hecho esto, se nos pedirá que usemos `Burp Default Configurations` o que `Load a Configuration File`, y elegiremos la primera opción:

![Burp Project Config](https://academy.hackthebox.com/storage/modules/110/burp_project_config.jpg)

Una vez que comencemos a utilizar intensamente las funciones de Burp, es posible que queramos personalizar nuestras configuraciones y cargarlas al iniciar Burp. Por ahora, podemos mantener `Use Burp Defaults` y `Start Burp`. Una vez hecho todo esto, deberíamos estar listos para comenzar a usar Burp.

---

## **ZAP**

Podemos descargar ZAP desde su [download page](https://www.zaproxy.org/download/), elegir el instalador que se ajuste a nuestro sistema operativo y seguir las instrucciones básicas de instalación para instalarlo. ZAP también se puede descargar como un archivo JAR multiplataforma y lanzarlo con el comando `java -jar` o haciendo doble clic en él, de manera similar a Burp.

Para comenzar con ZAP, podemos lanzarlo desde el terminal con el comando `zaproxy` o acceder a él desde el menú de aplicaciones como Burp. Una vez que ZAP se inicia, a diferencia de la versión gratuita de Burp, se nos pedirá que creemos un nuevo proyecto o un proyecto temporal. Usemos un proyecto temporal eligiendo `no`, ya que no estaremos trabajando en un proyecto grande que necesitaremos persistir durante varios días:

![ZAP New Config](https://academy.hackthebox.com/storage/modules/110/zap_new_project.jpg)

Después de eso, tendremos ZAP en funcionamiento y podemos continuar con el proceso de configuración del proxy, como discutiremos en la siguiente sección.

Tip: Si prefieres usar un tema oscuro, puedes hacerlo en Burp yendo a (`User Options>Display`) y seleccionando "dark" bajo (`theme`), y en ZAP yendo a (`Tools>Options>Display`) y seleccionando "Flat Dark" en (`Look and Feel`).
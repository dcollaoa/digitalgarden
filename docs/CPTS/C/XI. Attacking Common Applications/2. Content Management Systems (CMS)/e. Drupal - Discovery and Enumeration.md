[Drupal](https://www.drupal.org/), lanzado en 2001, es el tercer y último CMS que cubriremos en nuestro recorrido por el mundo de las aplicaciones comunes. Drupal es otro CMS de código abierto que es popular entre empresas y desarrolladores. Drupal está escrito en PHP y soporta el uso de MySQL o PostgreSQL para el backend. Adicionalmente, se puede usar SQLite si no hay un DBMS instalado. Al igual que WordPress, Drupal permite a los usuarios mejorar sus sitios web mediante el uso de temas y módulos. Al momento de escribir esto, el proyecto Drupal tiene cerca de 43,000 módulos y 2,900 temas y es el tercer CMS más popular por cuota de mercado. Aquí hay algunas [estadísticas](https://websitebuilder.org/blog/drupal-statistics/) interesantes sobre Drupal recopiladas de varias fuentes:

- Alrededor del 1.5% de los sitios en internet usan Drupal (¡más de 1.1 millones de sitios!), 5% de los principales 1 millón de sitios web en internet, y 7% de los principales 10,000 sitios.
- Drupal representa alrededor del 2.4% del mercado de CMS.
- Está disponible en 100 idiomas.
- Drupal es orientado a la comunidad y tiene más de 1.3 millones de miembros.
- Drupal 8 fue construido por 3,290 colaboradores, 1,288 empresas, y con la ayuda de la comunidad.
- 33 de las empresas Fortune 500 usan Drupal de alguna manera.
- 56% de los sitios web gubernamentales en todo el mundo usan Drupal.
- 23.8% de las universidades, colegios y escuelas usan Drupal en todo el mundo.
- Algunas marcas importantes que usan Drupal incluyen: Tesla y Warner Bros Records.

Según el [sitio web](https://www.drupal.org/project/usage/drupal) de Drupal, hay alrededor de 950,000 instancias de Drupal en uso al momento de escribir (distribuidas desde la versión 5.x hasta la versión 9.3.x, a partir del 5 de septiembre de 2021). Como podemos ver en estas estadísticas, el uso de Drupal se ha mantenido estable entre 900,000 y 1.1 millones de instancias entre junio de 2013 y septiembre de 2021. Estas estadísticas no cuentan `TODAS` las instancias de Drupal en uso en todo el mundo, sino las instancias que ejecutan el módulo [Update Status](https://www.drupal.org/project/update_status), que se conecta diariamente con drupal.org para buscar nuevas versiones de Drupal o actualizaciones de los módulos en uso.

---

## Discovery/Footprinting

Durante un test de penetración externo, encontramos lo que parece ser un CMS, pero sabemos a partir de una revisión superficial que el sitio no está ejecutando WordPress o Joomla. Sabemos que los CMS suelen ser objetivos "jugosos", así que investiguemos este y veamos qué podemos descubrir.

Un sitio web Drupal se puede identificar de varias maneras, incluyendo el mensaje de encabezado o pie de página `Powered by Drupal`, el logotipo estándar de Drupal, la presencia de un archivo `CHANGELOG.txt` o `README.txt`, a través del código fuente de la página, o pistas en el archivo robots.txt como referencias a `/node`.

```r
curl -s http://drupal.inlanefreight.local | grep Drupal

<meta name="Generator" content="Drupal 8 (https://www.drupal.org)" />
      <span>Powered by <a href="https://www.drupal.org">Drupal</a></span>
```

Otra forma de identificar un CMS Drupal es a través de [nodes](https://www.drupal.org/docs/8/core/modules/node/about-nodes). Drupal indexa su contenido usando nodes. Un node puede contener cualquier cosa, como una entrada de blog, encuesta, artículo, etc. Los URIs de la página suelen tener la forma `/node/<nodeid>`.

`http://drupal.inlanefreight.local/node/1`

![drupal_node](https://academy.hackthebox.com/storage/modules/113/drupal_node.png)

Por ejemplo, la entrada de blog anterior se encuentra en `/node/1`. Esta representación es útil para identificar un sitio web Drupal cuando se usa un tema personalizado.

Nota: No todas las instalaciones de Drupal se verán iguales o mostrarán la página de inicio de sesión o incluso permitirán a los usuarios acceder a la página de inicio de sesión desde internet.

Drupal admite tres tipos de usuarios por defecto:

1. `Administrator`: Este usuario tiene control total sobre el sitio web de Drupal.
2. `Authenticated User`: Estos usuarios pueden iniciar sesión en el sitio web y realizar operaciones como agregar y editar artículos según sus permisos.
3. `Anonymous`: Todos los visitantes del sitio web se designan como anónimos. Por defecto, estos usuarios solo pueden leer publicaciones.

---

## Enumeration

Una vez que hemos descubierto una instancia de Drupal, podemos hacer una combinación de enumeración manual y basada en herramientas (automática) para descubrir la versión, plugins instalados y más. Dependiendo de la versión de Drupal y cualquier medida de endurecimiento que se haya implementado, es posible que debamos intentar varias formas de identificar el número de versión. Las instalaciones más nuevas de Drupal por defecto bloquean el acceso a los archivos `CHANGELOG.txt` y `README.txt`, por lo que es posible que debamos hacer más enumeración. Veamos un ejemplo de cómo enumerar el número de versión usando el archivo `CHANGELOG.txt`. Para hacerlo, podemos usar `cURL` junto con `grep`, `sed`, `head`, etc.

```r
curl -s http://drupal-acc.inlanefreight.local/CHANGELOG.txt | grep -m2 ""

Drupal 7.57, 2018-02-21
```

Aquí hemos identificado una versión antigua de Drupal en uso. Probando esto contra la última versión de Drupal al momento de escribir, obtenemos una respuesta 404.

```r
curl -s http://drupal.inlanefreight.local/CHANGELOG.txt

<!DOCTYPE html><html><head><title>404 Not Found</title></head><body><h1>Not Found</h1><p>The requested URL "http://drupal.inlanefreight.local/CHANGELOG.txt" was not found on this server.</p></body></html>
```

Hay varias otras cosas que podríamos verificar en esta instancia para identificar la versión. Probemos con un escaneo usando `droopescan` como se muestra en la sección de enumeración de Joomla. `Droopescan` tiene mucha más funcionalidad para Drupal que para Joomla.

Ejecutemos un escaneo contra el host `http://drupal.inlanefreight.local`.

```r
droopescan scan drupal -u http://drupal.inlanefreight.local

[+] Plugins found:                                                              
    php http://drupal.inlanefreight.local/modules/php/
        http://drupal.inlanefreight.local/modules/php/LICENSE.txt

[+] No themes found.

[+] Possible version(s):
    8.9.0
    8.9.1

[+] Possible interesting urls found:
    Default admin - http://drupal.inlanefreight.local/user/login

[+] Scan finished (0:03:19.199526 elapsed)
```

Esta instancia parece estar ejecutando la versión `8.9.1` de Drupal. Al momento de escribir, esta no era la última ya que se lanzó en junio de 2020. Una búsqueda rápida de [vulnerabilidades](https://www.cvedetails.com/vulnerability-list/vendor_id-1367/product_id-2387/Drupal-Drupal.html) relacionadas con Drupal no muestra nada aparente para esta versión principal de Drupal. En este caso, lo siguiente sería investigar los plugins instalados o abusar de la funcionalidad incorporada.
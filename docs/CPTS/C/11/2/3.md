[Joomla](https://www.joomla.org/), lanzado en agosto de 2005, es otro CMS gratuito y de código abierto utilizado para foros de discusión, galerías de fotos, e-Commerce, comunidades basadas en usuarios y más. Está escrito en PHP y utiliza MySQL en el backend. Al igual que WordPress, Joomla puede ser mejorado con más de 7,000 extensiones y más de 1,000 plantillas. Hay hasta 2.5 millones de sitios en internet que ejecutan Joomla. Aquí hay algunas [estadísticas](https://websitebuilder.org/blog/joomla-statistics/) interesantes sobre Joomla:

- Joomla representa el 3.5% de la cuota de mercado de CMS
- Joomla es 100% gratuito y significa "todos juntos" en swahili (ortografía fonética de "Jumla")
- La comunidad de Joomla tiene cerca de 700,000 en sus foros en línea
- Joomla impulsa el 3% de todos los sitios web en internet, casi 25,000 de los principales 1 millón de sitios en todo el mundo (solo el 10% del alcance de WordPress)
- Algunas organizaciones notables que usan Joomla incluyen eBay, Yamaha, Harvard University y el gobierno del Reino Unido
- A lo largo de los años, 770 desarrolladores diferentes han contribuido a Joomla

Joomla recopila algunas [estadísticas de uso](https://developer.joomla.org/about/stats.html) anónimas, como la distribución de las versiones de Joomla, PHP y bases de datos, y los sistemas operativos de servidor utilizados en las instalaciones de Joomla. Estos datos pueden ser consultados a través de su [API pública](https://developer.joomla.org/about/stats/api.html).

Consultando esta API, podemos ver más de 2.7 millones de instalaciones de Joomla!



```r
curl -s https://developer.joomla.org/stats/cms_version | python3 -m json.tool

{
    "data": {
        "cms_version": {
            "3.0": 0,
            "3.1": 0,
            "3.10": 3.49,
            "3.2": 0.01,
            "3.3": 0.02,
            "3.4": 0.05,
            "3.5": 13,
            "3.6": 24.29,
            "3.7": 8.5,
            "3.8": 18.84,
            "3.9": 30.28,
            "4.0": 1.52,
            "4.1": 0
        },
        "total": 2776276
    }
}
```

---

## Discovery/Footprinting

Supongamos que nos encontramos con un sitio de e-commerce durante una prueba de penetración externa. A primera vista, no estamos exactamente seguros de qué se está ejecutando, pero no parece ser completamente personalizado. Si podemos identificar qué está ejecutando el sitio, es posible que podamos descubrir vulnerabilidades o configuraciones erróneas. Basándonos en la información limitada, asumimos que el sitio está ejecutando Joomla, pero debemos confirmar ese hecho y luego averiguar el número de versión y otra información como temas y plugins instalados.

A menudo podemos identificar Joomla mirando el código fuente de la página, lo que nos dice que estamos tratando con un sitio Joomla.



```r
curl -s http://dev.inlanefreight.local/ | grep Joomla

	<meta name="generator" content="Joomla! - Open Source Content Management" />
```


El archivo `robots.txt` para un sitio Joomla a menudo se verá así:



```r
# If the Joomla site is installed within a folder
# eg www.example.com/joomla/ then the robots.txt file
# MUST be moved to the site root
# eg www.example.com/robots.txt
# AND the joomla folder name MUST be prefixed to all of the
# paths.
# eg the Disallow rule for the /administrator/ folder MUST
# be changed to read
# Disallow: /joomla/administrator/
#
# For more information about the robots.txt standard, see:
# https://www.robotstxt.org/orig.html

User-agent: *
Disallow: /administrator/
Disallow: /bin/
Disallow: /cache/
Disallow: /cli/
Disallow: /components/
Disallow: /includes/
Disallow: /installation/
Disallow: /language/
Disallow: /layouts/
Disallow: /libraries/
Disallow: /logs/
Disallow: /modules/
Disallow: /plugins/
Disallow: /tmp/
```

También podemos ver a menudo el favicon característico de Joomla (aunque no siempre). Podemos identificar la versión de Joomla si el archivo `README.txt` está presente.



```r
curl -s http://dev.inlanefreight.local/README.txt | head -n 5

1- What is this?
	* This is a Joomla! installation/upgrade package to version 3.x
	* Joomla! Official site: https://www.joomla.org
	* Joomla! 3.9 version history - https://docs.joomla.org/Special:MyLanguage/Joomla_3.9_version_history
	* Detailed changes in the Changelog: https://github.com/joomla/joomla-cms/commits/staging
```

En ciertas instalaciones de Joomla, podemos identificar la versión a partir de archivos JavaScript en el directorio `media/system/js/` o navegando a `administrator/manifests/files/joomla.xml`.



```r
curl -s http://dev.inlanefreight.local/administrator/manifests/files/joomla.xml | xmllint --format -

<?xml version="1.0" encoding="UTF-8"?>
<extension version="3.6" type="file" method="upgrade">
  <name>files_joomla</name>
  <author>Joomla! Project</author>
  <authorEmail>admin@joomla.org</authorEmail>
  <authorUrl>www.joomla.org</authorUrl>
  <copyright>(C) 2005 - 2019 Open Source Matters. All rights reserved</copyright>
  <license>GNU General Public License version 2 or later; see LICENSE.txt</license>
  <version>3.9.4</version>
  <creationDate>March 2019</creationDate>
  
 <SNIP>
```

El archivo `cache.xml` puede ayudarnos a dar una versión aproximada. Se encuentra en `plugins/system/cache/cache.xml`.

---

## Enumeration

Vamos a probar [droopescan](https://github.com/droope/droopescan), un escáner basado en plugins que funciona para SilverStripe, WordPress y Drupal con funcionalidad limitada para Joomla y Moodle.

Podemos clonar el repositorio de Git y instalarlo manualmente o instalarlo vía `pip`.



```r
sudo pip3 install droopescan

Collecting droopescan
  Downloading droopescan-1.45.1-py2.py3-none-any.whl (514 kB)
     |████████████████████████████████| 514 kB 5.8 MB/s
	 
<SNIP>
```

Una vez completada la instalación, podemos confirmar que la herramienta está funcionando ejecutando `droopescan -h`.



```r
droopescan -h

usage: droopescan (sub-commands ...) [options ...] {arguments ...}

    |
 ___| ___  ___  ___  ___  ___  ___  ___  ___  ___
|   )|   )|   )|   )|   )|___)|___ |    |   )|   )
|__/ |    |__/ |__/ |__/ |__   __/ |__  |__/||  /
                    |
=================================================

commands:

  scan
    cms scanning functionality.

  stats
    shows scanner status & capabilities.

optional arguments:
  -h, --help  show this help message and exit
  --debug     toggle debug output
  --quiet     suppress all output

Example invocations: 
  droopescan scan drupal -u URL_HERE
  droopescan scan silverstripe -u URL_HERE

More info: 
  droopescan scan --help
 
Please see the README file for information regarding proxies.
```

Podemos acceder a un menú de ayuda más detallado escribiendo `droopescan scan --help`.

Vamos a ejecutar un escaneo y ver qué resultados obtenemos.



```r
droopescan scan joomla --url http://dev.inlanefreight.local/

[+] Possible version(s):                                                        
    3.8.10
    3.8.11
    3.8.11-rc
    3.8.12
    3.8.12-rc
    3.8.13
    3.8.7
    3.8.7-rc
    3.8.8
    3.8.8-rc
    3.8.9
    3.8.9-rc

[+] Possible interesting urls found:
    Detailed version information. - http://dev.inlanefreight.local/administrator/manifests/files/joomla.xml
    Login page. - http://dev.inlanefreight.local/administrator/
    License file. - http://dev.inlanefreight.local/LICENSE.txt
    Version attribute contains approx version - http://dev.inlanefreight.local/plugins/system/cache/cache.xml

[+] Scan finished (0:00:01.523369 elapsed)


```

Como podemos ver, no arrojó mucha información aparte del posible número de versión. También podemos probar [JoomlaScan](https://github.com/drego85/JoomlaScan), que es una herramienta en Python inspirada en la ahora desaparecida herramienta [joomscan](https://github.com/OWASP/joomscan) de OWASP. `JoomlaScan` está un poco desactualizada y requiere Python2.7 para ejecutarse. Podemos hacer que funcione asegurándonos primero de que algunas dependencias estén instaladas.



```r
sudo python2.7 -m pip install urllib3
sudo python2.7 -m pip install certifi
sudo python2.7 -m pip install bs4
```

Aunque un poco desactualizada, puede ser útil en nuestra enumeración. Vamos a ejecutar un escaneo.



```r
python2.7 joomlascan.py -u http://dev.inlanefreight.local

-------------------------------------------
      	     Joomla Scan                  
   Usage: python joomlascan.py <target>    
    Version 0.5beta - Database Entries 1233
         created by Andrea Draghetti       
-------------------------------------------
Robots file found: 	 	 > http://dev.inlanefreight.local/robots.txt
No Error Log found

Start scan...with 10 concurrent threads!
Component found: com_actionlogs	 > http://dev.inlanefreight.local/index.php?option=com_actionlogs
	 On the administrator components
Component found: com_admin	 > http://dev.inlanefreight.local/index.php?option=com_admin
	 On the administrator components
Component found: com_ajax	 > http://dev.inlanefreight.local/index.php?option=com_ajax
	 But possibly it is not active or protected
	 LICENSE file found 	 > http://dev.inlanefreight.local/administrator/components/com_actionlogs/actionlogs.xml
	 LICENSE file found 	 > http://dev.inlanefreight.local/administrator/components/com_admin/admin.xml
	 LICENSE file found 	 > http://dev.inlanefreight.local/administrator/components/com_ajax/ajax.xml
	 Explorable Directory 	 > http://dev.inlanefreight.local/components/com_actionlogs/
	 Explorable Directory 	 > http://dev.inlanefreight.local/administrator/components/com_actionlogs/
	 Explorable Directory 	 > http://dev.inlanefreight.local/components/com_admin/
	 Explorable Directory 	 > http://dev.inlanefreight.local/administrator/components/com_admin/
Component found: com_banners	 > http://dev.inlanefreight.local/index.php?option=com_banners
	 But possibly it is not active or protected
	 Explorable Directory 	 > http://dev.inlanefreight.local/components/com_ajax/
	 Explorable Directory 	 > http://dev.inlanefreight.local/administrator/components/com_ajax/
	 LICENSE file found 	 > http://dev.inlanefreight.local/administrator/components/com_banners/banners.xml


<SNIP>
```

Aunque no es tan valiosa como droopescan, esta herramienta puede ayudarnos a encontrar directorios y archivos accesibles y puede ayudar a identificar extensiones instaladas. En este punto, sabemos que estamos tratando con Joomla `3.9.4`. El portal de inicio de sesión del administrador se encuentra en `http://dev.inlanefreight.local/administrator/index.php`. Los intentos de enumeración de usuarios devuelven un mensaje de error genérico.



```r
Warning
Username and password do not match or you do not have an account yet.
```

La cuenta de administrador predeterminada en las instalaciones de Joomla es `admin`, pero la contraseña se establece en el momento de la instalación, por lo que la única forma en que podemos esperar ingresar al back-end de administración es si la cuenta tiene una contraseña muy débil/común y podemos ingresar con algunas conjeturas o fuerza bruta ligera. Podemos usar este [script](https://github.com/ajnik/joomla-bruteforce) para intentar forzar la contraseña.



```r
sudo python3 joomla-brute.py -u http://dev.inlanefreight.local -w /usr/share/metasploit-framework/data/wordlists/http_default_pass.txt -usr admin
 
admin:admin
```

Y obtenemos un acierto con las credenciales `admin:admin`. ¡Alguien no ha estado siguiendo las mejores prácticas!
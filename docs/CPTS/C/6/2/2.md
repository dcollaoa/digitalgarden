Ahora que entendemos los diferentes tipos de XSS y varios métodos para descubrir vulnerabilidades de XSS en las páginas web, podemos empezar a aprender cómo explotar estas vulnerabilidades de XSS. Como se mencionó anteriormente, el daño y el alcance de un ataque de XSS dependen del tipo de XSS, siendo un stored XSS el más crítico, mientras que un DOM-based XSS es menos grave.

Uno de los ataques más comunes que se suele utilizar con las vulnerabilidades de stored XSS es el de defacing de sitios web. `Defacing` un sitio web significa cambiar su apariencia para cualquiera que visite el sitio web. Es muy común que los grupos de hackers defacen un sitio web para reclamar que lo han hackeado con éxito, como cuando los hackers defacearon el UK National Health Service (NHS) [en 2018](https://www.bbc.co.uk/news/technology-43812539). Tales ataques pueden tener un gran eco mediático y pueden afectar significativamente las inversiones y los precios de las acciones de una empresa, especialmente para los bancos y las firmas de tecnología.

Aunque muchas otras vulnerabilidades pueden ser utilizadas para lograr lo mismo, las vulnerabilidades de stored XSS están entre las más utilizadas para hacerlo.

---

## Defacement Elements

Podemos utilizar código JavaScript inyectado (a través de XSS) para hacer que una página web se vea como queramos. Sin embargo, defacear un sitio web generalmente se usa para enviar un mensaje simple (es decir, te hackeamos con éxito), por lo que darle un aspecto hermoso a la página defaceada no es realmente el objetivo principal.

Tres elementos HTML se utilizan generalmente para cambiar la apariencia principal de una página web:

- Background Color `document.body.style.background`
- Background `document.body.background`
- Page Title `document.title`
- Page Text `DOM.innerHTML`

Podemos utilizar dos o tres de estos elementos para escribir un mensaje básico en la página web e incluso eliminar el elemento vulnerable, de manera que sea más difícil restablecer rápidamente la página web, como veremos a continuación.

---

## Changing Background

Volvamos a nuestro ejercicio de `Stored XSS` y utilicémoslo como base para nuestro ataque. Puedes volver a la sección de `Stored XSS` para iniciar el servidor y seguir los siguientes pasos.

Para cambiar el fondo de una página web, podemos elegir un color determinado o usar una imagen. Usaremos un color como nuestro fondo ya que la mayoría de los ataques de defacing usan un color oscuro para el fondo. Para hacerlo, podemos usar el siguiente payload:


```r
<script>document.body.style.background = "#141d2b"</script>
```

Tip: Aquí configuramos el color de fondo al color de fondo predeterminado de Hack The Box. Podemos usar cualquier otro valor hexadecimal, o usar un color nombrado como `= "black"`.

Una vez que agreguemos nuestro payload a la lista de `To-Do`, veremos que el color de fondo ha cambiado:

   
`http://SERVER_IP:PORT/`

![](https://academy.hackthebox.com/storage/modules/103/xss_defacing_background_color.jpg)

Esto será persistente a través de las actualizaciones de la página y aparecerá para cualquiera que visite la página, ya que estamos utilizando una vulnerabilidad de stored XSS.

Otra opción sería configurar una imagen como fondo usando el siguiente payload:


```r
<script>document.body.background = "https://www.hackthebox.eu/images/logo-htb.svg"</script>
```

Prueba usando el payload anterior para ver cómo puede verse el resultado final.

---

## Changing Page Title

Podemos cambiar el título de la página de `2Do` a cualquier título de nuestra elección, usando la función JavaScript `document.title`:


```r
<script>document.title = 'HackTheBox Academy'</script>
```

Podemos ver desde la ventana/pestaña de la página que nuestro nuevo título ha reemplazado al anterior:

   

![](https://academy.hackthebox.com/storage/modules/103/xss_defacing_page_title.jpg)

---

## Changing Page Text

Cuando queremos cambiar el texto mostrado en la página web, podemos utilizar varias funciones de JavaScript para hacerlo. Por ejemplo, podemos cambiar el texto de un elemento HTML específico/DOM usando la función `innerHTML`:


```r
document.getElementById("todo").innerHTML = "New Text"
```

También podemos utilizar funciones de jQuery para lograr lo mismo de manera más eficiente o para cambiar el texto de múltiples elementos en una línea (para hacerlo, la biblioteca `jQuery` debe haber sido importada dentro del código fuente de la página):


```r
$("#todo").html('New Text');
```

Esto nos da varias opciones para personalizar el texto en la página web y hacer ajustes menores para satisfacer nuestras necesidades. Sin embargo, como los grupos de hackers generalmente dejan un mensaje simple en la página web y no dejan nada más en ella, cambiaremos todo el código HTML del `body` principal, usando `innerHTML`, de la siguiente manera:


```r
document.getElementsByTagName('body')[0].innerHTML = "New Text"
```

Como podemos ver, podemos especificar el elemento `body` con `document.getElementsByTagName('body')`, y al especificar `[0]`, estamos seleccionando el primer elemento `body`, lo que debería cambiar todo el texto de la página web. También podemos usar `jQuery` para lograr lo mismo. Sin embargo, antes de enviar nuestro payload y hacer un cambio permanente, debemos preparar nuestro código HTML por separado y luego usar `innerHTML` para configurar nuestro código HTML en el código fuente de la página.

Para nuestro ejercicio, tomaremos prestado el código HTML de la página principal de `Hack The Box Academy`:


```r
<center>
    <h1 style="color: white">Cyber Security Training</h1>
    <p style="color: white">by 
        <img src="https://academy.hackthebox.com/images/logo-htb.svg" height="25px" alt="HTB Academy">
    </p>
</center>
```

**Tip:** Sería prudente probar nuestro código HTML localmente para ver cómo se ve y asegurarnos de que se ejecuta como se espera, antes de comprometernos con él en nuestro payload final.

Minificaremos el código HTML en una sola línea y lo agregaremos a nuestro payload de XSS anterior. El payload final debería ser el siguiente:


```r
<script>document.getElementsByTagName('body')[0].innerHTML = '<center><h1 style="color: white">Cyber Security Training</h1><p style="color: white">by <img src="https://academy.hackthebox.com/images/logo-htb.svg" height="25px" alt="HTB Academy"> </p></center>'</script>
```

Una vez que agreguemos nuestro payload a la lista vulnerable de `To-Do`, veremos que nuestro código HTML ahora es parte permanente del código fuente de la página web y muestra nuestro mensaje para cualquiera que visite la página:

`http://SERVER_IP:PORT/`

![](https://academy.hackthebox.com/storage/modules/103/xss_defacing_change_text.jpg)

Usando tres payloads de XSS, pudimos defacear exitosamente nuestra página web objetivo. Si miramos el código fuente de la página web, veremos que el código fuente original todavía existe, y nuestros payloads inyectados aparecen al final:


```r
<div></div><ul class="list-unstyled" id="todo"><ul>
<script>document.body.style.background = "#141d2b"</script>
</ul><ul><script>document.title = 'HackTheBox Academy'</script>
</ul><ul><script>document.getElementsByTagName('body')[0].innerHTML = '...SNIP...'</script>
</ul></ul>
```

Esto se debe a que nuestro código JavaScript inyectado cambia la apariencia de la página cuando se ejecuta, lo cual en este caso, es al final del código fuente. Si nuestra inyección estuviera en un elemento en el medio del código fuente, entonces otros scripts o elementos podrían agregarse después de ella, por lo que tendríamos que tenerlos en cuenta para obtener la apariencia final que necesitamos.

Sin embargo, para los usuarios comunes, la página parece defaceada y muestra nuestra nueva apariencia.
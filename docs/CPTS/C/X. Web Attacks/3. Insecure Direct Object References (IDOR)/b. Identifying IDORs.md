## URL Parameters & APIs

El primer paso para explotar vulnerabilidades IDOR es identificar los Direct Object References. Cada vez que recibimos un archivo o recurso específico, debemos estudiar las solicitudes HTTP para buscar parámetros de URL o APIs con una referencia de objeto (por ejemplo, `?uid=1` o `?filename=file_1.pdf`). Estos se encuentran mayormente en los parámetros de URL o APIs, pero también pueden encontrarse en otros encabezados HTTP, como cookies.

En los casos más básicos, podemos intentar incrementar los valores de las referencias de objeto para recuperar otros datos, como (`?uid=2`) o (`?filename=file_2.pdf`). También podemos usar una aplicación de fuzzing para intentar miles de variaciones y ver si devuelven algún dato. Cualquier acierto exitoso en archivos que no sean nuestros indicaría una vulnerabilidad IDOR.

---

## AJAX Calls

También podemos identificar parámetros o APIs no utilizados en el código front-end en forma de llamadas AJAX de JavaScript. Algunas aplicaciones web desarrolladas en frameworks de JavaScript pueden colocar de manera insegura todas las llamadas a funciones en el front-end y usar las apropiadas según el rol del usuario.

Por ejemplo, si no tenemos una cuenta de administrador, solo se usarían las funciones a nivel de usuario, mientras que las funciones de administrador estarían deshabilitadas. Sin embargo, aún podemos encontrar las funciones de administrador si miramos el código JavaScript del front-end y podemos identificar llamadas AJAX a puntos finales o APIs que contienen referencias directas de objetos. Si identificamos referencias directas de objetos en el código JavaScript, podemos probarlas para vulnerabilidades IDOR.

Esto no es exclusivo de las funciones de administrador, por supuesto, sino que también puede aplicarse a cualquier función o llamada que no se encuentre monitoreando las solicitudes HTTP. El siguiente ejemplo muestra un ejemplo básico de una llamada AJAX:


```r
function changeUserPassword() {
    $.ajax({
        url:"change_password.php",
        type: "post",
        dataType: "json",
        data: {uid: user.uid, password: user.password, is_admin: is_admin},
        success:function(result){
            //
        }
    });
}
```

La función anterior puede que nunca se llame cuando usamos la aplicación web como un usuario no administrador. Sin embargo, si la encontramos en el código front-end, podemos probarla de diferentes maneras para ver si podemos llamarla para realizar cambios, lo que indicaría que es vulnerable a IDOR. Podemos hacer lo mismo con el código back-end si tenemos acceso a él (por ejemplo, aplicaciones web de código abierto).

---

## Understand Hashing/Encoding

Algunas aplicaciones web pueden no usar números secuenciales simples como referencias de objeto, sino que pueden codificar la referencia o en su lugar cifrarla. Si encontramos tales parámetros usando valores codificados o cifrados, aún podemos explotarlos si no hay un sistema de control de acceso en el back-end.

Supongamos que la referencia fue codificada con un codificador común (por ejemplo, `base64`). En ese caso, podríamos decodificarla y ver el texto plano de la referencia del objeto, cambiar su valor y luego codificarlo nuevamente para acceder a otros datos. Por ejemplo, si vemos una referencia como (`?filename=ZmlsZV8xMjMucGRm`), podemos adivinar inmediatamente que el nombre del archivo está codificado en `base64` (por su conjunto de caracteres), que podemos decodificar para obtener la referencia de objeto original (`file_123.pdf`). Luego, podemos intentar codificar una referencia de objeto diferente (por ejemplo, `file_124.pdf`) y tratar de acceder a ella con la referencia de objeto codificada (`?filename=ZmlsZV8xMjQucGRm`), lo que puede revelar una vulnerabilidad IDOR si pudiéramos recuperar algún dato.

Por otro lado, la referencia del objeto puede estar cifrada, como (`download.php?filename=c81e728d9d4c2f636f067f89cc14862c`). A primera vista, podemos pensar que esta es una referencia de objeto segura, ya que no está usando ningún texto claro o codificación fácil. Sin embargo, si miramos el código fuente, podemos ver qué se está cifrando antes de que se haga la llamada a la API:


```r
$.ajax({
    url:"download.php",
    type: "post",
    dataType: "json",
    data: {filename: CryptoJS.MD5('file_1.pdf').toString()},
    success:function(result){
        //
    }
});
```

En este caso, podemos ver que el código usa el `filename` y lo cifra con `CryptoJS.MD5`, lo que nos facilita calcular el `filename` para otros archivos potenciales. De lo contrario, podemos intentar identificar manualmente el algoritmo de cifrado que se está utilizando (por ejemplo, con herramientas de identificación de hash) y luego cifrar el nombre del archivo para ver si coincide con el hash utilizado. Una vez que podamos calcular hashes para otros archivos, podemos intentar descargarlos, lo que puede revelar una vulnerabilidad IDOR si podemos descargar cualquier archivo que no nos pertenezca.

---

## Compare User Roles

Si queremos realizar ataques IDOR más avanzados, podemos necesitar registrar múltiples usuarios y comparar sus solicitudes HTTP y referencias de objetos. Esto puede permitirnos entender cómo se están calculando los parámetros de URL y los identificadores únicos, y luego calcularlos para otros usuarios para recopilar sus datos.

Por ejemplo, si tuviéramos acceso a dos usuarios diferentes, uno de los cuales puede ver su salario después de hacer la siguiente llamada a la API:


```r
{
  "attributes" : 
    {
      "type" : "salary",
      "url" : "/services/data/salaries/users/1"
    },
  "Id" : "1",
  "Name" : "User1"

}
```

El segundo usuario puede que no tenga todos estos parámetros de API para replicar la llamada y no debería poder hacer la misma llamada que `User1`. Sin embargo, con estos detalles en mano, podemos intentar repetir la misma llamada a la API mientras estamos conectados como `User2` para ver si la aplicación web devuelve algo. Tales casos pueden funcionar si la aplicación web solo requiere una sesión válida iniciada para hacer la llamada a la API pero no tiene control de acceso en el back-end para comparar la sesión del llamador con los datos solicitados.

Si este es el caso, y podemos calcular los parámetros de la API para otros usuarios, esto sería una vulnerabilidad IDOR. Incluso si no pudiéramos calcular los parámetros de la API para otros usuarios, aún habríamos identificado una vulnerabilidad en el sistema de control de acceso del back-end y podríamos comenzar a buscar otras referencias de objeto para explotar.
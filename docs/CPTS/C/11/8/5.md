Varios frameworks ofrecen útiles características de **mass-assignment** para reducir la carga de trabajo de los desarrolladores. Debido a esto, los programadores pueden insertar directamente un conjunto completo de datos ingresados por el usuario desde un formulario en un objeto o base de datos. Esta característica se usa a menudo sin una whitelist para proteger los campos de la entrada del usuario. Esta vulnerabilidad podría ser utilizada por un atacante para robar información sensible o destruir datos.

La vulnerabilidad de **Web mass assignment** es un tipo de vulnerabilidad de seguridad donde los atacantes pueden modificar los atributos del modelo de una aplicación a través de los parámetros enviados al servidor. Revirtiendo el código, los atacantes pueden ver estos parámetros y, al asignar valores a parámetros críticos no protegidos durante la solicitud HTTP, pueden editar los datos de una base de datos y cambiar la funcionalidad prevista de una aplicación.

**Ruby on Rails** es un framework de aplicaciones web que es vulnerable a este tipo de ataque. El siguiente ejemplo muestra cómo los atacantes pueden explotar la vulnerabilidad de **mass assignment** en Ruby on Rails. Asumamos que tenemos un modelo `User` con los siguientes atributos:

```r
class User < ActiveRecord::Base
  attr_accessible :username, :email
end
```

El modelo anterior especifica que solo los atributos `username` y `email` están permitidos para ser asignados en masa. Sin embargo, los atacantes pueden modificar otros atributos manipulando los parámetros enviados al servidor. Supongamos que el servidor recibe los siguientes parámetros:

```r
{ "user" => { "username" => "hacker", "email" => "hacker@example.com", "admin" => true } }
```

Aunque el modelo `User` no indica explícitamente que el atributo `admin` sea accesible, el atacante aún puede cambiarlo porque está presente en los argumentos. **Bypassing** cualquier control de acceso que pueda estar en su lugar, el atacante puede enviar estos datos como parte de una solicitud POST al servidor para establecer un usuario con privilegios de administrador.

---

## Exploiting Mass Assignment Vulnerability

Supongamos que encontramos la siguiente aplicación que presenta una aplicación web de Asset Manager. También supongamos que se nos ha proporcionado el código fuente de la aplicación. Completando el paso de registro, recibimos el mensaje `Success!!`, y podemos intentar iniciar sesión.

![pending](https://academy.hackthebox.com/storage/modules/113/mass_assignment/pending.png)

Después de iniciar sesión, recibimos el mensaje `Account is pending approval`. El administrador de esta aplicación web debe aprobar nuestro registro. Revisando el código python del archivo `/opt/asset-manager/app.py` revela el siguiente fragmento:

```r
for i,j,k in cur.execute('select * from users where username=? and password=?',(username,password)):
  if k:
    session['user']=i
    return redirect("/home",code=302)
  else:
    return render_template('login.html',value='Account is pending for approval')
```

Podemos ver que la aplicación está comprobando si el valor `k` está establecido. Si es así, permite que el usuario inicie sesión. En el código a continuación, también podemos ver que si establecemos el parámetro `confirmed` durante el registro, entonces inserta `cond` como `True` y nos permite omitir el paso de verificación del registro.

```r
try:
  if request.form['confirmed']:
    cond=True
except:
      cond=False
with sqlite3.connect("database.db") as con:
  cur = con.cursor()
  cur.execute('select * from users where username=?',(username,))
  if cur.fetchone():
    return render_template('index.html',value='User exists!!')
  else:
    cur.execute('insert into users values(?,?,?)',(username,password,cond))
    con.commit()
    return render_template('index.html',value='Success!!')
```

En ese caso, lo que debemos intentar es registrar otro usuario e intentar establecer el parámetro `confirmed` a un valor aleatorio. Usando **Burp Suite**, podemos capturar la solicitud HTTP POST a la página `/register` y establecer los parámetros `username=new&password=test&confirmed=test`.

![mass_hidden](https://academy.hackthebox.com/storage/modules/113/mass_assignment/mass_hidden.png)

Ahora podemos intentar iniciar sesión en la aplicación usando las credenciales `new:test`.

![loggedin](https://academy.hackthebox.com/storage/modules/113/mass_assignment/loggedin.png)

La vulnerabilidad de **mass assignment** se explota con éxito y ahora estamos conectados a la aplicación web sin esperar a que el administrador apruebe nuestra solicitud de registro.

---

## Prevention

Para prevenir este tipo de ataque, se deben asignar explícitamente los atributos para los campos permitidos, o usar métodos de whitelist proporcionados por el framework para verificar los atributos que pueden ser asignados en masa. El siguiente ejemplo muestra cómo usar **strong parameters** en el controlador `User`.

```r
class UsersController < ApplicationController
  def create
    @user = User.new(user_params)
    if @user.save
      redirect_to @user
    else
      render 'new'
    end
  end

  private

  def user_params
    params.require(:user).permit(:username, :email)
  end
end
```

En el ejemplo anterior, el método `user_params` devuelve un nuevo hash que incluye solo los atributos `username` y `email`, ignorando cualquier otra entrada que el cliente haya podido enviar. Al hacer esto, nos aseguramos de que solo los atributos explícitamente permitidos puedan ser cambiados mediante **mass assignment**.
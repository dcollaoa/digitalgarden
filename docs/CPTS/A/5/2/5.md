Como pentesters, a menudo obtenemos acceso a datos altamente sensibles, como listas de usuarios, credenciales (por ejemplo, descargando el archivo NTDS.dit para crackeo de contraseñas offline) y datos de enumeración que pueden contener información crítica sobre la infraestructura de red de la organización y el entorno de Active Directory (AD). Por lo tanto, es esencial encriptar estos datos o usar conexiones de datos encriptadas, como SSH, SFTP y HTTPS. Sin embargo, a veces estas opciones no están disponibles, y se requiere un enfoque diferente.

Nota: A menos que un cliente lo solicite específicamente, no recomendamos exfiltrar datos como Información de Identificación Personal (PII), datos financieros (por ejemplo, números de tarjetas de crédito), secretos comerciales, etc., desde un entorno del cliente. En su lugar, si se intenta probar controles de Prevención de Pérdida de Datos (DLP) o protecciones de filtrado de salida, cree un archivo con datos ficticios que imiten los datos que el cliente está tratando de proteger.

Por lo tanto, a menudo es necesario encriptar los datos o archivos antes de una transferencia para evitar que los datos sean leídos si se interceptan en tránsito.

La fuga de datos durante una prueba de penetración podría tener graves consecuencias para el pentester, su empresa y el cliente. Como profesionales de la seguridad de la información, debemos actuar de manera profesional y responsable y tomar todas las medidas para proteger cualquier dato que encontremos durante una evaluación.

---

## File Encryption en Windows

Se pueden usar muchos métodos diferentes para encriptar archivos e información en sistemas Windows. Uno de los métodos más simples es el script de PowerShell [Invoke-AESEncryption.ps1](https://www.powershellgallery.com/packages/DRTools/4.0.2.3/Content/Functions%5CInvoke-AESEncryption.ps1). Este script es pequeño y proporciona encriptación de archivos y cadenas.

### Invoke-AESEncryption.ps1

```r

.EXAMPLE
Invoke-AESEncryption -Mode Encrypt -Key "p@ssw0rd" -Text "Secret Text" 

Description
-----------
Encrypts the string "Secret Test" and outputs a Base64 encoded ciphertext.
 
.EXAMPLE
Invoke-AESEncryption -Mode Decrypt -Key "p@ssw0rd" -Text "LtxcRelxrDLrDB9rBD6JrfX/czKjZ2CUJkrg++kAMfs="
 
Description
-----------
Decrypts the Base64 encoded string "LtxcRelxrDLrDB9rBD6JrfX/czKjZ2CUJkrg++kAMfs=" and outputs plain text.
 
.EXAMPLE
Invoke-AESEncryption -Mode Encrypt -Key "p@ssw0rd" -Path file.bin
 
Description
-----------
Encrypts the file "file.bin" and outputs an encrypted file "file.bin.aes"
 
.EXAMPLE
Invoke-AESEncryption -Mode Decrypt -Key "p@ssw0rd" -Path file.bin.aes
 
Description
-----------
Decrypts the file "file.bin.aes" and outputs an encrypted file "file.bin"
#>
function Invoke-AESEncryption {
    [CmdletBinding()]
    [OutputType([string])]
    Param
    (
        [Parameter(Mandatory = $true)]
        [ValidateSet('Encrypt', 'Decrypt')]
        [String]$Mode,

        [Parameter(Mandatory = $true)]
        [String]$Key,

        [Parameter(Mandatory = $true, ParameterSetName = "CryptText")]
        [String]$Text,

        [Parameter(Mandatory = $true, ParameterSetName = "CryptFile")]
        [String]$Path
    )

    Begin {
        $shaManaged = New-Object System.Security.Cryptography.SHA256Managed
        $aesManaged = New-Object System.Security.Cryptography.AesManaged
        $aesManaged.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $aesManaged.Padding = [System.Security.Cryptography.PaddingMode]::Zeros
        $aesManaged.BlockSize = 128
        $aesManaged.KeySize = 256
    }

    Process {
        $aesManaged.Key = $shaManaged.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Key))

        switch ($Mode) {
            'Encrypt' {
                if ($Text) {$plainBytes = [System.Text.Encoding]::UTF8.GetBytes($Text)}
                
                if ($Path) {
                    $File = Get-Item -Path $Path -ErrorAction SilentlyContinue
                    if (!$File.FullName) {
                        Write-Error -Message "File not found!"
                        break
                    }
                    $plainBytes = [System.IO.File]::ReadAllBytes($File.FullName)
                    $outPath = $File.FullName + ".aes"
                }

                $encryptor = $aesManaged.CreateEncryptor()
                $encryptedBytes = $encryptor.TransformFinalBlock($plainBytes, 0, $plainBytes.Length)
                $encryptedBytes = $aesManaged.IV + $encryptedBytes
                $aesManaged.Dispose()

                if ($Text) {return [System.Convert]::ToBase64String($encryptedBytes)}
                
                if ($Path) {
                    [System.IO.File]::WriteAllBytes($outPath, $encryptedBytes)
                    (Get-Item $outPath).LastWriteTime = $File.LastWriteTime
                    return "File encrypted to $outPath"
                }
            }

            'Decrypt' {
                if ($Text) {$cipherBytes = [System.Convert]::FromBase64String($Text)}
                
                if ($Path) {
                    $File = Get-Item -Path $Path -ErrorAction SilentlyContinue
                    if (!$File.FullName) {
                        Write-Error -Message "File not found!"
                        break
                    }
                    $cipherBytes = [System.IO.File]::ReadAllBytes($File.FullName)
                    $outPath = $File.FullName -replace ".aes"
                }

                $aesManaged.IV = $cipherBytes[0..15]
                $decryptor = $aesManaged.CreateDecryptor()
                $decryptedBytes = $decryptor.TransformFinalBlock($cipherBytes, 16, $cipherBytes.Length - 16)
                $aesManaged.Dispose()

                if ($Text) {return [System.Text.Encoding]::UTF8.GetString($decryptedBytes).Trim([char]0)}
                
                if ($Path) {
                    [System.IO.File]::WriteAllBytes($outPath, $decryptedBytes)
                    (Get-Item $outPath).LastWriteTime = $File.LastWriteTime
                    return "File decrypted to $outPath"
                }
            }
        }
    }

    End {
        $shaManaged.Dispose()
        $aesManaged.Dispose()
    }
}
```

Podemos usar cualquiera de los métodos de transferencia de archivos previamente mostrados para obtener este archivo en un host objetivo. Después de que el script se haya transferido, solo necesita ser importado como un módulo, como se muestra a continuación.

### Import Module Invoke-AESEncryption.ps1

```r
PS C:\htb> Import-Module .\Invoke-AESEncryption.ps1
```

Después de importar el script, puede encriptar cadenas o archivos, como se muestra en los siguientes ejemplos. Este comando crea un archivo encriptado con el mismo nombre que el archivo encriptado pero con la extensión ".aes".

### File Encryption Example

```r
PS C:\htb> Invoke-AESEncryption -Mode Encrypt -Key "p4ssw0rd" -Path .\scan-results.txt

File encrypted to C:\htb\scan-results.txt.aes
PS C:\htb> ls

    Directory: C:\htb

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----        11/18/2020  12:17 AM           9734 Invoke-AESEncryption.ps1
-a----        11/18/2020  12:19 PM           1724 scan-results.txt
-a----        11/18/2020  12:20 PM           3448 scan-results.txt.aes
```

Es esencial usar contraseñas muy `fuertes` y `únicas` para la encriptación para cada empresa donde se realiza una prueba de penetración. Esto es para evitar que archivos e información sensibles sean desencriptados usando una sola contraseña que pueda haber sido filtrada y descifrada por un tercero.

---

## File Encryption en Linux

[OpenSSL](https://www.openssl.org/) se incluye frecuentemente en distribuciones de Linux, con sysadmins usándolo para generar certificados de seguridad, entre otras tareas. OpenSSL puede usarse para enviar archivos "nc style" para encriptar archivos.

Para encriptar un archivo usando `openssl` podemos seleccionar diferentes cifrados, ver [OpenSSL man page](https://www.openssl.org/docs/man1.1.1/man1/openssl-enc.html). Vamos a usar `-aes256` como ejemplo. También podemos sobrescribir los conteos de iteraciones predeterminados con la opción `-iter 100000` y agregar la opción `-pbkdf2` para usar el algoritmo Password-Based Key Derivation Function 2. Cuando presionemos enter, necesitaremos proporcionar una contraseña.

### Encrypting /etc/passwd with openssl

```r
openssl enc -aes256 -iter 100000 -pbkdf2 -in /etc/passwd -out passwd.enc

enter aes-256-cbc encryption password:                                                         
Verifying - enter aes-256-cbc encryption password:                              
```

Recuerde usar una contraseña fuerte y única para evitar ataques de fuerza bruta en caso de que una parte no autorizada obtenga el archivo. Para desencriptar el archivo, podemos usar el siguiente comando:

### Decrypt passwd.enc with openssl

```r
openssl enc -d -aes256 -iter 100000 -pbkdf2 -in passwd.enc -out passwd                    

enter aes-256-cbc decryption password:
```

Podemos usar cualquiera de los métodos anteriores para transferir este archivo, pero se recomienda usar un método de transporte seguro como HTTPS, SFTP o SSH. Como siempre, practique los ejemplos en esta sección contra hosts objetivo en este u otros módulos y reproduzca lo que pueda (como los ejemplos de `openssl` usando el Pwnbox). La siguiente sección cubrirá diferentes formas de transferir archivos sobre HTTP y HTTPS.
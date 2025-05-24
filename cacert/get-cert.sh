# Use this script to download the certificates from the server in case the certificates are not trusted.

openssl s_client -showcerts -connect :443 -servername  < /dev/null | sed -n '/BEGIN CERTIFICATE/,/END CERTIFICATE/p' > diam-api-server-cert.crt
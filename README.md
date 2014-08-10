# cheeseman

A proof-of-concept TLS termination server with a focus on Server Name
Indication (SNI), an extension to TLS that allows a single IP to present
multiple host certificates. With cheeseman you can run a vhost for HTTPS
traffic.

## Golang >= 1.4

cheeseman depends on the `GetCertificate` func added to `tls.Config` in golang
v1.4. At the time of writing v1.4 is still under development so `tip` is
required.

# ntor
An Simple Implementation of the nTOR Protocol in Rust

## Generate ReverseProxy Ed25519 key-pair and certificate

```shell
cd python && python3 generate_ed25519_cert.pem -t [hex|dec|utf8] -v [value] -s [ntor_server_id]
```

Example:
```
cd python && python3 generate_ed25519_cert.py -t utf8 -v "this is 32-byte nTorStaticSecret" -s ReverseProxyServer
```
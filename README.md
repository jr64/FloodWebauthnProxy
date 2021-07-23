# FloodWebauthnProxy

This project is a Proof of Concept reverse proxy to add Webauthn authentication to an application that uses JWT for authentication. It has been specifically written for [jesec/flood](https://github.com/jesec/flood) but could be easily adapted to other applications.

## How does it work?

The Webauthn proxy is supposed to go in front of Flood and handle all requests to it. If a request contains a valid JWT token, it is directly forwarded to Flood. If not, the user is redirected to `/webauthn/` where they can log in or sign up for a new account. Upon successful authentication, the proxy will issue a valid JWT token and redirect the user to `/`, thus also signing them into Flood. Of course, both applications have to use the same JWT secret for this to work.

## Caveats

Since this is mostly a Proof of Concept project, there are some limitations which make it unsuitable for any production environment:
* Users aren't stored in a database, they are merely serialized to files on disk. 
* There is no UI to remove authenticators from an account. You have to manually edit the user's JSON file.
* There is no way to sign in with a password instead of using Webauthn
* No account recovery
* Registration of accounts has to be enabled or disabled at application startup by passing a flag. Keep in mind that if registration is enabled, ANYONE CAN REGISTER AN ACCOUNT. You should only enable it for a short time, register your authenticators and then disable it. If you are paranoid like me you can also check the logs to make sure no one else registered during that time.

## Build

```
go build .
```

## Example

Assuming your flood instance is running at 127.0.0.1:3000 and the interface will be accessed externally through https://flood.example.com, the proxy can be stared like this:
```bash
./FloodWebauthnProxy --upstream "http://127.0.0.1:3000" --rp-id "example.com" --rp-origin "https://flood.example.com" --userdb-directory ./users --jwt-secret "long-secret-here" --enable-registratio
```

```
Usage of FloodWebauthnProxy:
  -u, --upstream string            upstream Flood server
  -s, --server-address string      ip address to listen on (default ":8080")
  -r, --enable-registration        allow anyone to register new authenticators (disable this after initial setup)
      --rp-display-name string     WebAuthn relying party display name (default "Flood")
      --rp-id string               WebAuthn relying party ID
      --rp-origin string           WebAuthn relying party origin
  -d, --userdb-directory string    directory where user data will be stored (default "users")
  -j, --jwt-secret string          secret used to sign JWT tokens
  -t, --jwt-duration int           time in hours that created JWT tokens will be valid (default 168)
  -k, --insecure-skip-verify-tls   skip verifying TLS certificate of upstream
  -v, --verbose                    print debug messages
```

All arguments can also be passed as environment variables for Docker by prefixing them with FLOODPROXY (e.g. FLOODPROXY_RP_ORIGIN instead of --rp-origin).

## Thanks:

Thanks to those people for Webauthn samples and for allowing me to copypaste their HTML because I am a horrible UI designer.

* https://github.com/duo-labs/webauthn
* https://github.com/hbolimovsky/webauthn-example
* https://bootsnipp.com/snippets/2X0r
* https://bootsnipp.com/snippets/00ADR
* https://bootsnipp.com/snippets/8o7X

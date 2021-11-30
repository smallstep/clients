# step-ca certificate signing clients

This repo contains client code in various languages, for getting X.509 certificates signed by a [step-ca](https://github.com/smallstep/certificates/) Certificate Authority.

## How you might use this

Use one of these clients if you need to write a custom integration with `step-ca` that authenticates X.509 certificate requests on behalf of your users.

**These clients are not designed to be used directly by end users.** Their use of the [JWK provisioner](https://smallstep.com/docs/step-ca/provisioners#jwk) gives these clients too much power. For end user applications, either use the [OIDC provisioner](https://smallstep.com/docs/step-ca/provisioners/#oauthoidc-single-sign-on), or use this client code to create a custom service that your users will use.

The ideal use case for this is to **delegate CA authentication to an independent service** that will request TLS certificates on behalf of its users/clients.
Your implementation must be responsible for authenticating certificate requests.

For example, say you manage a set of global VPN servers for your company, 
and each server provides access an internal network for a given business unit or region.
You've created a service for managing VPN access and issuing client certificates.
The service maintains a mapping between employees and VPN servers.
A user can sign in, request access to a particular server.
When access is granted, the service will get a client certificate for the user from the CA,
and make it available for download.

## Alternatives

If you only need certificates with IP or hostname identifiers, the ACME protocol may be ba better fit for you.
It has [many client implementations](https://letsencrypt.org/docs/client-options/).
Pair your ACME client with `step-ca`'s [ACME provisioner](https://smallstep.com/docs/step-ca/provisioners#acme).

The [OIDC provisioner](https://smallstep.com/docs/step-ca/provisioners/#oauthoidc-single-sign-on) allows you to authenticate client certificate requests using any OpenID Connect identity provider.
This is a better fit for integrating into interactive, end-user workflows.

## You will need

- A `step-ca` server or a [Certificate Manager](https://smallstep.com/certificate-manager/) authority.
- A JWK provisioner configured in your CA. (use `step ca provisioner add` to add one)
- The JSON for the provisioner's JWK praviate key, to authenticate the client to the CA. To generate the JSON file, take the `encryptedKey` value from the CA provisioner, and run:

  ```
  $ step crypto jwk decrypt < encrypted.key > decrypted.json
  Please enter the password to decrypt the content encryption key: 
  $ cat decrypted.json
  {"use":"sig","kty":"EC","kid":"udaECquEXAMPLErW2dYw","crv":"P-256","alg":"ES256","x":"Pn_JEXAMPLEByDJA","y":"_x7JjfwqKEXAMPLEBp73E","d":"u1_OZH1EXAMPLEXAL__bE6u0"}
  ```
  
  Treat this `decrypted.json` file as you would any sensitive credential. Anyone with this file can create JWTs and request arbitrary certificates from your CA.

## Features

These clients are not full featured. They are able to do the following:
- Bootstrap with the CA (download the CA root certificate securely)
- Check CA health
- Get a Certificate Signing Request (CSR) signed by a [JWK provisioner](https://smallstep.com/docs/step-ca/provisioners#jwk) configured in the CA

The clients authenticate with the CA using a private JSON Web Key (JWK).
Note that this JWK can typically make any request of the CA, 
so it's necessary to protect the private key JSON file.

## Under the hood

To get the CSR signed, clients follow these steps:
- Bootstrap with the CA (using the CA's URL and SHA256 root certificate fingerprint); and download the root certificate
- Generate the desired CSR (a [PKCS#10](https://www.rfc-editor.org/rfc/rfc2986#section-4.2) PEM)
- Generate and sign a one-time-use authentication token for the CA. This token is a JSON Web Token (JWT) ([RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519); see [jwt.io](https://jwt.io/)) signed using the JSON Web Key (JWK) that has been configured in the CA's JWK provisioner.
- POST the CSR and JWT to the `/1.0/sign` endpoint on the CA
- Return the signed TLS certificate PEM from the response.


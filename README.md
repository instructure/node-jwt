# Node-JWT

A lightweight Express middleware for verifying JWTs (JSON Web Tokens).

* built on [jsonwebtoken](https://github.com/auth0/node-jsonwebtoken)
* creates and signs JWTs
* handles key rotation

## Installation

1. Include `node-jwt` in your router file using `import * as auth from "node-jwt"` (ES6) or `var auth = require("node-jwt")` (ES5).
2. This middleware should only be used when required. Add this code before your routes:
    ```js
      if (auth.required()) {
        app.use([auth.middleware, auth.errorHandler])
      }
    ```
3. Add necessary configuration as environment variables.
    - `MAX_JWT_AGE` - age that JWT will last before being rejected. Uses [zeit/ms](https://github.com/zeit/ms) format, defaults to `5s`.
    - `AUTH_SECRET` - The secret(s) used for verifying JWTs. Secrets are `:`-separated key-value pairs. Multiple secrets are space-separated. See [Keystore](#keystore) for more details. Eg: `secret1:<base64-secret> secret2:<base64-other-secret>`
    - `REQUIRE_AUTH` - used for debugging. When `true`, `auth.required()` returns true and JWTs are required with every request.
4. The middleware will verify JWTs that are included in the request's query string as`token` (`example.com?token=<jwt-here>`) or as an authorization header (`Authorization: Bearer <jwt-here>`). It prefers the query string over the header.
5. If the token is valid, `res.locals.payload` will be set with the token's payload.

### Debugging

To debug your code using your own JWTs, `node-jwt` has the ability to sign JWTs based on your provided secrets. The recommended way to do this is to create a new route in your app that returns a signed JWT using `auth._createToken()`.

## About

`node-jwt` fills a need for a simple JWT middleware that can handle key rotation.

### Keystore

The keystore is initialized with values from the `AUTH_SECRET` environment variable. It can contain as many secrets as needed (within the max length of an environment variable). Each secret consists of a `kid` and a key value, separated by a `:`. The `kid`, or key id, is included in the `header` section of a JWT is an easy way of identifying which secret was used to sign that JWT. The key value is the base64-encoded secret. A secret that has no `kid``:` is known as the `default` key. There can only be one `default` key; all other keys without `kid`s will be ignored.

### Verification

`node-jwt` is capable of verifying JWTs using different options. If a `kid` is included in the JWT header, `node-jwt` will attempt to verify using the key that matchs the `kid`, if there is one. If that fails, it will verify using the `default` key. Otherwise, it will try using every key in the keystore to verify.
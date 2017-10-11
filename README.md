# Inst-node-JWT

A decently opinionated [Expressjs](http://expressjs.com/) middleware for
verifying JWTs (JSON Web Tokens).

Lets you authenticate HTTP requests using JWT tokens. Both signs and verifies
JWTs. Handles multiple secrets and key rotation. Built on
[jsonwebtoken](https://github.com/auth0/node-jsonwebtoken)


## Install

```
npm install inst-node-jwt
```

`inst-node-jwt` is configured using environment variables:
* `AUTH_SECRET` - The secret(s) used for verifying JWTs. Secrets are
`:`-separated key-value pairs. Multiple secrets are space-separated. See
[Keystore](#keystore) for more details.
* `MAX_JWT_AGE` - age that JWT will last before being rejected. Uses
[zeit/ms](https://github.com/zeit/ms) format. If not set, defaults to `5s`.
* `REQUIRE_AUTH` - used for development. When set, `auth.required()` returns
`true` and JWTs are required with every request. (When `REQUIRE_AUTH` is not
set, `auth.required()` returns true iff `NODE_ENV === 'production'`)


## Usage

Set the `AUTH_SECRET` environment variable; e.g. with
`AUTH_SECRET="kid:secret" node myfancyapp.js`

```js
var auth = require('inst-node-jwt')

if (auth.required()) {
  app.use([auth.middleware, auth.errorHandler])
}
```

The middleware will verify JWTs that are included in the request's query string
as `token`:

```
example.com/route?token=<jwt-here>
```

or as an authorization header:

```
Authorization: Bearer <jwt-here>
```

It prefers the query string over the header.

If the token is valid, `res.locals.JWTPayload` will be set with the token's payload.

---

## About

`inst-node-jwt fills a need for a simple JWT middleware that can handle key
`rotation.

`required()`: returns `true` if `NODE_ENV === production` or
`REQUIRE_AUTH` is set

`middleware() / errorHandler()`: two Expressjs middlewares that should be called
early in your middleware pipeline. If `middleware()` is unable to verify a JWT,
it will abort the request, send an error to the `errorHandler()` middleware,
which will return a `401` error with a JSON description of the error.


### Keystore

The keystore is initialized with values from the `AUTH_SECRET` environment
variable. It can contain as many secrets as needed (within the max length of an
environment variable). Each secret consists of a `kid` and a key value,
separated by a `:`.

```js
const auth = require('inst-node-jwt')

(async () => {
  const s1 = Buffer.from("secret1").toString("base64")
  const s2 = Buffer.from("secret2").toString("base64")
  process.env.AUTH_SECRET = `secret1:${s1} secret2:${s2}`

  const keystore = await auth.keystoreBuilders.fromEnv()

  console.log(keystore.secret1.toString()) // secret1
  console.log(keystore.secret2.toString()) // secret2
})()
```

The `kid`, or key id, is included in the `header` section of a JWT is an easy
way of identifying which secret was used to sign that JWT.

The key value is the base64-encoded secret. Note that `inst-node-jwt` will sign and
verify JWTs by decoded that secret using base64 and use the original random bytes.
This is based on `jsonwebtoken`'s behavior, outlined [here]
(https://github.com/auth0/node-jsonwebtoken/issues/208#issuecomment-231861138)

A secret that has no `kid:` is known as the `default` key. There can only be one
`default` key; all other keys without `kid`s will be ignored.


```js
const auth = require('inst-node-jwt')

(async () => {
  const s1 = Buffer.from("secret1").toString("base64")
  const s2 = Buffer.from("secret2").toString("base64")
  const s3 = Buffer.from("secret3").toString("base64")
  process.env.AUTH_SECRET = `secret1:${s1} ${s2} ${s3}`

  const keystore = await auth.keystoreBuilders.fromEnv()

  console.log(keystore.secret1.toString()) // secret1
  // Notice that secret2 has been overridden
  console.log(keystore.default.toString()) // secret3
})()
```


### Verification

`inst-node-jwt` is capable of verifying JWTs using different methods. If a
`kid` is included in the JWT header, `inst-node-jwt` will attempt to verify
using the key that matchs the `kid`, if there is one. If that fails, it will
verify using the `default` key. Otherwise, it will try using every key in the
keystore to verify.

### Signing

`inst-node-jwt` can also sign tokens, e.g. for testing purposes.

```js
const auth = require('inst-node-jwt')

(async () => {
  const s1 = Buffer.from("secret1").toString("base64")
  const s2 = Buffer.from("secret2").toString("base64")
  process.env.AUTH_SECRET = `${s1} secret2:${s2}`

  const token1 = await auth.createToken({foo: "bar"})
  const payload1 = await auth.verifyToken(token1)
  console.log(payload1) // { "foo": "bar" }

  const token2 = await auth.createToken({bar: "baz"}, "secret2")
  const payload2 = await auth.verifyToken(token2)
  console.log(payload2) // { "bar": "baz" }
})()
```

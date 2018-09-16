# ring-jwt
[Ring](https://github.com/ring-clojure/ring) middleware for parsing, decoding and verifying
a [JWS](https://tools.ietf.org/html/rfc7515)-signed [JWT](https://tools.ietf.org/html/rfc7519) token from the incoming request.

Built on top of the excellent [auth0](https://github.com/auth0/java-jwt) JWT library.

Once wired into to your ring server, the middleware will:

* Search for a JWT token on each incoming request (see below for information on where it looks).
* Will add the claims it finds in the token as a clojure map against the `:claims` key on the incoming request.
* Add an empty `:claims` map to the request if no token is found.
* Respond with a `401` if the JWS signature in the token cannot be verified.
* Respond with a `401` if the token has expired (i.e. the [exp]() claim indicates a time
in the past)
* Respond with a `401` if the token will only be active in the future (i.e. the [nbf]() claim indicates
a time in the future)

Note that there is the option to specify a leeway for the `exp`/`nbf` checks - see usage below.

## Installation
```
[ovotech/ring-jwt "0.1.0"]
```

## Usage
```clj
(require '[ring.middleware.jwt :refer [wrap-jwt]])

(defn handler [request]
  (response {:foo "bar"}))

(jwt/wrap-jwt handler {:alg        :HS256
                       :public-key "yoursecret"})
```

Depending upon the cryptographic algorithm that is selected for the middleware, a different
map of options will be required. Note that, at the point your ring middleware is wired up, ring-jwt will
throw an error if it detects that the given options are invalid. 

Currently the following [JWA](https://tools.ietf.org/html/rfc7518#page-6) algorithms are
supported for the purposes of JWS:

| Algorithm                      | Options                                       |
| ------------------------------ | --------------------------------------------- |
| RSASSA-PKCS-v1_5 using SHA-256 | `{:alg :RS256 :public-key public-key}` <sup>[1]</sup> |
|                                | `{:alg :RS256 :jwk-endpoint "https://your/jwk/endpoint :key-id "key-id" :cache true}` <sup>[2]</sup> | 
| HMAC using SHA-256             | `{:alg :HS256 :public-key "your-secret"}`     |

[1] `public-key` is of type `java.security.PublicKey`.

[2] when `cache` is set to true, jwks are cached using lru-cache. Cache threshold is equal to 10.

Additionally, the following optional options are supported:

* `leeway-seconds`: The number of seconds leeway to give when verifying the expiry/active from claims
of the token (i.e. the `exp` and `nbf` claims).

### Finding the token on the request
Currently the library looks in order from the following locations:

1. `Authorization` header bearer token (i.e. an `Authorization` HTTP header of the form "Bearer TOKEN")

## Useful links

* [JSON Web Tokens - JWT Specification](https://tools.ietf.org/html/rfc7519)
* [JSON Web Signatures - JWS Specification](https://tools.ietf.org/html/rfc7515)
* [JSON Web Algorithms - JWA Specification](https://tools.ietf.org/html/rfc7518)
* [JSON Web Keys - JWK Specification](https://tools.ietf.org/html/rfc7517)
* [jwt.io](https://jwt.io/)

## License
Copyright © 2018 Ovo Energy Ltd.

Distributed under the Eclipse Public License, the same as Clojure.

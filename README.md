# go-jwks-api-auth

This library provides a method to retrieve the public key from Auth0's endpoint that serves JWKS for JWT validation. The implementation was designed around [Auth0's API authentication](https://auth0.com/docs/api-auth/config/asking-for-access-tokens) design, although any API that serves JWKS on the `/.well-known/jwks.json` endpoint would work as well.

## Usage

This library is intended to be used with [`auth0/go-jwt-middleware`](https://github.com/auth0/go-jwt-middleware), more specifically in the `ValidationKeyGetter` callback.

`GetPublicKey()` asks for a target `iss` and `aud` to perform verification against the token, which can be forged by malicious actors to request JWKS from their own endpoint and/or target an arbitrary resource server.

The following example performs validation via JWKS (asymmetric, RS256) as well as standard client secret (symmetric, HS256).

```go
jwtMiddleware := jwtmiddleware.New(jwtmiddleware.Options{
	ValidationKeyGetter: func(token *jwt.Token) (interface{}, error) {
		var (
			decoded []byte
			err     error
		)
		// If kid exists then get the public key from the JWT's iss, otherwise use client secret
		if _, ok := token.Header["kid"]; ok {
			decoded, err = jwks.GetPublicKey(token, "TARGET_ISS", "TARGET_AUD")
		} else {
			decoded, err = base64.URLEncoding.DecodeString("AUTH0_CLIENT_SECRET")
		}
		if err != nil {
			return nil, err
		}
		return decoded, nil
	},
})
```

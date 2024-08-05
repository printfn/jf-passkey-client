# Jellyfish Passkey Client

This app authenticates with the Jellyfish API using a Passkey (FIDO2).

## Registration

Run this app with `go run .` and enter a Jellyfish domain and a username/password.

It will log in and register a new passkey to your account. This involves
generating an Ed25519 keypair and uploading the public key to the server. Once this
has succeeded, this app will store the private key in `secret.json`, which looks like this:

```json
{
	"domain": "https://pre.jellyfishhq.com",
	"relying-party-id": "pre.jellyfishhq.com",
	"key": "QXqRXuqzVF8rWuVDGut4SRBI1d8tw6eHNXf7POzr5wrfvCRS1WkdF9MHIP6GCEP8TgMmH4JhvXOyONT8Fevs4g==",
	"credential-id": "S220gHsPxSnI4FT5iCFOLpvqz6vsyz3D69mKfYmv7dA=",
	"user-id": "12YBTZNpW99ez50iMyJPqsXdz0vHAWTQ8eyC1+adXb7se6xVPMVqgwuzEi5OOxfUtzXShdwZcwK3aX7RzVTMnw==",
	"sign-count": 1
}
```

## Authentication

Once you've registered a passkey, simply run the program again with `go run .`.

It will then use the stored passkey to authenticate. This involves using the
stored Ed25519 private key to sign a random challenge (nonce) from the server,
which proves possession of the private key.

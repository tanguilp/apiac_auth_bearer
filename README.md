# APIacAuthBearer

An `APIac.Authenticator` plug for API authentication using the OAuth2 `Bearer` scheme

The OAuth2 `Bearer` scheme is documented in
[RFC6750 - The OAuth 2.0 Authorization Framework: Bearer Token Usage](https://tools.ietf.org/html/rfc6750)
and consists in sending an OAuth2 access token in the HTTP request. Any party
in possession of that token can use it on the API, hence its name: 'Bearer'.

```http
GET /api/accounts HTTP/1.1
Host: example.com
Authorization: Bearer NLdtYEY8Y4Q09kKBUnsYy9mExGQnBy
Accept: */*
```

That bearer token has been granted beforehand by an OAuth2 authorization server to the
client making the API request (typically through one of the 4
[RFC6749](https://tools.ietf.org/html/rfc6749) flows or one of the 3
[OpenID Connect](https://openid.net/specs/openid-connect-core-1_0.html) flows).

Note that according to the specification, the bearer can be sent:
- in the `Authorization` HTTP header
- in the request body (assuming the request has one)
- as a query parameter

The `bearer_extract_methods` plug option allows to specify where to seek the bearer.

Bearer tokens are usually:
- opaque tokens, to be validated against the OAuth2 authorization server that has released it
- self-contained signed JWT tokens, that can be verified locally by the API

## Installation

```elixir
def deps do
  [
    {:apiac_auth_bearer, "~> 2.0"}
  ]
end
```

## Validating the access token

This plug provides with 2 bearer verification implementations:
- `APIacAuthBearer.Validator.Introspect` which implements
[RFC7662 - OAuth 2.0 Token Introspection](https://tools.ietf.org/html/rfc7662), and
which consists in requesting validation of the token on the authorization server
that has issued it
- `APIacAuthBearer.Validator.JWT` which implements
[JSON Web Token (JWT) Profile for OAuth 2.0 Access Tokens](https://tools.ietf.org/html/draft-ietf-oauth-access-token-jwt-07)
and which consists in locally verifying signed (and possibly encrypted)
tokens, using the cryptographic keys of the authorization server and of the current
API (using this plug)

A validator must implement the `APIacAuthBearer.Validator` behaviour.

## Caching

A bearer token may be used many times on an API in a short time-frame,
which is why caching is important
when using `APIacAuthBearer.Validator.Introspect` or a similar mechanism as a
back pressure mechanism for the authorization server. This plug comes with 4 caching
implementations:

| Caching implementation         | Repository | Use-case                                                                                                                                                    |
|--------------------------------|:----------:|-------------------------------------------------------------------------------------------------------------------------------------------------------------|
| APIacAuthBearer.Cache.NoCache | Built-in   | No caching, for testing purpose or when using a custom validator that doesn't require caching                                                               |
| APIacAuthBearer.Cache.ETSMock | Built-in   | Local cache in ETS table, for testing purpose, development environment, etc. Does not have a token expiration clean-up code: the cache will grow endlessly  |
| APIacAuthBearerCacheCachex  | [github](https://github.com/tanguilp/apiac_auth_bearer_cache_cachex) | Production ready cache, for a single instance or a small cluster of nodes                                                                                   |
| APIacAuthBearerCacheRiak    | Work in progress | Production ready cache, for larger clusters of nodes                                                                                                        |

A cache implements the `APIacAuthBearer.Cache` behaviour.

## Validation flow sequence diagram

![SVG sequence diagram of the validation flow](https://raw.githubusercontent.com/tanguilp/apiac_auth_bearer/master/media/success_flow.svg)

## Plug options

- `realm`: a mandatory `String.t` that conforms to the HTTP quoted-string syntax,
however without
the surrounding quotes (which will be added automatically when needed).
Defaults to `default_realm`
- `bearer_validator`: a `{validator_module, validator_options}` tuple where
`validator_module` is
a module implementing the `APIacAuthBearer.Validator` behaviour and `validator_options`
module-specific options that will be passed to the validator when called. No default
value, mandatory parameter
- `bearer_extract_methods`: a list of methods that will be tried to extract the bearer
token, among `:header`, `:body` and `:query`. Methods will be tried in the list order.
Defaults to `[:header]`
- `set_error_response`: function called when authentication failed. Defaults to
`APIacAuthBearer.send_error_response/3`
- `error_response_verbosity`: one of `:debug`, `:normal` or `:minimal`.
Defaults to `:normal`
- `required_scopes`: a list of scopes required to access this API. Defaults to `[]`.
When the bearer's granted scope are
not sufficient, an HTTP 403 response is sent with the `insufficient_scope` RFC6750 error
- `forward_bearer`: if set to `true`, the bearer is saved in the `Plug.Conn` APIac
metadata (under the "bearer" key) and can be later be retrieved using `APIac.metadata/1`.
Defaults to `false`
- `forward_metadata`: in addition to the bearer's `client` and `subject`, list of the
validator's response to set in the APIac metadata, or the `:all` atom to forward all
of the response's data.
For example: `["username", "aud"]`. Defaults to `[]`
- `resource_indicator`: the name of the resource server as a String, to be
checked against the `aud` attribute returned by the validator. This is an optional
security mecanism for RFC7662 and mandatory for JWT access tokens. See the security
consideration sections. Defaults to `nil`, i.e. no check of this parameter
- `cache`: a `{cache_module, cache_options}` tuple where `cache_module` is
a module implementing the `APIacAuthBearer.Cache` behaviour and `cache_options`
module-specific options that will be passed to the cache when called.
The cached entry expiration ttl can be set thanks to the `:ttl` option. It is set to
200 seconds by default, but is shortened when the bearer's lifetime is less than 200
seconds (as indicated by its expiration timestamp of the `"exp"` member of bearer
metadata returned by the validator)
Defaults to `{APIacAuthBearer.Cache.NoCache, [ttl: 200]}`

## Error responses

This plug, conforming to RFC6750, responds with the following status and parameters
in case of authentication failure when `:error_response_verbosity` is set to `:normal`:

| Error                                   | HTTP status | Included WWW-Authenticate parameters |
|-----------------------------------------|:-----------:|--------------------------------------|
| No bearer token found                   | 401         | - realm                              |
| Invalid bearer                          | 401         | - realm<br>- error                   |
| Bearer doesn't have the required scopes | 403         | - realm<br>- error<br>- scope        |

For other `:error_response_verbosity` values, see the documentation of the
`send_error_response/3` function.

## Example

```elixir
plug APIacAuthBearer, bearer_validator: {
  APIacAuthBearer.Validator.Introspect,
  [
    issuer: "https://example.com/auth"
    tesla_middleware:[
      {Tesla.Middleware.BasicAuth, [username: "client_id_123", password: "WN2P3Ci+meSLtVipc1EZhbFm2oZyMgWIx/ygQhngFbo"]}
    ]
  ]},
  bearer_extract_methods: [:header, :body],
  required_scopes: ["article:write", "comments:moderate"],
  forward_bearer: true,
  resource_indicator: "https://example.com/api/data"
  cache: {APIacAuthBearerCacheCachex, []}

```

## Security considerations

### HTTPS
As the bearer token is sent in an HTTP header, use of HTTPS is **mandatory**
(but however not verfified by this Plug).

### Bearer methods
As stated by RFC6750, section 2:

>  This section defines three methods of sending bearer access tokens in
>  resource requests to resource servers.  Clients **MUST NOT** use more
>  than one method to transmit the token in each request.

This plug does not check whether several methods are used or not. It will
only deal with the first bearer (valid or not) found following the order
of the `bearer_extract_methods`.

### Form-Encoded Body Parameter
RFC6750, section 2.2, demands that the following conditions are met for
form-encoded body bearer access token:

> o  The HTTP request entity-header includes the "Content-Type" header
>    field set to "application/x-www-form-urlencoded".
>
> o  The entity-body follows the encoding requirements of the
>    "application/x-www-form-urlencoded" content-type as defined by
>    HTML 4.01 [W3C.REC-html401-19991224].
>
> o  The HTTP request entity-body is single-part.
>
> o  The content to be encoded in the entity-body MUST consist entirely
>    of ASCII [USASCII] characters.
>
> o  The HTTP request method is one for which the request-body has
>    defined semantics.  In particular, this means that the "GET"
>    method MUST NOT be used.

This plug, however:
- doesn't verify that the HTTP request entity-body is single-part
- the content is entirely US-ASCCI (the plug parser checks that it
is [utf8](https://github.com/elixir-plug/plug/blob/master/lib/plug/parsers/urlencoded.ex#L31)

### Audience
RFC6750, section 5.2, states that:

> To deal with token redirect, it is important for the authorization
> server to include the identity of the intended recipients (the
> audience), typically a single resource server (or a list of resource
> servers), in the token.  Restricting the use of the token to a
> specific scope is also RECOMMENDED.

Consider implementing it using the `resource_indicator` parameter when using the
RFC7662 introspection validator.

### URI Query Parameter
According to RFC6750, section 2.3,:

> Clients using the URI Query Parameter method SHOULD also send a
> Cache-Control header containing the "no-store" option.  Server
> success (2XX status) responses to these requests SHOULD contain a
> Cache-Control header with the "private" option.

This plug does set the `cache-control` to `private` when such a method
is used. Beware, however, of not overwriting it later unless you
know what you're doing.

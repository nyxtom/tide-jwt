# tide-jwt

Simple implementation of [JWT](https://docs.rs/jsonwebtoken) Authorization Middleware for the [tide](https://github.com/http-rs/tide) web framework. This makes use of the [jsonwebtoken](https://docs.rs/jsonwebtoken) crate for the encoding/decoding. It will only return Unauthorized in the case where an *Authorization* header is found and it is not valid. If no authorization header is found the middleware will continue to run. It is up to the implementation to make sure to check if the request is actually authenticated to prevent downstream middleware from running and to return the appropriate response.

## Features

- [x] Read "Authorization" header
- [x] Validate "Bearer" token with generic claims and [jsonwebtoken](https://docs.rs/jsonwebtoken)
- [x] Add helper functions for encoding (from secret base64, chosen algorithm, claims)
- [x] Support Send + Sync + 'static, Serializable/Deserialize ([serde](https://docs.rs/serde)) claims used for [jsonwebtoken](https://docs.rs/jsonwebtoken)
- [ ] Possibly read jwt cookie if configured/present

## Examples

Implementation with the [tide](https://docs.rs/tide) web framework is as simple as using the `.with` function to include the middleware. This functions as technically a [Before](https://docs.rs/tide/latest/tide/utils/struct.Before.html) middleware in that it reads from the *Request* before continuing the rest of the middleware. It will make use of the [set_ext](https://docs.rs/tide/latest/tide/struct.Request.html#method.set_ext) function to add the ability to get the `<Claims>` object with any other middleware.

```rust
use jsonwebtoken::{DecodingKey, Validation};
use registry::State;
use serde::{Deserialize, Serialize};
use tide::log::LogMiddleware;
use tide_jwt::JwtAuthenticationDecoder;

mod flash;
mod registry;
mod routes;

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    sub: String,
    username: String,
    uid: u64,
    exp: usize,
}

#[async_std::main]
async fn main() -> tide::Result<()> {
    let mut app = tide::with_state(State::new());
    dotenv::dotenv().ok();
    env_logger::init();

    app.with(LogMiddleware::new());

    // configure openid connect and session middleware
    let jwt_secret = std::env::var("SESSION_SECRET")?;
    app.with(JwtAuthenticationDecoder::<Claims>::new(
        Validation::default(),
        DecodingKey::from_base64_secret(&jwt_secret)?,
    ));
    routes::configure(&mut app);

    let host = std::env::var("HOST").unwrap_or(String::from("0.0.0.0"));
    let port: u16 = std::env::var("PORT")?.parse()?;
    app.listen((host, port)).await?;

    Ok(())
}
```

The above example will allow enable the middleware to properly decode the *Claims* from the request and set the object on the request as an extention. This allows us to later grab it in an endpoint or another middleware function.

```rust
pub async fn index(req: Request<State>) -> tide::Result {
    let claims = req.ext::<Claims>();
    println!("{:?}", claims);

    let mut res = Response::new(200);
    Ok(res)
}
```

Assuming you have properly authenticated a request, you can use the `encode` utility functions to encode a token with the proper claims.

```rust
pub async fn login(mut req: Request<State>) -> tide::Result {
    match req.body_form::<UserForm>().await {
        Ok(form) => {
            if form.username == "foo" && form.password == "bar" {
                let mut res: Response = Redirect::new("/").into();
                let secret = std::env::var("SESSION_SECRET")?;
                let claims = Claims {
                    username: String::from("foo"),
                    exp: 10000000000,
                    sub: String::from("asdf"),
                    uid: 1,
                };
                let token = tide_jwt::jwtsign_secret(&claims, &secret)?;
                println!("{token}");
                res.insert_cookie(
                    Cookie::build("_jwt", token)
                        .max_age(Duration::seconds(60000))
                        .same_site(SameSite::Lax)
                        .path("/")
                        .finish(),
                );
                Ok(res)
            } else {
                flash::redirect("/", flash::warn("invalid credentials"))
            }
        }
        Err(e) => flash::redirect("/", flash::error(e.to_string().as_str())),
    }
}
```

Claims should be built to allow some uniqueness (such as the exp or the iat) so that encryption/signing is performed with uniqueness each time. It should be noted that it is generally preferred that authentication for a web application is done with Sessions and that JWT is typically reserved for backend api services (or if you are looking at serverless type production systems).


### build for release:
`cargo lambda build --release --arm64`

### deploy:
DEV: `cargo lambda deploy --binary-name rust-authorizer dev-cc-authorizer`
PROD: `cargo lambda deploy --binary-name rust-authorizer cc-authorizer`



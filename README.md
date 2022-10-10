# quic-server-zig

![CI status](https://github.com/shiguredo/quic-server-zig/actions/workflows/ci.yml/badge.svg)

This repository is an experimental implementation and is not intended for production use.

## Status

Currently the server succeeds in establishing a connection with one of the existing client implementation, [cloudflare/quiche]. To try it out, just run the following commands:

```shell
# Start the server
$ zig build run

# In another terminal session, run the client
$ cd third_party/quiche
$ RUST_LOG=debug cargo run
```

You'll see `thread 'main' panicked at 'called `Result::unwrap()` on an `Err` value: Done', src/main.rs:188:18` when running the client, meaning that the client has determined that the QUIC connection is established and tried to send a HTTP request, but our server implementation cannot handle properly it at the moment.

[cloudflare/quiche]: https://github.com/cloudflare/quiche

## LICENSE


```
Copyright 2022, Yusuke Tanaka (Original Author)
Copyright 2022, Shiguredo Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```

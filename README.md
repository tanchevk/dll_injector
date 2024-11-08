# DLL Injector
#### A DLL injector written in Rust

## Compiling and Using
To get started, clone this repo and compile:
```shell
# Clone the repo
git clone https://github.com/tanchevk/dll_injector.git

# Compile
# Do NOT compile with --release
# Compiling this in release mode breaks it, for some reason
cargo build --profile dev
```

After compiling it, the binary should be in `target/debug`.
It is completely portable, so feel free to move it wherever you like.
If you want, you can also add it to your path, so you can access it from anywhere.

To use it, run:
```shell
dll_injector [TARGET] [DLL PATH]
```
where [TARGET] is the process to inject the DLL into,
and [DLL PATH] is the path to the DLL to inject.

## Licensing
Dual-licensed under both the [Apache License, Version 2.0](LICENSE-APACHE)
and the [MIT license](LICENSE-MIT).

## Contributing
Unless explicitly stated otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the [Apache-2.0
license](LICENSE-APACHE), will be dual-licensed as above,
without any additional terms or conditions.
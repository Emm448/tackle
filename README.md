# tackle

```
        ~ ~ ~
     ~         ~
   ~    (\_/)    ~
  ~     ( •_•)     ~
   ~    / >🎣       ~
     ~         ~
        ~ ~ ~

   if it bites, we hook it
```

A small C library for low-level Windows runtime utilities.

## Overview

tackle provides a set of minimal primitives for working with Windows internals, including:

* PE parsing (mapped and raw images)
* Import Address Table (IAT) hooking
* PEB walking (module and API resolution)
* API lookup via hashing (ROR13)

The goal is to keep things simple, transparent, and easy to extend.

## Features

* Lightweight PE parsing helpers
* IAT hooking by name or hash
* WinAPI-less module resolution via PEB
* Minimal and dependency-free design

## Design Philosophy

* Keep it simple
* Avoid unnecessary abstractions
* Give full control to the caller
* Be easy to hack on and extend

## Future

This project will be updated… whenever I feel like it 🙂

## Disclaimer

This project is intended for educational and research purposes only.

## License

Public domain / MIT — use it however you want.

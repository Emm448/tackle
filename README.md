# tackle

```
        ~ ~ ~
     ~         ~
   ~    (\_/)    ~
  ~     ( •_•)    ~
   ~    / >🎣    ~
     ~         ~
        ~ ~ ~

   If it bites, we hook it
```

A small C library for Windows offensive security.

## Overview

tackle is a C library for developing offensive tooling on Windows.

It incorporates AV/EDR evasion techniques and simple static analysis resistance.

## Features

tackle provides a set of minimal primitives for working with Windows internals, including:

* PE parsing (mapped and raw images)
* Import Address Table (IAT) hooking
* PEB walking (module and API resolution)
* API lookup via hashing (ROR13)
* Direct syscalls (dynamic resolution via ntdll exports and runtime-generated stubs)

## Future

This project will be updated… whenever I feel like it 🙂

## Disclaimer

This project is intended for educational and research purposes only.

## License

Public domain / MIT — use it however you want.
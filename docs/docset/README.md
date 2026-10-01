# docset

The folder contains the required files to create a [docset](https://kapeli.com/docsets) which can be used in
documentation browsers like [Dash](https://kapeli.com/dash), [Velocity](https://velocity.silverlakesoftware.com), or
[Zeal](https://zealdocs.org).

The docset can be created with

```sh
make JSON_for_Modern_C++.docset
```

The generated folder `JSON_for_Modern_C++.docset` can then be opened in the documentation browser. `make all` builds a
`JSON_for_Modern_C++.tgz` archive instead, and `make install_docset_zeal` installs the docset for Zeal directly.

A recent version is also part of the [Dash user contributions](https://github.com/Kapeli/Dash-User-Contributions/tree/master/docsets/JSON_for_Modern_C%2B%2B).

## Licenses

The [JSON logo](https://commons.wikimedia.org/wiki/File:JSON_vector_logo.svg) is public domain.

# Documentation

## Generate documentation

Note on documentation: The source files contain links to the online documentation at https://json.nlohmann.me. This URL
contains the most recent documentation and should also be applicable to previous versions; documentation for deprecated
functions is not removed, but marked deprecated.

If you want to see the documentation for a specific tag or commit hash, you can generate it as follows (here for tag
`v3.10.2`):

```shell
git clone https://github.com/nlohmann/json.git
cd json
git checkout v3.10.2
make install_venv serve -C docs/mkdocs
```

Open URL <http://127.0.0.1:8000/> in your browser. Replace from any URL from the source code `https://json.nlohmann.me`
with `http://127.0.0.1:8000` to see the documentation for your tag or commit hash.

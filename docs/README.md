# Documentation

## Generate documentation

Note on documentation: The source files contain links to the online documentation at https://json.nlohmann.me.  
This URL provides the most recent documentation and also applies to previous versions. Documentation for deprecated
functions is not removed; instead, it is marked as deprecated.

If you want to view the documentation for a specific tag or commit hash, you can generate it locally as follows (example
using tag `v3.10.2`):

```shell
git clone https://github.com/nlohmann/json.git
cd json
git checkout v3.10.2
make install_venv serve -C docs/mkdocs
```

Open <http://127.0.0.1:8000/> in your browser. Replace any URL in the source code that points to
`https://json.nlohmann.me` with `http://127.0.0.1:8000` to view the documentation for the selected tag or commit hash.




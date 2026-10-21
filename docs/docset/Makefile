SHELL=/usr/bin/env bash
PYTHON=../mkdocs/venv/bin/python3

.PHONY: all
all: JSON_for_Modern_C++.tgz

# generate the search index (the docset target does this itself, this is
# only handy for inspecting the index)
docSet.dsidx: generate_docset.py
	$(PYTHON) generate_docset.py index docSet.dsidx

# build the documentation and turn it into a self-contained docset
.PHONY: JSON_for_Modern_C++.docset
JSON_for_Modern_C++.docset:
	$(MAKE) install_venv -C ../mkdocs
	$(MAKE) build -C ../mkdocs
	$(PYTHON) generate_docset.py docset ../mkdocs/site .

.PHONY: JSON_for_Modern_C++.tgz
JSON_for_Modern_C++.tgz: JSON_for_Modern_C++.docset
	$(PYTHON) generate_docset.py tgz .

# install docset for Zeal documentation browser (https://zealdocs.org/)
.PHONY: install_docset_zeal
install_docset_zeal: JSON_for_Modern_C++.docset
	docset_root=$${XDG_DATA_HOME:-$$HOME/.local/share}/Zeal/Zeal/docsets; \
	rm -rf $$docset_root/JSON_for_Modern_C++.docset; \
	mkdir -p $$docset_root; \
	cp -r JSON_for_Modern_C++.docset $$docset_root/

.PHONY: clean
clean:
	rm -f docSet.dsidx
	rm -fr JSON_for_Modern_C++.docset JSON_for_Modern_C++.tgz

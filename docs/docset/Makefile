SHELL=/usr/bin/env bash
SED ?= $(shell which gsed 2>/dev/null || which sed)

MKDOCS_PAGES=$(shell cd ../mkdocs/docs/ && find * -type f -name '*.md' | sort)

.PHONY: all
all: JSON_for_Modern_C++.tgz

docSet.dsidx: docSet.sql
	# generate index
	sqlite3 docSet.dsidx <docSet.sql

JSON_for_Modern_C++.docset: Info.plist docSet.dsidx
	rm -fr JSON_for_Modern_C++.docset JSON_for_Modern_C++.tgz
	mkdir -p JSON_for_Modern_C++.docset/Contents/Resources/Documents/
	cp icon*.png JSON_for_Modern_C++.docset
	cp Info.plist JSON_for_Modern_C++.docset/Contents
	# build and copy documentation
	$(MAKE) build -C ../mkdocs
	cp -r ../mkdocs/site/* JSON_for_Modern_C++.docset/Contents/Resources/Documents
	# patch CSS to hide navigation items
	echo -e "\n\nheader, footer, nav.md-tabs, nav.md-tabs--active, div.md-sidebar--primary, a.md-content__button { display: none; }" >> "$$(ls JSON_for_Modern_C++.docset/Contents/Resources/Documents/assets/stylesheets/main.*.min.css)"
	# fix spacing
	echo -e "\n\ndiv.md-sidebar div.md-sidebar--secondary, div.md-main__inner { top: 0; margin-top: 0 }" >> "$$(ls JSON_for_Modern_C++.docset/Contents/Resources/Documents/assets/stylesheets/main.*.min.css)"
	# remove "JSON for Modern C++" from page titles (fallback)
	find JSON_for_Modern_C++.docset/Contents/Resources/Documents -type f -exec $(SED) -i 's| - JSON for Modern C++</title>|</title>|' {} +
	# replace page titles with name from index, if available
	for page in $(MKDOCS_PAGES); do \
		case "$$page" in \
			*/index.md) path=$${page/\/index.md/} ;; \
			*)          path=$${page/.md/}        ;; \
		esac; \
		title=$$(sqlite3 docSet.dsidx "SELECT name FROM searchIndex WHERE path='$$path/index.html'" | tr '\n' ',' | $(SED) -e 's/,/, /g' -e 's/, $$/\n/'); \
		if [ "x$$title" != "x" ]; then \
			$(SED) -i "s%<title>.*</title>%<title>$$title</title>%" "JSON_for_Modern_C++.docset/Contents/Resources/Documents/$$path/index.html"; \
		fi \
	done
	# clean up
	rm JSON_for_Modern_C++.docset/Contents/Resources/Documents/sitemap.*
	# copy index
	cp docSet.dsidx JSON_for_Modern_C++.docset/Contents/Resources/

JSON_for_Modern_C++.tgz: JSON_for_Modern_C++.docset
	tar --exclude='.DS_Store' -cvzf JSON_for_Modern_C++.tgz JSON_for_Modern_C++.docset

# install docset for Zeal documentation browser (https://zealdocs.org/)
.PHONY: install_docset_zeal
install_docset_zeal: JSON_for_Modern_C++.docset
	docset_root=$${XDG_DATA_HOME:-$$HOME/.local/share}/Zeal/Zeal/docsets; \
	rm -rf $$docset_root/JSON_for_Modern_C++.docset; \
	mkdir -p $$docset_root; \
	cp -r JSON_for_Modern_C++.docset $$docset_root/

# list mkdocs pages missing from the docset index
.PHONY: list_missing_pages
list_missing_pages: docSet.dsidx
	@for page in $(MKDOCS_PAGES); do \
		case "$$page" in \
			*/index.md) path=$${page/\/index.md/} ;; \
			*)          path=$${page/.md/}        ;; \
		esac; \
		if [ "x$$page" != "xindex.md" -a "x$$(sqlite3 docSet.dsidx "SELECT COUNT(*) FROM searchIndex WHERE path='$$path/index.html'")" = "x0" ]; then \
			echo $$page; \
		fi \
	done

# list paths in the docset index without a corresponding mkdocs page
.PHONY: list_removed_paths
list_removed_paths: docSet.dsidx
	@for path in $$(sqlite3 docSet.dsidx "SELECT path FROM searchIndex"); do \
		page=$${path/\/index.html/.md}; \
		page_index=$${path/index.html/index.md}; \
		page_found=0; \
		for p in $(MKDOCS_PAGES); do \
			if [ "x$$p" = "x$$page" -o "x$$p" = "x$$page_index" ]; then \
				page_found=1; \
			fi \
		done; \
		if [ "x$$page_found" = "x0" ]; then \
			echo $$path; \
		fi \
	done

.PHONY: clean
clean:
	rm -f docSet.dsidx
	rm -fr JSON_for_Modern_C++.docset JSON_for_Modern_C++.tgz

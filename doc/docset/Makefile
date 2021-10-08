JSON_for_Modern_C++.docset: Info.plist docSet.sql
	$(MAKE) clean
	mkdir -p JSON_for_Modern_C++.docset/Contents/Resources/Documents/
	cp icon*.png JSON_for_Modern_C++.docset
	cp Info.plist JSON_for_Modern_C++.docset/Contents
	# build and copy documentation
	$(MAKE) build -C ../mkdocs
	cp -r ../mkdocs/site/* JSON_for_Modern_C++.docset/Contents/Resources/Documents
	# patch CSS to hide navigation items
	echo "\n\nheader, footer, navi, div.md-sidebar--primary, nav.md-tabs--active, a.md-content__button { display: none; }" >> "$$(ls JSON_for_Modern_C++.docset/Contents/Resources/Documents/assets/stylesheets/main.*.min.css)"
	# fix spacing
	echo "\n\ndiv.md-sidebar div.md-sidebar--secondary, div.md-main__inner { top: 0; margin-top: 0 }" >> "$$(ls JSON_for_Modern_C++.docset/Contents/Resources/Documents/assets/stylesheets/main.*.min.css)"
	# remove "JSON for Modern C++" from page titles
	find JSON_for_Modern_C++.docset/Contents/Resources/Documents -type f -exec gsed -i 's| - JSON for Modern C++</title>|</title>|' {} +
	# clean up
	rm JSON_for_Modern_C++.docset/Contents/Resources/Documents/hooks.py
	rm JSON_for_Modern_C++.docset/Contents/Resources/Documents/sitemap.*
	# generate index
	sqlite3 JSON_for_Modern_C++.docset/Contents/Resources/docSet.dsidx < docSet.sql

JSON_for_Modern_C++.tgz: JSON_for_Modern_C++.docset
	tar --exclude='.DS_Store' -cvzf JSON_for_Modern_C++.tgz JSON_for_Modern_C++.docset

clean:
	rm -fr JSON_for_Modern_C++.docset JSON_for_Modern_C++.tgz

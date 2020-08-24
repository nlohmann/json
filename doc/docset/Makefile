nlohmann_json.docset: Info.plist docSet.sql
	$(MAKE) clean
	mkdir -p nlohmann_json.docset/Contents/Resources/Documents/
	cp info.plist nlohmann_json.docset/Contents
	# build and copy documentation
	$(MAKE) build -C ../mkdocs
	cp -r ../mkdocs/site/* nlohmann_json.docset/Contents/Resources/Documents
	# patch CSS to hide navigation items
	echo "\n\nheader, footer, navi, div.md-sidebar--primary, nav.md-tabs--active, a.md-content__button { display: none; }" >> nlohmann_json.docset/Contents/Resources/Documents/assets/stylesheets/main.b5d04df8.min.css
	# fix spacing
	echo "\n\ndiv.md-sidebar div.md-sidebar--secondary, div.md-main__inner { top: 0; margin-top: 0 }" >> nlohmann_json.docset/Contents/Resources/Documents/assets/stylesheets/main.b5d04df8.min.css
	# remove "JSON for Modern C++" from page titles
	find nlohmann_json.docset/Contents/Resources/Documents -type f -exec gsed -i 's| - JSON for Modern C++</title>|</title>|' {} +
	# clean up
	rm nlohmann_json.docset/Contents/Resources/Documents/hooks.py
	rm nlohmann_json.docset/Contents/Resources/Documents/sitemap.*
	# generate index
	sqlite3 nlohmann_json.docset/Contents/Resources/docSet.dsidx < docSet.sql

clean:
	rm -fr nlohmann_json.docset

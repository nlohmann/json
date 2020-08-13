nlohmann_json.docset: Info.plist docSet.sql
	$(MAKE) clean
	mkdir -p nlohmann_json.docset/Contents/Resources/Documents/
	cp info.plist nlohmann_json.docset/Contents
	sqlite3 nlohmann_json.docset/Contents/Resources/docSet.dsidx < docSet.sql

clean:
	rm -fr nlohmann_json.docset

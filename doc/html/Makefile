DOCSET_NAME=me.nlohmann.json.docset
DOCSET_CONTENTS=$(DOCSET_NAME)/Contents
DOCSET_RESOURCES=$(DOCSET_CONTENTS)/Resources
DOCSET_DOCUMENTS=$(DOCSET_RESOURCES)/Documents
DESTDIR=~/Library/Developer/Shared/Documentation/DocSets
XCODE_INSTALL="$(shell xcode-select -print-path)"

all: docset

docset:
	mkdir -p $(DOCSET_DOCUMENTS)
	cp Nodes.xml $(DOCSET_RESOURCES)
	cp Tokens.xml $(DOCSET_RESOURCES)
	cp Info.plist $(DOCSET_CONTENTS)
	tar --exclude $(DOCSET_NAME) \
	    --exclude Nodes.xml \
	    --exclude Tokens.xml \
	    --exclude Info.plist \
	    --exclude Makefile -c -f - . \
	    | (cd $(DOCSET_DOCUMENTS); tar xvf -)
	$(XCODE_INSTALL)/usr/bin/docsetutil index $(DOCSET_NAME)
	rm -f $(DOCSET_DOCUMENTS)/Nodes.xml
	rm -f $(DOCSET_DOCUMENTS)/Info.plist
	rm -f $(DOCSET_DOCUMENTS)/Makefile
	rm -f $(DOCSET_RESOURCES)/Nodes.xml
	rm -f $(DOCSET_RESOURCES)/Tokens.xml

clean:
	rm -rf $(DOCSET_NAME)

install: docset
	mkdir -p $(DESTDIR)
	cp -R $(DOCSET_NAME) $(DESTDIR)

uninstall:
	rm -rf $(DESTDIR)/$(DOCSET_NAME)

always:

serve: prepare_files
	venv/bin/mkdocs serve

prepare_files:
	# build Doxygen
	$(MAKE) -C ..
	# clean subfolders
	rm -fr docs/images docs/examples
	# create subfolders
	mkdir docs/images docs/examples
	# copy images
	cp -vr ../json.gif docs/images
	# copy examples
	cp -vr ../examples/*.cpp ../examples/*.output docs/examples

publish: prepare_files
	venv/bin/mkdocs gh-deploy --clean --force

install_venv:
	python3 -mvenv venv
	venv/bin/pip install -r requirements.txt

uninstall_venv:
	rm -fr venv

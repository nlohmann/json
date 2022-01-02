# serve the site locally
serve: prepare_files
	venv/bin/mkdocs serve

build: prepare_files
	venv/bin/mkdocs build

# create files that are not versioned inside the mkdocs folder
prepare_files: clean
	# create subfolders
	mkdir docs/examples
	# copy images
	cp -vr ../json.gif docs/images
	# copy examples
	cp -vr ../examples/*.cpp ../examples/*.output docs/examples

# clean subfolders
clean:
	rm -fr docs/images/json.gif docs/examples

# publish site to GitHub pages
publish: prepare_files
	venv/bin/mkdocs gh-deploy --clean --force

# install a Python virtual environment
install_venv: requirements.txt
	python3 -mvenv venv
	venv/bin/pip install wheel
	venv/bin/pip install -r requirements.txt

# uninstall the virtual environment
uninstall_venv: clean
	rm -fr venv

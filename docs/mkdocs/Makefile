# serve the site locally
serve: prepare_files style_check
	venv/bin/mkdocs serve

serve_dirty: prepare_files style_check
	venv/bin/mkdocs serve --dirtyreload

build: prepare_files style_check
	venv/bin/mkdocs build

# create files that are not versioned inside the mkdocs folder (images, examples)
prepare_files: clean
	mkdir docs/examples
	cp -r ../json.gif docs/images
	cp -r ../examples/*.cpp ../examples/*.output docs/examples

style_check:
	@cd docs ; python3 ../scripts/check_structure.py

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

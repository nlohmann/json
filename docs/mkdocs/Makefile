# serve the site locally
serve: style_check
	venv/bin/mkdocs serve

serve_dirty: style_check
	venv/bin/mkdocs serve --dirtyreload

# This target is used in the CI (ci_test_build_documentation).
# This target is used by the docset Makefile.
build: style_check
	venv/bin/mkdocs build

style_check:
	@cd docs ; ../venv/bin/python3 ../scripts/check_structure.py

# check the links in the documentation files in docs/mkdocs
link_check:
	ENABLED_HTMLPROOFER=true venv/bin/mkdocs build

# check the links in all other Markdown files
link_check_markdowns:
	npx markdown-link-check --progress --alive 200,429 ../../README.md ../../FILES.md ../../.github/*.md

# publish site to GitHub pages (not working in GitHub Actions; need special action)
publish:
	venv/bin/mkdocs gh-deploy --clean --force

# install a Python virtual environment
# This target is used by the docset Makefile.
install_venv: requirements.txt
	python3 -mvenv venv
	venv/bin/pip install --upgrade pip
	venv/bin/pip install -r requirements.txt

# uninstall the virtual environment
uninstall_venv:
	rm -fr venv

update_requirements:
	rm -fr venv_small
	python3 -mvenv venv_small
	venv_small/bin/pip3 install pur
	venv_small/bin/pur -r requirements.txt
	rm -fr venv_small venv
	make install_venv

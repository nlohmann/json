# Rebuild the animated feature slideshow of the home page (docs/images/json-light.svg and json-dark.svg) when
# slides.md, build.py or the fonts change. Needs uv (build.py declares its dependencies inline, PEP 723), curl,
# unzip and shasum. Run it from docs/mkdocs/scripts/slideshow.
#
#   make                 download missing fonts and build both SVGs
#   make fonts           download only the fonts
#   make SECONDS=12      change the time per slide
#   make clean           remove the generated SVGs
#   make distclean       also remove the downloaded fonts

SECONDS      ?= 15

IMAGES := ../../docs/images
LIGHT  := $(IMAGES)/json-light.svg
DARK   := $(IMAGES)/json-dark.svg

RUN   := uv run --script build.py
FONTS := fonts/Inter.ttf fonts/JetBrainsMono.ttf
DEPS  := build.py slides.md $(FONTS)

# Pinned sources; the checksums make a changed upstream file fail instead of silently changing the output.
# Inter: Google Fonts repository at a fixed commit (variable font with opsz and wght axes).
INTER_URL := https://raw.githubusercontent.com/google/fonts/0b58fb370093f9a9f4ff785d94405710b79de67c/ofl/inter/Inter%5Bopsz%2Cwght%5D.ttf
# JetBrains Mono: release 2.304 (the variable font in fonts/variable/ of the zip).
JBM_URL   := https://github.com/JetBrains/JetBrainsMono/releases/download/v2.304/JetBrainsMono-2.304.zip
JBM_ZIP   := fonts/JetBrainsMono-2.304.zip

SHA256_Inter.ttf                := 29160a80ff49ddcab2c97711247e08b1fab27a484a329ce8b813d820dc559031
SHA256_JetBrainsMono.ttf        := 662a196d58f1183bf2d77428b6d5283fe3f45161ab021bea4036bc98e5cac016
SHA256_JetBrainsMono-2.304.zip  := 6f6376c6ed2960ea8a963cd7387ec9d76e3f629125bc33d1fdcd7eb7012f7bbf

# Check $@.tmp against its pinned checksum, then move it into place.
define verify
	echo '$(SHA256_$(notdir $@))  $@.tmp' | shasum -a 256 -c --quiet - || { rm -f $@.tmp; exit 1; }
	mv $@.tmp $@
endef

.PHONY: all fonts clean distclean
.INTERMEDIATE: $(JBM_ZIP)

all: $(LIGHT) $(DARK)

fonts: $(FONTS)

# fixed colours for the docs: an <img> cannot see Material's theme toggle, so the home page includes both
# and shows the one that matches
$(LIGHT): $(DEPS)
	$(RUN) $@.tmp $(SECONDS) light
	mv $@.tmp $@

$(DARK): $(DEPS)
	$(RUN) $@.tmp $(SECONDS) dark
	mv $@.tmp $@

fonts/Inter.ttf:
	mkdir -p fonts
	curl -fsSL -m 300 -o $@.tmp '$(INTER_URL)'
	$(verify)

$(JBM_ZIP):
	mkdir -p fonts
	curl -fsSL -m 300 -o $@.tmp '$(JBM_URL)'
	$(verify)

fonts/JetBrainsMono.ttf: | $(JBM_ZIP)
	unzip -p $(JBM_ZIP) 'fonts/variable/JetBrainsMono[[]wght].ttf' > $@.tmp
	$(verify)

clean:
	rm -f $(LIGHT) $(DARK) $(IMAGES)/*.svg.tmp

distclean: clean
	rm -f $(FONTS) fonts/*.tmp $(JBM_ZIP)

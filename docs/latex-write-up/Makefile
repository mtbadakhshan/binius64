# Build the Akita bridge spec into ./build/akita-bridge.pdf.
#
# Targets:
#   make            — compile the spec (default)
#   make watch      — recompile on every save (requires latexmk)
#   make clean      — remove build/

TARGET = akita-bridge
BUILDDIR = build

.PHONY: all watch clean view

all: $(BUILDDIR)/$(TARGET).pdf

$(BUILDDIR)/$(TARGET).pdf: $(TARGET).tex
	@mkdir -p $(BUILDDIR)
	latexmk $(TARGET).tex

watch:
	@mkdir -p $(BUILDDIR)
	latexmk -pvc $(TARGET).tex

view: $(BUILDDIR)/$(TARGET).pdf
	@open $(BUILDDIR)/$(TARGET).pdf

clean:
	rm -rf $(BUILDDIR)

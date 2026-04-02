SPHINXBUILD = sphinx-build
SOURCEDIR   = source
BUILDDIR    = build

.PHONY: html clean livehtml

html:
	$(SPHINXBUILD) -b html $(SOURCEDIR) $(BUILDDIR)/html
	@echo "Done: $(BUILDDIR)/html/index.html"

clean:
	rm -rf $(BUILDDIR)

livehtml:
	sphinx-autobuild $(SOURCEDIR) $(BUILDDIR)/html

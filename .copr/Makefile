# Entry point for COPR's "Custom" source method: Build Settings -> Source ->
# Custom, with "Path to Makefile" = .copr/Makefile, target "srpm", and
# "Builder host dependencies" = `rpm-build tar gzip`. COPR checks out this
# repo at build time and runs `make -f .copr/Makefile srpm outdir=<dir>`,
# then expects exactly one .src.rpm to exist in <dir>. COPR itself builds
# the binary noarch RPM from that srpm on its own workers - this target only
# needs to produce a valid source RPM, not run the build/test suite (that
# already happens locally via packaging/rpm/build-rpm.sh, see
# packaging/rpm/README.md for the one remaining manual step this can't do:
# registering a COPR project under a maintainer's Fedora account).

outdir ?= $(CURDIR)
NAME := ipa-diagnose
VERSION := $(shell grep -m1 '^version' pyproject.toml | sed -E 's/version = "(.*)"/\1/')
TOPDIR := $(shell mktemp -d)

.PHONY: srpm
srpm:
	mkdir -p "$(TOPDIR)/SOURCES" "$(TOPDIR)/SPECS" "$(TOPDIR)/SRPMS"
	tar czf "$(TOPDIR)/SOURCES/$(NAME)-$(VERSION).tar.gz" \
		--exclude-vcs \
		--exclude="./dist" --exclude="./build" --exclude="./*.egg-info" \
		--exclude="./artifacts" --exclude="./.pytest_cache" \
		--exclude="./packaging/rpm/rpmbuild" \
		--transform "s,^\.,$(NAME)-$(VERSION)," .
	cp packaging/rpm/ipa-diagnose.spec "$(TOPDIR)/SPECS/"
	rpmbuild --define "_topdir $(TOPDIR)" --define "version $(VERSION)" --define "release 1" \
		-bs "$(TOPDIR)/SPECS/$(NAME).spec"
	mkdir -p "$(outdir)"
	cp "$(TOPDIR)"/SRPMS/*.src.rpm "$(outdir)/"
	rm -rf "$(TOPDIR)"

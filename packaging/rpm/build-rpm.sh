#!/usr/bin/env bash
# Builds the ipa-diagnose RPM from the current working tree. Intended to run
# INSIDE the rpmbuild container (see packaging/rpm/Dockerfile.rpmbuild) -
# never on the host. Produces /rpmbuild/RPMS/noarch/*.rpm and
# /rpmbuild/SRPMS/*.src.rpm.
set -euo pipefail

SRC_DIR="${SRC_DIR:-/src}"
TOPDIR="${TOPDIR:-/rpmbuild}"
NAME=ipa-diagnose
PYPROJECT_VERSION="$(grep -m1 '^version' "${SRC_DIR}/pyproject.toml" | sed -E 's/version = "(.*)"/\1/')"
# BUILD_VERSION lets the upgrade/downgrade install test build a second,
# bumped release without permanently touching the tracked pyproject.toml.
VERSION="${BUILD_VERSION:-${PYPROJECT_VERSION}}"
RELEASE="${BUILD_RELEASE:-1}"

echo "Building ${NAME}-${VERSION}-${RELEASE} (pyproject.toml declares ${PYPROJECT_VERSION})"

# Note: TOPDIR is typically a bind-mounted volume root, so its subdirectories
# are removed individually rather than `rm -rf "${TOPDIR}"` itself (which
# fails with "Device or resource busy" on a mount point).
rm -rf "${TOPDIR}"/{SOURCES,SPECS,RPMS,SRPMS,BUILD,BUILDROOT}
mkdir -p "${TOPDIR}"/{SOURCES,SPECS,RPMS,SRPMS,BUILD,BUILDROOT}
WORK="$(mktemp -d)"
cp -a "${SRC_DIR}/." "${WORK}/"
if [ "${VERSION}" != "${PYPROJECT_VERSION}" ]; then
    sed -i -E "s/^version = \".*\"/version = \"${VERSION}\"/" "${WORK}/pyproject.toml"
fi

tar czf "${TOPDIR}/SOURCES/${NAME}-${VERSION}.tar.gz" \
    --exclude-vcs \
    --exclude="./dist" \
    --exclude="./build" \
    --exclude="./*.egg-info" \
    --exclude="./artifacts" \
    --exclude="./.pytest_cache" \
    --exclude="./packaging/rpm/rpmbuild" \
    --transform "s,^\.,${NAME}-${VERSION}," \
    -C "${WORK}" .
rm -rf "${WORK}"

cp "${SRC_DIR}/packaging/rpm/ipa-diagnose.spec" "${TOPDIR}/SPECS/"

rpmbuild --define "_topdir ${TOPDIR}" \
    --define "version ${VERSION}" \
    --define "release ${RELEASE}" \
    -ba "${TOPDIR}/SPECS/${NAME}.spec"

echo
echo "Built artifacts:"
find "${TOPDIR}/RPMS" "${TOPDIR}/SRPMS" -type f -name '*.rpm'

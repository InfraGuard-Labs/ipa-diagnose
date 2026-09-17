#!/usr/bin/env bash
# Builds the ipa-diagnose RPM for EL9 from the current working tree.
# Intended to run INSIDE the el9 build container (see
# packaging/rpm/el9/Dockerfile.build) - never on the host. Produces
# /rpmbuild/RPMS/noarch/*.rpm and /rpmbuild/SRPMS/*.src.rpm. Mirrors
# packaging/rpm/build-rpm.sh (the Fedora build script) but uses the
# EL9-specific spec at packaging/rpm/el9/ipa-diagnose.spec.
set -euo pipefail

SRC_DIR="${SRC_DIR:-/src}"
TOPDIR="${TOPDIR:-/rpmbuild}"
NAME=ipa-diagnose
PYPROJECT_VERSION="$(grep -m1 '^version' "${SRC_DIR}/pyproject.toml" | sed -E 's/version = "(.*)"/\1/')"
VERSION="${BUILD_VERSION:-${PYPROJECT_VERSION}}"
RELEASE="${BUILD_RELEASE:-1}"

echo "Building ${NAME}-${VERSION}-${RELEASE} for EL9 (pyproject.toml declares ${PYPROJECT_VERSION})"

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
    --exclude="./packaging/rpm/el9/rpmbuild" \
    --transform "s,^\.,${NAME}-${VERSION}," \
    -C "${WORK}" .
rm -rf "${WORK}"

cp "${SRC_DIR}/packaging/rpm/el9/ipa-diagnose.spec" "${TOPDIR}/SPECS/"

rpmbuild --define "_topdir ${TOPDIR}" \
    --define "version ${VERSION}" \
    --define "release ${RELEASE}" \
    -ba "${TOPDIR}/SPECS/${NAME}.spec"

echo
echo "Built artifacts:"
find "${TOPDIR}/RPMS" "${TOPDIR}/SRPMS" -type f -name '*.rpm'

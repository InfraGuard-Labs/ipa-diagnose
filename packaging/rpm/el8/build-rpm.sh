#!/usr/bin/env bash
# Builds the ipa-diagnose EL8 RPM from the current working tree. Intended to
# run INSIDE the packaging/rpm/el8/Dockerfile.build container - never on the
# host. Produces /rpmbuild/RPMS/noarch/*.rpm and /rpmbuild/SRPMS/*.src.rpm,
# built against EL8's python39 AppStream module (see ipa-diagnose.spec).
set -euo pipefail

SRC_DIR="${SRC_DIR:-/src}"
TOPDIR="${TOPDIR:-/rpmbuild}"
NAME=ipa-diagnose
PYPROJECT_VERSION="$(grep -m1 '^version' "${SRC_DIR}/pyproject.toml" | sed -E 's/version = "(.*)"/\1/')"
VERSION="${BUILD_VERSION:-${PYPROJECT_VERSION}}"
RELEASE="${BUILD_RELEASE:-1}"

echo "Building ${NAME}-${VERSION}-${RELEASE} for EL8/python39 (pyproject.toml declares ${PYPROJECT_VERSION})"

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
    --exclude="./packaging/rpm/el8/rpmbuild" \
    --transform "s,^\.,${NAME}-${VERSION}," \
    -C "${WORK}" .
rm -rf "${WORK}"

cp "${SRC_DIR}/packaging/rpm/el8/ipa-diagnose.spec" "${TOPDIR}/SPECS/"

rpmbuild --define "_topdir ${TOPDIR}" \
    --define "version ${VERSION}" \
    --define "release ${RELEASE}" \
    -ba "${TOPDIR}/SPECS/${NAME}.spec"

echo
echo "Built artifacts:"
find "${TOPDIR}/RPMS" "${TOPDIR}/SRPMS" -type f -name '*.rpm'

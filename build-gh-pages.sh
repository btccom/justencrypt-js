#!/bin/sh

# grunt

PROJECTDIR=$(pwd)
TMPDIR=$(uuidgen)

git clone `git config --get remote.origin.url` -b gh-pages /tmp/${TMPDIR} && \
cd /tmp/${TMPDIR} && \
cp -rf ${PROJECTDIR}/build/*.js /tmp/${TMPDIR}/build && \
cp -rf ${PROJECTDIR}/node_modules/mocha/mocha.js /tmp/${TMPDIR}/build && \
cp -rf ${PROJECTDIR}/node_modules/mocha/mocha.css /tmp/${TMPDIR}/build && \
cp -rf ${PROJECTDIR}/test/run-tests.html /tmp/${TMPDIR}/index.html && \
sed -i 's/\.\.\///g' /tmp/${TMPDIR}/index.html && \
sed -i 's/node_modules\/mocha/build/g' /tmp/${TMPDIR}/index.html && \
git add -A && \
git commit -am "new build" && \
git push origin gh-pages  && \
echo "DONE!"

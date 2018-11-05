#!/bin/bash

echo "$(date) Build started"

mvn install:install-file \
   -Dfile=lib/crypto.gammaprov.jar \
   -DgroupId=kz.gamma \
   -DartifactId=crypto-gammaprov \
   -Dversion=2.0.1.1140 \
   -Dpackaging=jar \
   -DgeneratePom=true

mvn install -Dmaven.javadoc.skip=true -B -V

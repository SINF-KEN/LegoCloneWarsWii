#!/bin/zsh

set -e

export JAVA_HOME=$(/usr/libexec/java_home -v 21)

"$HOME/Decomp/tools/ghidra/support/analyzeHeadless" \
    "$HOME/Decomp/ghidra-projects" \
    LegoCloneWarsWii \
    -process main.dol \
    -noanalysis \
    -postScript ExportDataCatalog.java \
    -scriptPath "$HOME/Decomp/LegoCloneWarsWii/tools/ghidra"

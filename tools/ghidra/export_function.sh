#!/bin/zsh

set -e

if [[ $# -ne 1 ]]; then
    echo "Usage: $0 <address>"
    exit 1
fi

export JAVA_HOME=$(/usr/libexec/java_home -v 21)

"$HOME/Decomp/tools/ghidra/support/analyzeHeadless" \
    "$HOME/Decomp/ghidra-projects" \
    LegoCloneWarsWii \
    -process main.dol \
    -noanalysis \
    -postScript ExportFunctionContext.java "$1" \
    -scriptPath "$HOME/Decomp/LegoCloneWarsWii/tools/ghidra"

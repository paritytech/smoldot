#!/bin/bash
#   Adds package.json files to cjs/mjs subtrees with the respective type needed for
#   the target environment.
#

cat >dist/cjs/package.json <<!EOF
{
    "type": "commonjs"
}
!EOF

cat >dist/mjs/package.json <<!EOF
{
    "type": "module"
}
!EOF
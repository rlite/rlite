#!/bin/bash

git log --no-merges --pretty=format:"%H%n" | tac > .shas

test -f hist && rm hist

first=1
for l in $(cat .shas); do
    # extract the SHA and Unix timestamp
    s=$(echo $l | cut -d" " -f 1)
    if [ $first == "1" ]; then
        t=$(git log --pretty=format:"%at" $s)
        first=0
    else
        t=$(git log --pretty=format:"%at" $s~1..$s)
    fi

    # checkout to the SHA
    git checkout $s &> /dev/null

    # count the number lines
    c=$(find kernel user include -type f -and \( -name "*.c" -or -name "*.h" -or -name "*.cpp" -or -name "*.hpp" \) | xargs wc -l | tail -n 1 | sed 's|^[ \t]\+||g' | cut -d' ' -f 1)
    echo "$t: $c"
    echo $t $c >> hist
done

rm .shas

git checkout master

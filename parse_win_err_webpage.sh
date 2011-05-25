#!/bin/sh

wget -q $1 -O - | egrep '(id=|<dt>|<p>)' | grep -v input | grep -v '<tr><td><a' | tr -d '/' | grep -B 2 '<p>' | cut -d '>' -f2 | cut -d '<' -f 1
#!/bin/bash

if [ $# == 0 ]; then
    echo "Usage: $0 /path/to/nmap/xml/output"
    exit 0
fi

FILES=$1

#do not process *.xml if there are no xml files in directory
shopt -s nullglob

for f in $FILES*.xml
do
  # take action on each file. $f store current file name
  xsltproc "$f" -o "$f.html"
done

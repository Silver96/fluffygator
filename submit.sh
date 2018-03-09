#!/bin/bash

if [ $# -eq 0 ]
  then
	echo "usage: submit.sh students_dir"
	exit 1
fi


paths=$(grep -rn $USER $1 | cut -f1 -d':')
files=$(for p in $paths; do basename $p; done)

cp $paths .
tar czvf CMPS122-Lab3-Phase4.tar.gz $files
cp CMPS122-Lab3-Phase4.tar.gz ~/
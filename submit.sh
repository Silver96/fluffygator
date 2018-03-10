#!/bin/bash

if [ $# -eq 0 ]
  then
	echo "usage: submit.sh students_dir"
	exit 1
fi


paths=$(grep -rn $USER $1 | cut -f1 -d':')

i=0
files=""
for p in $paths; do 
    i=$(($i + 1))
    cp $p plain$i
    files="$files plain$i"
done

tar czvf CMPS122-Lab3-Phase3.tar.gz $files
# cp CMPS122-Lab3-Phase3.tar.gz ~/

while read -r pass; do python3 cracker_test.py -p $pass; done < $1

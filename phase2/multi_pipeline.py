import sys
import socket
import os
import subprocess

def main():
    if len(sys.argv) < 2:
        print("Usage: %s dir_name" % sys.argv[0])
        exit(1)

    students_dir = sys.argv[1]

    for student_id in range(len(os.listdir(students_dir))):
        student_dir = "%s/%d/" % (students_dir, student_id)

        cmd = "python3 pipeline.py %s" % student_dir
        print(cmd)

        subprocess.Popen(cmd.split(' '))

main()
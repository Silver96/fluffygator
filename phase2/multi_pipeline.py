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
        passwd_file = student_dir + "/passwd.plain"

        passwd = ""

        if os.path.isfile(passwd_file):
            with open(passwd_file, "rt") as file:
                passwd = file.read()


        cmd = "python3 pipeline.py %s %s" % (student_dir, passwd)
        print(cmd)

        subprocess.Popen(cmd.split(' '))

main()
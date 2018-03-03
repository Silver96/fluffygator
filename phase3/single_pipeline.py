import sys
import socket
import os
import subprocess

FAILED_LIST = "failed"

def main():
    if len(sys.argv) < 2:
        print("Usage: %s dir_name start_num" % sys.argv[0])
        exit(1)

    students_dir = sys.argv[1]
    start = 0


    if len(sys.argv) == 3:
        start = int(sys.argv[2])

    with open(FAILED_LIST, "at") as f_failed:

        for student_id in range(start, len(os.listdir(students_dir))):
            student_dir = "%s/%d/" % (students_dir, student_id)
            passwd_file = student_dir + "/passwd.plain"

            passwd = ""

            if os.path.isfile(passwd_file):
                with open(passwd_file, "rt") as file:
                    passwd = file.read()


            cmd = "python3 pipeline.py %s %s" % (student_dir, passwd)
            # print(cmd)

            # subprocess.Popen(cmd.split(' '))
            if subprocess.run(cmd.split(' ')).returncode == 2:
                f_failed.write(str(student_id))
                f_failed.write("\n")
                f_failed.flush()
main()
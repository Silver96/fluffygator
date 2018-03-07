import sys
import socket
import os
import subprocess

FAILED_LIST = "failed"

def main():
    if len(sys.argv) < 3:
        print("Usage: %s dir_name msg_count" % sys.argv[0])
        exit(1)

    students_dir = sys.argv[1]
    msg_count = int(sys.argv[2])

    with open(FAILED_LIST, "wt") as f_failed:

        for student_id in range(len(os.listdir(students_dir))):
            student_dir = "%s/%d/" % (students_dir, student_id)
            
            cmd = "python3 pipeline.py %s %d" % (student_dir, msg_count)
            
            if subprocess.run(cmd.split(' ')).returncode != 0:
                f_failed.write(str(student_id))
                f_failed.write("\n")
                f_failed.flush()
main()
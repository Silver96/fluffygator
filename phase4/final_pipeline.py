import sys
import socket
import os
import subprocess
import time
import argparse

def print_main_message(string):
    print("#"*80)
    print(string)

def main():

    def capture_packets(args):
        print_main_message("Starting packet capture...")
        cmd = "python3 capture_packets.py --working-dir %s/packets/" % args.working_dir + ((" -t %s" % args.start_time) if args.start_time else "") + ((" -m %d" % args.max_packets) if args.max_packets else "") + ((" --timeout %d" % args.timeout) if args.timeout else "")
        subprocess.run(cmd.split(" "), stdout=stdout, stderr=stderr)
        print_main_message("%d packets captured" % len(os.listdir(args.working_dir+"/packets/")))

    def inspect_packets(args):
        print_main_message("Starting packet inspection...")
        cmd = "python3 inspect_packets.py %s %d %d --working-dir %s/students/" % (args.working_dir+"/packets/", args.tuples_count, args.msg_count, args.working_dir)
        subprocess.run(cmd.split(" "), stdout=stdout, stderr=stderr)
        print_main_message("%d tuple directories generated" % len(os.listdir(args.working_dir+"/students/")))

    def cast_pipelines(args):
        max_processes = 3
        failed_list = "failed"
        pipeline_file = "pipeline_no_deobf.py"

        if args.m:
            max_processes = args.m

        if args.pipeline:
            pipeline_file = args.pipeline

        if args.failed:
            failed_list = args.failed

        l = []

        students_dir = args.working_dir+"/students"


        print_main_message("Launching pipeline processes...")

        for student_id in range(len(os.listdir(students_dir))):
            student_dir = "%s/%d/" % (students_dir, student_id)
            passwd_file = student_dir + "/passwd.plain"

            passwd = ""

            if os.path.isfile(passwd_file):
                with open(passwd_file, "rt") as file:
                    passwd = file.read()


            cmd = "python3 %s %s %d -p %s" % (pipeline_file, student_dir, args.msg_count, passwd)

            if len(l) == max_processes:
                l[0].wait()
                l.pop(0)

            l.append(subprocess.Popen(cmd.split(' '), stdout=stdout, stderr=stderr))

        print_main_message("All pipeline processes returned")

    def parse_args():

        def valid_dir(dir_name):
            if os.path.isdir(dir_name):
                return dir_name
            raise argparse.ArgumentTypeError("%s is not a valid path" % dir_name)

        def valid_file(f_name):
            if os.path.isfile(f_name):
                return f_name
            raise argparse.ArgumentTypeError("%s is not a valid file" % f_name)

        parser = argparse.ArgumentParser()

        # Stages-skipping arguments
        parser.add_argument("--no-capture", action="store_true", help="Skip packet capturing")
        parser.add_argument("--no-inspect", action="store_true", help="Skip packet inspection")
        parser.add_argument("--no-decrypt", action="store_true", help="Skip packet decryption")

        # Capture arguments
        parser.add_argument("--start-time", help="Packet capture start time")
        parser.add_argument("--max-packets", type=int, help="Maximum number of packets to capture")
        parser.add_argument("--timeout", type=int, help="Enables capture interruption after timeout seconds without packets")

        # Inspect arguments
        parser.add_argument("--tuples-count", type=int, help="Number of tuples", required=True)
        parser.add_argument("--msg-count", type=int, help="Number of messages per tuple", required=True)

        # Decrypt arguments
        # parser

        # Multi-pipeline arguments
        parser.add_argument("-m", required=False, type=int, help="Maximum number of processes to launch")
        parser.add_argument("--pipeline", type=valid_file, help="Pipeline script to call on each student")
        parser.add_argument("--failed", help="Output file for failed student pipelines")
        parser.add_argument("--working-dir", type=valid_dir, help="Sets working directory for script", required=True)
        parser.add_argument("-v", "--verbose", action="store_true", help="Enables printing of subprocesses output")

        return parser.parse_args()

    try:   
        args = parse_args()

        stdout = stderr = None

        if not args.verbose:
            stdout = stderr = subprocess.DEVNULL

        if not args.no_capture:
            capture_packets(args)

        if not args.no_inspect:
            inspect_packets(args)

        if not args.no_decrypt:
            cast_pipelines(args)

    except KeyboardInterrupt:
        print("User terminated")

start_time = time.time()

main()

print("-" * 100)
print("Multi-process pipeline finished in %d seconds" % (time.time()-start_time))
print("-" * 100)

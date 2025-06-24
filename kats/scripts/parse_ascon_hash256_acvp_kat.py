#!/usr/bin/python

import json
import sys


def main():
    json_as_str = ''
    for line in sys.stdin:
        json_as_str += line
    
    acvp_kats = json.loads(json_as_str)
    count = 0

    for test_group in acvp_kats["testGroups"]:
        if test_group["testType"] != "AFT":
            continue

        for test in test_group["tests"]:
            if test["len"] % 8 != 0:
                continue

            count += 1

            sys.stdout.write(f'Count =  {count}\n')
            sys.stdout.write(f'Msg = {test["msg"]}\n')
            sys.stdout.write(f'MD = {test["md"]}\n')

            sys.stdout.write('\n')
            sys.stdout.flush()

if __name__=='__main__':
    main()

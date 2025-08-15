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
        if test_group["supportsNonceMasking"]:
            continue
        if test_group["testType"] != "AFT":
            continue

        for test in test_group["tests"]:
            if test["payloadLen"] % 8 != 0:
                continue
            if test["adLen"] % 8 != 0:
                continue
            if test["tagLen"] % 8 != 0:
                continue

            count += 1

            sys.stdout.write(f'Count =  {count}\n')
            sys.stdout.write(f'Key = {test["key"]}\n')
            sys.stdout.write(f'Nonce = {test["nonce"]}\n')
            sys.stdout.write(f'PT = {test["pt"]}\n')
            sys.stdout.write(f'AD = {test["ad"]}\n')
            sys.stdout.write(f'CT = {test["ct"]}\n')
            sys.stdout.write(f'Tag = {test["tag"]}\n')

            if test_group["direction"]  == "decrypt":
                sys.stdout.write(f'TestPassed = {test["testPassed"]}\n')
            else:
                sys.stdout.write(f'TestPassed = {True}\n')

            sys.stdout.write('\n')
            sys.stdout.flush()

if __name__=='__main__':
    main()

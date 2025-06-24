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

            out_bit_len = test["outLen"]
            smaller_out_bit_len = out_bit_len & -8
            smaller_out_byte_len = smaller_out_bit_len // 8
            hex_char_len = smaller_out_byte_len * 2

            if hex_char_len == 0:
                continue

            count += 1

            sys.stdout.write(f'Count =  {count}\n')
            sys.stdout.write(f'Msg = {test["msg"]}\n')
            sys.stdout.write(f'MD = {test["md"][:hex_char_len]}\n')

            sys.stdout.write('\n')
            sys.stdout.flush()

if __name__=='__main__':
    main()

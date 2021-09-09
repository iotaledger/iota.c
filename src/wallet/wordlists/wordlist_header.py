#! /usr/bin/env python3

# Copyright 2021 IOTA Stiftung
# SPDX-License-Identifier: Apache-2.0

import sys
import os.path
import datetime


def main():
    w_file = sys.argv[1]
    lan_prefix = sys.argv[2]
    with open(w_file, mode='r', encoding="utf-8") as wf:
        word_list = [l.strip() for l in wf.readlines()]

    if len(word_list) != 2048:
        print("must have 2048 words in the wordlist")
        sys.exit()

    # print(word_list)
    print("/* ===Auto Generated via " +
          os.path.basename(sys.argv[0]) + " do not modify!!=== */\n")
    print("// Copyright " + str(datetime.datetime.now().year) + " IOTA Stiftung")
    print("// SPDX-License-Identifier: Apache-2.0\n")
    print("#ifndef __WALLE__WORDLISTS_" + lan_prefix.upper() + "_H__")
    print("#define __WALLE__WORDLISTS_" + lan_prefix.upper() + "_H__\n")
    print('#include "wallet/wordlists/word.h"\n')
    print('static word_t ' + lan_prefix + '_word[] = {')
    for w in word_list:
        print('  {"'+w+'", ' + str(len(w.encode('utf-8'))) + '},')
    print('};\n')
    print("#endif\n")


if __name__ == "__main__":
    main()

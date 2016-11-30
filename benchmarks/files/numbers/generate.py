#!/usr/bin/env python

import json
import random
import sys

random.seed(0)

# floats
result_floats = []
for x in range(0, 1000000):
	result_floats.append(random.uniform(-100000000.0, 100000000.0))
json.dump(result_floats, open("floats.json", "w"), indent=2)

# unsigned integers
result_uints = []
for x in range(0, 1000000):
	result_uints.append(random.randint(0, 18446744073709551615))
json.dump(result_uints, open("unsigned_ints.json", "w"), indent=2)

# signed integers
result_sints = []
for x in range(0, 1000000):
	result_sints.append(random.randint(-9223372036854775808, 9223372036854775807))
json.dump(result_sints, open("signed_ints.json", "w"), indent=2)

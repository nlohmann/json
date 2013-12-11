#!/usr/bin/env python

import json
import sys
import datetime

a = datetime.datetime.now()
data = json.loads(open(sys.argv[1]).read())
b = datetime.datetime.now()

print (b-a)

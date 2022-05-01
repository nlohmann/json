#!/usr/bin/env python3

# 2017, Georg Sauthoff <mail@gms.tf>, GPLv3

import sys

def skip_comments(lines):
  state = 0
  for line in lines:
    n = len(line)
    l = ''
    p = 0
    while p < n:
      if state == 0:
        a = line.find('//', p)
        b = line.find('/*', p)
        if a > -1 and (a < b or b == -1):
          l += line[p:a]
          p = n
        elif b > -1 and (b < a or a == -1):
          l += line[p:b]
          p = b+2
          state = 1
        else:
          l += line[p:]
          p = n
      elif state == 1:
        a = line.rfind('*/', p)
        if a == -1:
          p = n
        else:
          p = a + 2
          state = 0
    yield l

def cond_lines(lines):
  state = 0
  pcnt = 0
  for nr, line in enumerate(lines, 1):
    if not line:
      continue
    n = len(line)
    p = 0
    do_yield = False
    while p < n:
      if state == 0:
        p = line.find('if', p)
        if p == -1:
          p = n
          continue
        if (p == 0 or not line[p-1].isalpha()) \
            and (p+2 == len(line) or not line[p+2].isalpha()):
          do_yield = True
          state = 1
        p += 2
      elif state == 1:
        do_yield = True
        p = line.find('(', p)
        if p == -1:
          p = n
        else:
          p += 1
          state = 2
          pcnt = 1
      elif state == 2:
        do_yield = True
        for p in range(p, n):
          if line[p] == '(':
            pcnt += 1
          elif line[p] == ')':
            pcnt -= 1
          if not pcnt:
            state = 0
            break
        p += 1
    if do_yield:
      yield nr

def cond_lines_from_file(filename):
  with open(filename) as f:
    yield from cond_lines(skip_comments(f))

def filter_lcov_trace(lines):
  nrs = set()
  for line in lines:
    if line.startswith('SF:'):
      nrs = set(cond_lines_from_file(line[3:-1]))
    elif line.startswith('BRDA:'):
      xs = line[5:].split(',')
      nr = int(xs[0]) if xs else 0
      if nr not in nrs:
        continue
    yield line

def filter_lcov_trace_file(s_filename, d_file):
  with open(s_filename) as f:
    for l in filter_lcov_trace(f):
      print(l, end='', file=d_file)

if __name__ == '__main__':
  #for l in cond_lines_from_file(sys.argv[1]):
  #  print(l)

  filter_lcov_trace_file(sys.argv[1], sys.stdout)

  #with open(sys.argv[1]) as f:
  #  for l in skip_comments(f):
  #    print(l)


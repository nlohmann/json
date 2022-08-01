#!/usr/bin/env python3

import datetime
import logging
import pathlib
import shlex
import shutil
import signal
import subprocess
import sys

DATETIME_FORMAT = '%Y-%m-%d %H:%M:%S'

START_TIME = datetime.datetime.now()
class ExitHandler(logging.StreamHandler):
    def __init__(self, level):
        '''.'''
        super().__init__()
        self.level = level

    def emit(self, record):
        if record.levelno >= self.level:
            sys.exit(1)

class Pool:
    def __init__(self, name, size, allocation_size, allocate_fn, prio_pools=None):
        self.name = name
        self.total_size = size
        self.size = 0
        if allocation_size < 0:
            self.allocation_size = size
        else:
            self.allocation_size = allocation_size
        self.allocate_fn = allocate_fn
        self.prio_pools = prio_pools

    def next_allocation_size(self):
        if self.prio_pools:
            for pool in self.prio_pools:
                if pool.next_allocation_size() > 0:
                    return 0

        size = self.allocation_size
        if self.total_size >= 0:
            available = max(0, self.total_size - self.size)
            size = min(size, available)
        return size

    def allocate(self):
        size = self.next_allocation_size()
        if size > 0:
            self.allocate_fn(size)
            self.size += size
            return True
        return False

class Job:
    def __init__(self, name, args, env=None, is_main=False):
        self.name = name
        self.args = args
        self.env = env or {}
        self.is_main = is_main
        self.proc = None

    def is_running(self):
        return self.proc and self.proc.poll() == None

    def start(self):
        popen_args = {'env': self.env}

        if self.is_main:
            command=''
            for env_key, env_val in popen_args['env'].items():
                command += f'{env_key}={env_val} '
            command += " ".join([shlex.quote(str(arg)) for arg in self.args])

            print(command)
            print('\n\n')
        else:
            log = open(f"{self.name}-{START_TIME.date()}T{START_TIME.time()}.log", "w")

            popen_args.update({
                'stdin': subprocess.DEVNULL,
                'stdout': log,
                'stderr': subprocess.STDOUT,
            })
            popen_args['env']['AFL_NO_UI'] = '1'

            command=''
            for env_key, env_val in popen_args['env'].items():
                command += f'{env_key}={env_val} '
            command += " ".join([shlex.quote(str(arg)) for arg in self.args])

            log.write(command)
            log.write('\n\n')

        self.proc = subprocess.Popen(self.args, **popen_args)

    def wait(self, timeout=None):
        return self.proc.wait(timeout)

    def terminate(self):
        if not self.proc.poll():
            self.proc.send_signal(signal.SIGINT)
            try:
                self.proc.wait(0.5)
            except subprocess.TimeoutExpired:
                pass

            self.proc.terminate()
            self.proc.wait()

        return self.proc.poll()

class AFLJobAllocator:
    DEFAULT_FUZZER_BIN = -1
    FUZZER_BIN = -2

    def __init__(self, args):
        self.args = args
        self.jobs = []

    def allocate_jobs(self):
        self.sanitizers = self.args.sanitizers
        self.power_schedules = ['explore', 'coe', 'lin', 'quad', 'exploit']
        self.jobs.clear()
        pools = [
            Pool('main', 1, 1, self.allocate_main_job),
            Pool('sanitizer', len(self.sanitizers), -1, self.allocate_sanitizer_job),
            Pool('complog', 2 if 'complog' in self.args.instrumentations else 0, 1, self.allocate_complog_job),
            Pool('laf-intel', 3 if 'laf-intel' in self.args.instrumentations else 0, 1, self.allocate_laf_intel_job),
            Pool('MOpt', int(self.args.num_jobs / 3 + 0.5), 1, self.allocate_mopt_job),
            Pool('power schedule', len(self.power_schedules), 1, self.allocate_power_sched_job),
        ]
        pools.append(Pool('filler', -1, 1, self.allocate_filler_job, pools.copy()))

        while len(self.jobs) < self.args.num_jobs:
            for pool in pools:
                if len(self.jobs) >= self.args.num_jobs:
                    break
                pool.allocate()

        if self.args.verbose:
            label = '# allocated job(s):'
            print(f'{label:<24} {len(self.jobs)}')
            for pool in pools:
                label = f'{pool.name} job(s):'
                print(f'{label:<24} {pool.size}')

    def resolve(self, args, fuzzer_bin):
        replacements = {
            self.DEFAULT_FUZZER_BIN: self.args.default_fuzzer_bin,
            self.FUZZER_BIN: fuzzer_bin
        }
        return [replacements.get(arg, arg) for arg in (args or [])]

    def allocate_job(self, suffix=None, args=None, use_default_fuzzer_bin=False):
        fuzzer_bin = self.args.fuzzer_bin
        if suffix:
            bin_suffix = self.args.fuzzer_bin_suffix
            name = fuzzer_bin.name
            name = name[:len(name)-len(bin_suffix)]
            fuzzer_bin = fuzzer_bin.with_name(f'{name}.{suffix}{bin_suffix}')

        name = self.job_name()
        is_main = len(self.jobs) == 0
        if is_main:
            dist_args = ['-M', name]
        else:
            dist_args = ['-S', name]
        args = self.resolve(args, fuzzer_bin)
        if use_default_fuzzer_bin:
            fuzzer_bin = self.args.default_fuzzer_bin
        fuzzer_args = [
            self.args.driver,
            '-i', self.args.input_dir,
            '-o', self.args.output_dir,
            '-t', '+1000',
            *dist_args,
            *args,
            '--', fuzzer_bin
        ]
        fuzzer_env = {
            'AFL_IMPORT_FIRST': '0',
            'AFL_CMPLOG_ONLY_NEW': '1'
        }
        if self.args.resume:
            fuzzer_env['AFL_AUTORESUME'] = '1'
        if self.args.tmp_dir:
            tmp_dir = self.args.tmp_dir / name
            tmp_dir.mkdir(parents=True, exist_ok=True)
            fuzzer_env['AFL_TMPDIR'] = tmp_dir

        self.jobs.append(Job(name, fuzzer_args, fuzzer_env, is_main))

    def job_name(self):
        return f'{self.args.fuzzer_bin.name}{len(self.jobs)}'

    def allocate_main_job(self, n):
        assert(n == 1 and len(self.jobs) == 0)
        self.allocate_job(args=['-Z'])

    def allocate_sanitizer_job(self, n):
        for _ in range(n):
            self.allocate_job(suffix=self.sanitizers.pop(0))

    def allocate_complog_job(self, n):
        for _ in range(n):
            self.allocate_job(suffix='complog', args=['-c', self.FUZZER_BIN], use_default_fuzzer_bin=True)

    def allocate_laf_intel_job(self, n):
        for _ in range(n):
            self.allocate_job(suffix='laf-intel')

    def allocate_power_sched_job(self, n):
        for _ in range(n):
            self.allocate_job(args=['-p', self.power_schedules.pop(0)])

    def allocate_mopt_job(self, n):
        for _ in range(n):
            self.allocate_job(args=['-L', '0'])

    def allocate_filler_job(self, n):
        for _ in range(n):
            self.allocate_job()

class Fuzz:
    def __init__(self, args, error_fn):
        self.args = args
        self.error_fn = error_fn
        self.dispatch()

    def dispatch(self):
        cmd = f'cmd_{self.args.command}'.replace('-', '_')
        if not hasattr(self, cmd):
            self.error_fn(f'unknown command: {self.args.command} ({self.args.engine})')
        getattr(self, cmd)()

    def check_io_dirs(self):
        if not self.args.input_dir.exists() or not self.args.input_dir.is_dir():
            self.args.error_fn('input_dir must be an existing directory')

        if self.args.output_dir.exists():
            if not self.args.output_dir.is_dir() or len(list(self.args.output_dir.iterdir())):
                self.args.error_fn('output_dir must either not exists or be an empty directory')
        else:
            self.args.output_dir.mkdir(parents=True)

    def cmd_generate_corpus(self):
        self.check_io_dirs()

        for f in self.args.input_dir.glob(self.args.glob):
            if f.stat().st_size <= self.args.max_size:
                shutil.copy(f, self.args.output_dir)

class AFLFuzz(Fuzz):
    def cmd_minimize_corpus(self):
        self.check_io_dirs()

        if not self.args.fuzzer_bin:
            self.args.error_fn('required argument missing: -f/--fuzzer-bin')

        proc = subprocess.run([self.args.minimizer_bin,
            '-i', self.args.input_dir, '-o', self.args.output_dir,
            '--', self.args.fuzzer_bin])

        if proc.returncode != 0:
            raise RuntimeError('subprocess failed')

        if self.args.replace_input_dir:
            shutil.rmtree(self.args.input_dir)
            shutil.move(self.args.output_dir, self.args.input_dir)

    def cmd_run(self):
        self.args.default_fuzzer_bin = self.args.fuzzer_bin = self.args.fuzzer_bin.resolve()
        if not self.args.driver.is_absolute():
            driver = shutil.which(self.args.driver)
            if not driver:
                args.error_fn('driver does not reference an executable in PATH')
            self.args.driver = pathlib.Path(driver)

        allocator = AFLJobAllocator(self.args)
        allocator.allocate_jobs()

        try:
            for job in allocator.jobs:
                cur_input = (self.args.tmp_dir or self.args.output_dir) / job.name / '.cur_input'
                cur_input.unlink(missing_ok=True)
                job.start()
            while any([job.is_running() for job in allocator.jobs]):
                for job in allocator.jobs:
                    try:
                        ret = job.wait(0.5)
                        if ret != 0:
                            print(f'{job.name} failed ({ret})')
                    except subprocess.TimeoutExpired:
                        pass
        except KeyboardInterrupt:
            pass
        finally:
            for job in allocator.jobs:
                ret = job.terminate()
                if ret != 0:
                    print(f'{job.name} failed ({ret})')

class LLVMFuzz(Fuzz):
    pass

def cmake_list(arg):
    return arg.split(';')

def iec_number(arg):
    units = 'kmgt'
    n, u = arg[:-1], arg[-1:]
    if u.isalpha():
        n = int(n)
        u = units.find(u.lower()) + 1
        if u < 1:
            raise ValueError()
        n *= 1024**u
    else:
        n = int(arg)
    return n

if __name__ == '__main__':
    import argparse

    ec = 1

    # setup logging
    logging.basicConfig(format='[%(asctime)s] %(levelname)s: %(message)s',
                        datefmt=DATETIME_FORMAT, level=logging.INFO)
    log = logging.getLogger()
    log.addHandler(ExitHandler(logging.ERROR))

    # parse command line arguments
    parser = argparse.ArgumentParser()
    parser.add_argument('-v', '--verbose', dest='verbose', action='store_true', help='Verbose output.')
    subparsers = parser.add_subparsers(title='commands', required=True)

    gen_corpus_parser = subparsers.add_parser('generate-corpus', aliases=['gen-corpus'])
    gen_corpus_parser.set_defaults(command='generate-corpus', error_fn=gen_corpus_parser.error)
    gen_corpus_parser.add_argument('-i', '--input-dir', dest='input_dir', type=pathlib.Path, metavar='<dir>', help='Input corpus directory.', required=True)
    gen_corpus_parser.add_argument('-o', '--output-dir', dest='output_dir', type=pathlib.Path, metavar='<dir>', help='Output corpus directory.', required=True)
    gen_corpus_parser.add_argument('-g', '--glob', dest='glob', metavar='<glob pattern>', default='**/*.*', help='Glob pattern of files to include.')
    gen_corpus_parser.add_argument('-m', '--max-size', dest='max_size', type=iec_number, default=5*1024, help='Maximum file size.')

    min_corpus_parser = subparsers.add_parser('minimize-corpus', aliases=['min-corpus'])
    min_corpus_parser.set_defaults(command='minimize-corpus', error_fn=min_corpus_parser.error)
    min_corpus_parser.add_argument('-e', '--fuzz-engine', dest='engine', type=str.lower, metavar='<engine>', choices=['afl++', 'libfuzzer'], help='The fuzzing engine to use. AFL++ or libFuzzer.', required=True)
    min_corpus_parser.add_argument('-i', '--input-dir', dest='input_dir', type=pathlib.Path, metavar='<dir>', help='Input corpus directory.', required=True)
    min_corpus_parser.add_argument('-o', '--output-dir', dest='output_dir', type=pathlib.Path, metavar='<dir>', help='Output corpus directory.', required=True)
    min_corpus_parser.add_argument('-r', '--replace-input-dir', dest='replace_input_dir', action='store_true', help='Replace input directory with output directory.')
    min_corpus_parser.add_argument('-b', '--fuzzer-bin', dest='fuzzer_bin', type=pathlib.Path, help='Fuzzer binary.', required=True)
    min_corpus_parser.add_argument('-m', '--minimizer-bin', dest='minimizer_bin', type=pathlib.Path, help='Path to or name of afl-cmin binary (AFL++).')

    run_parser = subparsers.add_parser('run')
    run_parser.set_defaults(command='run', error_fn=run_parser.error)
    run_parser.add_argument('-e', '--fuzz-engine', dest='engine', type=str.lower, metavar='<engine>', choices=['afl++', 'libfuzzer'], help='The fuzzing engine to use. AFL++ or libFuzzer.', required=True)
    run_parser.add_argument('-i', '--input-dir', dest='input_dir', type=pathlib.Path, metavar='<dir>', help='Corpus directory.', required=True)
    run_parser.add_argument('-o', '--output-dir', dest='output_dir', type=pathlib.Path, metavar='<dir>', help='Findings directory.', required=True)
    run_parser.add_argument('-S', '--sanitizers', dest='sanitizers', type=cmake_list, metavar='<list>', default=[], help='Semicolon-separated list of sanitizers or plus-separated sanitizer combos.')
    run_parser.add_argument('-I', '--instrumentations', dest='instrumentations', type=cmake_list, metavar='<list>', default=[], help='Semicolon-separated list of instrumentations. (AFL++ only)')
    run_parser.add_argument('-j', '--parallel', dest='num_jobs', type=int, metavar='<N>', default=8, help='Number of parallel fuzzing jobs.')
    run_parser.add_argument('-r', '--resume', dest='resume', action='store_true', help='Resume fuzzing or restart.')
    run_parser.add_argument('-d', '--driver', dest='driver', type=pathlib.Path, default=pathlib.Path('afl-fuzz'), help='Path to or name of driver (afl-fuzz) binary.', required=True)
    run_parser.add_argument('-b', '--fuzzer-bin', dest='fuzzer_bin', type=pathlib.Path, help='Fuzzer binary.', required=True)
    run_parser.add_argument('-B', '--fuzzer-bin-suffix', dest='fuzzer_bin_suffix', default='', help='Fuzzer binary suffix.')
    run_parser.add_argument('-t', '--tmp-dir', dest='tmp_dir', type=pathlib.Path, default=pathlib.Path.cwd(), help='Path to temporary directory.')

    args = parser.parse_args()

    try:
        if 'engine' in args:
            if args.engine == 'afl++':
                fuzz_class = AFLFuzz
            elif args.engine == 'libfuzzer':
                fuzz_class = LLVMFuzz
        else:
            fuzz_class = Fuzz
        fuzz_class(args, parser.error)
        ec = 0
    except Exception:
        log.exception('an error occurred:')
    finally:
        if args.verbose:
            log.info(f'exiting with code {ec}')
        sys.exit(ec)

#!/usr/bin/env python3

import contextlib
import logging
import os
import re
import shutil
import sys
import subprocess

from datetime import datetime, timedelta
from io import BytesIO
from threading import Lock, Timer

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from http import HTTPStatus
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler

CONFIG_FILE = 'serve_header.yml'
MAKEFILE = 'Makefile'
INCLUDE = 'include/nlohmann/'
SINGLE_INCLUDE = 'single_include/nlohmann/'
HEADER = 'json.hpp'

DATETIME_FORMAT = '%Y-%m-%d %H:%M:%S'

JSON_VERSION_RE = re.compile(r'\s*#\s*define\s+NLOHMANN_JSON_VERSION_MAJOR\s+')

class ExitHandler(logging.StreamHandler):
    def __init__(self, level):
        """."""
        super().__init__()
        self.level = level

    def emit(self, record):
        if record.levelno >= self.level:
            sys.exit(1)

def is_project_root(test_dir='.'):
    makefile = os.path.join(test_dir, MAKEFILE)
    include = os.path.join(test_dir, INCLUDE)
    single_include = os.path.join(test_dir, SINGLE_INCLUDE)

    return (os.path.exists(makefile)
            and os.path.isfile(makefile)
            and os.path.exists(include)
            and os.path.exists(single_include))

class DirectoryEventBucket:
    def __init__(self, callback, delay=1.2, threshold=0.8):
        """."""
        self.delay = delay
        self.threshold = timedelta(seconds=threshold)
        self.callback = callback
        self.event_dirs = set([])
        self.timer = None
        self.lock = Lock()

    def start_timer(self):
        if self.timer is None:
            self.timer = Timer(self.delay, self.process_dirs)
            self.timer.start()

    def process_dirs(self):
        result_dirs = []
        event_dirs = set([])
        with self.lock:
            self.timer = None
            while self.event_dirs:
                time, event_dir = self.event_dirs.pop()
                delta = datetime.now() - time
                if delta < self.threshold:
                    event_dirs.add((time, event_dir))
                else:
                    result_dirs.append(event_dir)
            self.event_dirs = event_dirs
            if result_dirs:
                self.callback(os.path.commonpath(result_dirs))
            if self.event_dirs:
                self.start_timer()

    def add_dir(self, path):
        with self.lock:
            # add path to the set of event_dirs if it is not a sibling of
            # a directory already in the set
            if not any(os.path.commonpath([path, event_dir]) == event_dir
               for (_, event_dir) in self.event_dirs):
                self.event_dirs.add((datetime.now(), path))
                if self.timer is None:
                    self.start_timer()

class WorkTree:
    make_command = 'make'

    def __init__(self, root_dir, tree_dir):
        """."""
        self.root_dir = root_dir
        self.tree_dir = tree_dir
        self.rel_dir = os.path.relpath(tree_dir, root_dir)
        self.name = os.path.basename(tree_dir)
        self.include_dir = os.path.abspath(os.path.join(tree_dir, INCLUDE))
        self.header = os.path.abspath(os.path.join(tree_dir, SINGLE_INCLUDE, HEADER))
        self.rel_header = os.path.relpath(self.header, root_dir)
        self.dirty = True
        self.build_count = 0
        t = os.path.getmtime(self.header)
        t = datetime.fromtimestamp(t)
        self.build_time = t.strftime(DATETIME_FORMAT)

    def __hash__(self):
        """."""
        return hash((self.tree_dir))

    def __eq__(self, other):
        """."""
        if not isinstance(other, type(self)):
            return NotImplemented
        return self.tree_dir == other.tree_dir

    def update_dirty(self, path):
        if self.dirty:
            return

        path = os.path.abspath(path)
        if os.path.commonpath([path, self.include_dir]) == self.include_dir:
            logging.info(f'{self.name}: working tree marked dirty')
            self.dirty = True

    def amalgamate_header(self):
        if not self.dirty:
            return

        mtime = os.path.getmtime(self.header)
        subprocess.run([WorkTree.make_command, 'amalgamate'], cwd=self.tree_dir,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if mtime == os.path.getmtime(self.header):
            logging.info(f'{self.name}: no changes')
        else:
            self.build_count += 1
            self.build_time = datetime.now().strftime(DATETIME_FORMAT)
            logging.info(f'{self.name}: header amalgamated (build count {self.build_count})')

        self.dirty = False

class WorkTrees(FileSystemEventHandler):
    def __init__(self, root_dir):
        """."""
        super().__init__()
        self.root_dir = root_dir
        self.trees = set([])
        self.tree_lock = Lock()
        self.scan(root_dir)
        self.created_bucket = DirectoryEventBucket(self.scan)
        self.observer = Observer()
        self.observer.schedule(self, root_dir, recursive=True)
        self.observer.start()

    def scan(self, base_dir):
        scan_dirs = set([base_dir])
        # recursively scan base_dir for working trees

        while scan_dirs:
            scan_dir = os.path.abspath(scan_dirs.pop())
            self.scan_tree(scan_dir)
            try:
                with os.scandir(scan_dir) as dir_it:
                    for entry in dir_it:
                        if entry.is_dir():
                            scan_dirs.add(entry.path)
            except FileNotFoundError as e:
                logging.debug('path disappeared: %s', e)

    def scan_tree(self, scan_dir):
        if not is_project_root(scan_dir):
            return

        # skip source trees in build directories
        # this check could be enhanced
        if scan_dir.endswith('/_deps/json-src'):
            return

        tree = WorkTree(self.root_dir, scan_dir)
        with self.tree_lock:
            if not tree in self.trees:
                if tree.name == tree.rel_dir:
                    logging.info(f'adding working tree {tree.name}')
                else:
                    logging.info(f'adding working tree {tree.name} at {tree.rel_dir}')
                url = os.path.join('/', tree.rel_dir, HEADER)
                logging.info(f'{tree.name}: serving header at {url}')
                self.trees.add(tree)

    def rescan(self, path=None):
        if path is not None:
            path = os.path.abspath(path)
        trees = set([])
        # check if any working trees have been removed
        with self.tree_lock:
            while self.trees:
                tree = self.trees.pop()
                if ((path is None
                    or os.path.commonpath([path, tree.tree_dir]) == tree.tree_dir)
                    and not is_project_root(tree.tree_dir)):
                    if tree.name == tree.rel_dir:
                        logging.info(f'removing working tree {tree.name}')
                    else:
                        logging.info(f'removing working tree {tree.name} at {tree.rel_dir}')
                else:
                    trees.add(tree)
            self.trees = trees

    def find(self, path):
        # find working tree for a given header file path
        path = os.path.abspath(path)
        with self.tree_lock:
            for tree in self.trees:
                if path == tree.header:
                    return tree
        return None

    def on_any_event(self, event):
        logging.debug('%s (is_dir=%s): %s', event.event_type,
                      event.is_directory, event.src_path)
        path = os.path.abspath(event.src_path)
        if event.is_directory:
            if event.event_type == 'created':
                # check for new working trees
                self.created_bucket.add_dir(path)
            elif event.event_type == 'deleted':
                # check for deleted working trees
                self.rescan(path)
        elif event.event_type == 'closed':
            with self.tree_lock:
                for tree in self.trees:
                    tree.update_dirty(path)

    def stop(self):
        self.observer.stop()
        self.observer.join()

class HeaderRequestHandler(SimpleHTTPRequestHandler):
    def __init__(self, request, client_address, server):
        """."""
        self.worktrees = server.worktrees
        self.worktree = None
        try:
            super().__init__(request, client_address, server,
                             directory=server.worktrees.root_dir)
        except ConnectionResetError:
            logging.debug('connection reset by peer')

    def translate_path(self, path):
        path = os.path.abspath(super().translate_path(path))

        # add single_include/nlohmann into path, if needed
        header = os.path.join('/', HEADER)
        header_path = os.path.join('/', SINGLE_INCLUDE, HEADER)
        if (path.endswith(header)
            and not path.endswith(header_path)):
            path = os.path.join(os.path.dirname(path), SINGLE_INCLUDE, HEADER)

        return path

    def send_head(self):
        # check if the translated path matches a working tree
        # and fullfill the request; otherwise, send 404
        path = self.translate_path(self.path)
        self.worktree = self.worktrees.find(path)
        if self.worktree is not None:
            self.worktree.amalgamate_header()
            logging.info(f'{self.worktree.name}; serving header (build count {self.worktree.build_count})')
            return super().send_head()
        logging.info(f'invalid request path: {self.path}')
        super().send_error(HTTPStatus.NOT_FOUND, 'Not Found')
        return None

    def send_header(self, keyword, value):
        # intercept Content-Length header; sent in copyfile later
        if keyword == 'Content-Length':
            return
        super().send_header(keyword, value)

    def end_headers (self):
        # intercept; called in copyfile() or indirectly
        # by send_head via super().send_error()
        pass

    def copyfile(self, source, outputfile):
        injected = False
        content = BytesIO()
        length = 0
        # inject build count and time into served header
        for line in source:
            line = line.decode('utf-8')
            if not injected and JSON_VERSION_RE.match(line):
                length += content.write(bytes('#define JSON_BUILD_COUNT '\
                                              f'{self.worktree.build_count}\n', 'utf-8'))
                length += content.write(bytes('#define JSON_BUILD_TIME '\
                                              f'"{self.worktree.build_time}"\n\n', 'utf-8'))
                injected = True
            length += content.write(bytes(line, 'utf-8'))

        # set content length
        super().send_header('Content-Length', length)
        # CORS header
        self.send_header('Access-Control-Allow-Origin', '*')
        # prevent caching
        self.send_header('Cache-Control', 'no-cache, no-store, must-revalidate')
        self.send_header('Pragma', 'no-cache')
        self.send_header('Expires', '0')
        super().end_headers()

        # send the header
        content.seek(0)
        shutil.copyfileobj(content, outputfile)

    def log_message(self, format, *args):
        pass

class DualStackServer(ThreadingHTTPServer):
    def __init__(self, addr, worktrees):
        """."""
        self.worktrees = worktrees
        super().__init__(addr, HeaderRequestHandler)

    def server_bind(self):
        # suppress exception when protocol is IPv4
        with contextlib.suppress(Exception):
            self.socket.setsockopt(
                socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        return super().server_bind()

if __name__ == '__main__':
    import argparse
    import ssl
    import socket
    import yaml

    # exit code
    ec = 0

    # setup logging
    logging.basicConfig(format='[%(asctime)s] %(levelname)s: %(message)s',
                        datefmt=DATETIME_FORMAT, level=logging.INFO)
    log = logging.getLogger()
    log.addHandler(ExitHandler(logging.ERROR))

    # parse command line arguments
    parser = argparse.ArgumentParser()
    parser.add_argument('--make', default='make',
                        help='the make command (default: make)')
    args = parser.parse_args()

    # propagate the make command to use for amalgamating headers
    WorkTree.make_command = args.make

    worktrees = None
    try:
        # change working directory to project root
        os.chdir(os.path.realpath(os.path.join(sys.path[0], '../../')))

        if not is_project_root():
            log.error('working directory does not look like project root')

        # load config
        config = {}
        config_file = os.path.abspath(CONFIG_FILE)
        try:
            with open(config_file, 'r') as f:
                config = yaml.safe_load(f)
        except FileNotFoundError:
            log.info(f'cannot find configuration file: {config_file}')
            log.info('using default configuration')

        # find and monitor working trees
        worktrees = WorkTrees(config.get('root', '.'))

        # start web server
        infos = socket.getaddrinfo(config.get('bind', None), config.get('port', 8443),
                                   type=socket.SOCK_STREAM, flags=socket.AI_PASSIVE)
        DualStackServer.address_family = infos[0][0]
        HeaderRequestHandler.protocol_version = 'HTTP/1.0'
        with DualStackServer(infos[0][4], worktrees) as httpd:
            scheme = 'HTTP'
            https = config.get('https', {})
            if https.get('enabled', True):
                cert_file = https.get('cert_file', 'localhost.pem')
                key_file = https.get('key_file', 'localhost-key.pem')
                ssl.minimum_version = ssl.TLSVersion.TLSv1_3
                ssl.maximum_version = ssl.TLSVersion.MAXIMUM_SUPPORTED
                httpd.socket = ssl.wrap_socket(httpd.socket,
                    certfile=cert_file, keyfile=key_file,
                    server_side=True, ssl_version=ssl.PROTOCOL_TLS)
                scheme = 'HTTPS'
            host, port = httpd.socket.getsockname()[:2]
            log.info(f'serving {scheme} on {host} port {port}')
            log.info('press Ctrl+C to exit')
            httpd.serve_forever()

    except KeyboardInterrupt:
        log.info('exiting')
    except Exception:
        log.exception('an error occurred:')
        ec = 1
    finally:
        if worktrees is not None:
            worktrees.stop()
            sys.exit(ec)

#!/usr/bin/env python

# Tool for symbolizing stack traces in BUG reports, mainly those produced
# by KASAN.

from __future__ import print_function
from collections import defaultdict
import getopt
import os
import re
import sys
import subprocess

# Matches the timestamp or a thread/cpu number prefix of a log line.
BRACKET_PREFIX_RE = re.compile(
    '^(?P<time>\[ *[TC0-9\.]+\]) ?(?P<body>.*)$'
)

# A decimal number.
DECNUM_RE = '[0-9]+'

# A hexadecimal number without the leading 0x.
HEXNUM_RE = '[0-9A-Fa-f]+'

# An address in the form [<ffffffff12345678>].
FRAME_ADDR_RE = (
    '((\[\<(?P<addr>' + HEXNUM_RE + ')\>\]) )'
)

# A function name with an offset and function size, plus an optional module
# name, e.g.:
# __asan_load8+0x64/0x66
FRAME_BODY_RE = (
    '(?P<body>' +
        '(?P<function>[^\+]+)' +
        '\+' +
        '0x(?P<offset>' + HEXNUM_RE + ')' +
        '/' +
        '0x(?P<size>' + HEXNUM_RE + ')' +
    ')' +
    '( \[(?P<module>.+)\])?'
)

# Matches a single stacktrace frame (without time or thread/cpu number prefix).
FRAME_RE = re.compile(
    '^' +
    '(?P<prefix> *)' +
    FRAME_ADDR_RE + '?' +
    '((?P<precise>\?) )?' +
    FRAME_BODY_RE +
    '$'
)

# Matches the 'RIP:' line in BUG reports.
RIP_RE = re.compile(
    '^' +
    '(?P<prefix>RIP: ' + HEXNUM_RE + ':)' +
    FRAME_BODY_RE +
    '$'
)

# Matches the 'lr :' and 'pc :' lines in BUG reports.
LR_RE = re.compile(
    '^' +
    '(?P<prefix>(lr|pc) : )' +
    FRAME_BODY_RE +
    '$'
)

# Matches sanitizers' 'in fuction+0x42/0x420' headers.
KSAN_RE = re.compile(
    '^' +
    '(?P<prefix>(BUG:).+in )' +
    FRAME_BODY_RE +
    '$'
)

# Matches a single relevant line of `readelf -Ws` output.
READELF_RE = re.compile(
    '^[ ]*' +
    '(?P<num>' + DECNUM_RE + '):[ ]+' +
    '(?P<offset>' + HEXNUM_RE + ')[ ]+' +
    '(?P<size>' + DECNUM_RE + ')[ ]+' +
    '(?P<type>(OBJECT|FUNC|NOTYPE))[ ]+' +
    '(?P<bind>(LOCAL|GLOBAL))[ ]+' +
    '(?P<vis>DEFAULT)[ ]+' +
    '(?P<section>' + DECNUM_RE + ')[ ]+' +
    '(?P<symbol>[^ ]+)$'
)

class Symbolizer(object):
    def __init__(self, binary_path):
        self.proc = subprocess.Popen(
            ['addr2line', '-f', '-i', '-e', binary_path],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE)

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        self.close()

    def process(self, addr):
        self.proc.stdin.write((addr + '\n').encode('ascii'))
        self.proc.stdin.write(('ffffffffffffffff\n').encode('ascii'))
        self.proc.stdin.flush()

        result = []
        while True:
            func = self.proc.stdout.readline().decode('ascii').rstrip()
            fileline = self.proc.stdout.readline().decode('ascii').rstrip()
            if func == '??':
                if len(result) == 0:
                    self.proc.stdout.readline().decode('ascii')
                    self.proc.stdout.readline().decode('ascii')
                return result
            result.append((func, fileline))

    def close(self):
        self.proc.kill()
        self.proc.wait()


def find_file(path, name, prefix=False):
    path = os.path.expanduser(path)
    best_match = None

    for root, dirs, files in os.walk(path):
        for f in files:
            if f == name:
                return os.path.join(root, f)
            if prefix and f.startswith(name):
                f_path = os.path.join(root, f)
                if best_match == None or len(f_path) < len(best_match):
                    best_match = f_path

    return best_match


class SymbolOffsetTable(object):
    """A table of symbol offsets.

    There can be several symbols with similar names. The only possible way to
    distinguish between them is by their size. For each symbol name we keep a
    mapping from the sizes of symbols with that name to their offsets.
    To conform with the kernel behavior, instead of the actual symbol size
    returned by nm we store the difference between the next symbol's offset and
    this symbol's offset.
    """
    def __init__(self, binary_path):
        output = subprocess.check_output(['readelf', '-Ws', binary_path]).decode('ascii')

        # Extract symbols for each section.
        sections = defaultdict(dict)
        for line in output.split('\n'):
            match = READELF_RE.match(line)
            if match == None:
                continue
            symbol = match.group('symbol')
            # Ignore init_module and cleanup_module, as those are aliases.
            if symbol == 'init_module' or symbol == 'cleanup_module':
                continue
            offset = int(match.group('offset'), 16)
            size = int(match.group('size'))
            section = match.group('section')
            if not(offset in sections[section]):
                sections[section][offset] = []
            sections[section][offset].append((symbol, size))

        # Store symbol sizes based on readelf-provided size (arm64).
        self.offsets = defaultdict(dict)
        for section in sections.values():
            for offset in section.keys():
                for (symbol, size) in section[offset]:
                    self.offsets[symbol][size] = offset

        # Calculate and store symbol sizes based on offset difference (x86-64).
        for section in sections.values():
            prev_offset = None
            for offset in sorted(section.keys()):
                if not(prev_offset):
                    prev_offset = offset
                    continue
                for (symbol, _) in section[prev_offset]:
                    self.offsets[symbol][offset - prev_offset] = prev_offset
                prev_offset = offset
            # Skip the last symbol, as we cannot calculate its size.

    def lookup_offset(self, symbol, size):
        offsets = self.offsets.get(symbol)
        if offsets is None:
            return None
        if (size not in offsets):
            return None
        return offsets[size]


class ReportProcessor(object):
    def __init__(self, linux_paths, strip_paths):
        self.strip_paths = strip_paths
        self.linux_paths = linux_paths
        self.module_symbolizers = {}
        self.module_offset_tables = {}
        self.loaded_files = {}

    def process_input(self, context_size, questionable):
        for line in sys.stdin:
            line = line.rstrip()
            line = self.strip_time(line)
            self.process_line(line, context_size, questionable)

    def strip_time(self, line):
        # Strip time prefix if present.
        match = BRACKET_PREFIX_RE.match(line)
        if match != None:
            line = match.group('body')
        # Try to strip thread/cpu number prefix if present.
        match = BRACKET_PREFIX_RE.match(line)
        if match != None:
            line = match.group('body')
        return line

    def process_line(self, line, context_size, questionable):
        # |RIP_RE| is less general than |FRAME_RE|, so try it first.
        match = None
        for regexp in [RIP_RE, LR_RE, KSAN_RE, FRAME_RE]:
            match = regexp.match(line)
            if match:
                break
        if match == None:
            print(line)
            return

        prefix = match.group('prefix')
        try:
            addr = match.group('addr')
        except IndexError:
            addr = None
        body = match.group('body')

        precise = True
        if 'precise' in match.groupdict().keys():
            precise = not match.group('precise')
        # Don't print frames with '?' until user asked otherwise.
        if not precise and not questionable:
            if '<EOI>' in match.group('prefix'):
                print(match.group('prefix'))
            return

        function = match.group('function')
        offset = match.group('offset')
        size = match.group('size')
        try:
            module = match.group('module')
        except IndexError:
            module = None

        if module == None:
            module = 'vmlinux'
        else:
            module += '.ko'

        if not self.load_module(module, module == 'vmlinux'):
            print(line)
            return

        symbolizer = self.module_symbolizers[module]
        loader = self.module_offset_tables[module]

        symbol_offset = loader.lookup_offset(function, int(size, 16))
        if symbol_offset is None:
            print(line)
            return

        instruction_offset = int(offset, 16)
        module_addr = hex(symbol_offset + instruction_offset - 1);

        frames = symbolizer.process(module_addr)

        if len(frames) == 0:
            print(line)
            return

        for i, frame in enumerate(frames):
            inlined = (i + 1 != len(frames))
            func, fileline = frame[0], frame[1]
            fileline = fileline.split(' (')[0] # strip ' (discriminator N)'
            self.print_frame(inlined, precise, prefix, addr, func, fileline,
                             body)
            self.print_lines(fileline, context_size)

    def load_module(self, module, prefix=False):
        if module in self.module_symbolizers.keys():
            return True

        for path in self.linux_paths:
            module_path = find_file(path, module, prefix)
            if module_path != None:
                break

        if module_path == None:
            return False

        self.module_symbolizers[module] = Symbolizer(module_path)
        self.module_offset_tables[module] = SymbolOffsetTable(module_path)
        return True

    def load_file(self, path):
        if path in self.loaded_files.keys():
            return self.loaded_files[path]
        try:
            with open(path) as f:
                self.loaded_files[path] = f.readlines()
                return self.loaded_files[path]
        except:
            return None

    def print_frame(self, inlined, precise, prefix, addr, func, fileline, body):
        if self.strip_paths != None:
            for path in self.strip_paths:
                fileline_parts = fileline.split(path, 1)
                if len(fileline_parts) >= 2:
                    fileline = fileline_parts[1].lstrip('/')
        if inlined:
            if addr != None:
                addr = '     inline     ';
            body = func
        precise = '' if precise else '? '
        if addr != None:
            print('%s[<%s>] %s%s %s' % (prefix, addr, precise, body, fileline))
        else:
            print('%s%s%s %s' % (prefix, precise, body, fileline))

    def print_lines(self, fileline, context_size):
        if context_size == 0:
            return
        fileline = fileline.split(':')
        filename, linenum = fileline[0], fileline[1]

        try:
            linenum = int(linenum)
        except:
            return
        assert linenum >= 0
        if linenum == 0: # addr2line failed to restore correct line info
            return
        linenum -= 1 # addr2line reports line numbers starting with 1

        start = max(0, linenum - context_size / 2)
        end = start + context_size
        lines = self.load_file(filename)
        if not lines:
            return

        for i, line in enumerate(lines[start:end]):
            print('    {0:5d} {1}'.format(i + start + 1, line), end=' ')

    def finalize(self):
        for module, symbolizer in self.module_symbolizers.items():
            symbolizer.close()


def print_usage():
    print('Usage: {0} --linux=<linux path>'.format(sys.argv[0]), end=' ')
    print('[--strip=<strip path>]', end=' ')
    print('[--context=<lines before/after>]', end=' ')
    print('[--questionable]', end=' ')
    print()


def main():
    try:
        opts, args = getopt.getopt(sys.argv[1:], 'l:s:c:q:',
                ['linux=', 'strip=', 'context=', 'questionable'])
    except:
        print_usage()
        sys.exit(1)

    linux_paths = []
    strip_paths = []
    context_size = 0
    questionable = False

    for opt, arg in opts:
        if opt in ('-l', '--linux'):
            linux_paths.append(arg)
        elif opt in ('-s', '--strip'):
            strip_paths.append(arg)
        elif opt in ('-c', '--context'):
            context_size = arg
        elif opt in ('-q', '--questionable'):
            questionable = True

    if len(linux_paths) == 0:
        linux_paths = [os.getcwd()]
    if len(strip_paths) == 0:
        strip_paths = [os.getcwd()]

    try:
        if isinstance(context_size, str):
            context_size = int(context_size)
    except:
        print_usage()
        sys.exit(1)

    processor = ReportProcessor(linux_paths, strip_paths)
    processor.process_input(context_size, questionable)
    processor.finalize()

    sys.exit(0)


if __name__ == '__main__':
    main()

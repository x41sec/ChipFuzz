"""
ChipFuzz.py - Chipwhisper assisted fuzzing.

This is a framework/tool to fuzz test code on an external IC
using a ChipWhipser to capture power traces, which are used
for coverage information.

Created by eric.sesterhenn@x41-dsec.de
Released under the terms of GPL 3.0
"""

import chipwhisperer as cw
import chipwhisperer.capture.scopes as scopes
import numpy as np
import hashlib
import argparse
import string
import datetime
import time
import pathlib
import random
import sys
import csv
import os

try:
    import pyradamsa
    RAD = pyradamsa.Radamsa()
except Exception:
    RAD = None


""" Configuration parameters """
PLATFORM = "CWNANO"
FIRMWARE = "/home/cw/chipwhisperer/hardware/victims/firmware/basic-passwdcheck/basic-passwdcheck-{}.hex".format(PLATFORM)
SAMPLES = 3000
TRESHOLD = SAMPLES / 15
MAXITER = 10000
LOG_LEVEL = 1
LENGTH = 5

# settings to identify repeating states in the end of traces
NEEDLETHRESH = 0.1
NEEDLETHRESHFULL = 0.2
NEEDLELEN = 3

DEBUG = 0
INFO = 1
WARN = 2
CRIT = 3

IDLEWARN = True
COUNT = 0
AFL_TIME = 0
args = None

parser = argparse.ArgumentParser(
    prog="ChipFuzz",
    description="Use chipwhisperer power traces as fuzzing coverage information",
    epilog="By eric.sesterhenn@x41-dsec.de")


def sum_abs_diff(array, start1, start2, length):
    """
    Calculate the sum of absolute difference with two starting points in the same trace.

    Args:
        array: Power trace
        start1: start of first area
        start2: start of second area
        length: lenght of comparison
    """
    rsum = 0
    for i in range(0, length):
        rsum += abs(array[start1 + i] - array[start2 + i])

    return rsum


def find_repeats(array):
    """
    Find repeating (idle) pattern at the end of a power trace.

    Args:
        array: Power trace

    Returns:
        Amount of repeats of the idle pattern
    """
    length = len(array)
    last_match = 0
    full_length = 0
    matches = 0
    for i in range(length - NEEDLELEN - 1, 0, -1):
        rsum = sum_abs_diff(array, length - NEEDLELEN, i, NEEDLELEN)
        if rsum < NEEDLETHRESH:
            # we got a candidate, check the full period
            full_length = length - NEEDLELEN - i
            rsum = sum_abs_diff(array, length - (2 * full_length), length - full_length, full_length)
            if (rsum < NEEDLETHRESHFULL):
                break

    if full_length > 0:
        for i in range(length - (full_length * 3), 0, full_length * -1):
            rsum = sum_abs_diff(array, i, length - full_length, full_length)
            if (rsum >= NEEDLETHRESHFULL):
                break
        last_match = (i + (2 * full_length))
        matches = ((length - full_length - last_match) / full_length)

    return matches


def log(level: int, string: str):
    """
    Log data to stdout.

    Args:
        level (int): Verbosity level of message
        string (str): Error message to be logged
    """
    if level >= LOG_LEVEL:
        print("{}: {}".format(datetime.datetime.fromtimestamp(time.time()), string))


def program_firmware(scope: scopes.ScopeTypes, prog):
    """
    Write firmware onto the target.

    Args:
        scope (scopes.ScopeTypes): The scope the target is attached to
        prog: Programmer
    """
    log(INFO, "Writing Firmware...")
    cw.program_target(scope, prog, FIRMWARE)


def reset_target(scope: scopes.ScopeTypes):
    """
    Reset the target to a know, default state.

    Args:
        scope (scopes.ScopeTypes): The scope the target is attached to
    """
    log(DEBUG, "Resetting Target...")
    if PLATFORM == "CW303" or PLATFORM == "CWLITEXMEGA":
        scope.io.pdic = 'low'
        time.sleep(0.1)
        scope.io.pdic = 'high_z'  # XMEGA doesn't like pdic driven high
        time.sleep(0.1)  # xmega needs more startup time
    elif "neorv32" in PLATFORM.lower():
        raise IOError("Default iCE40 neorv32 build does not have external reset - reprogram device to reset")
    elif PLATFORM == "CW308_SAM4S" or PLATFORM == "CWHUSKY":
        scope.io.nrst = 'low'
        time.sleep(0.25)
        scope.io.nrst = 'high_z'
        time.sleep(0.25)
    else:
        scope.io.nrst = 'low'
        time.sleep(0.05)
        scope.io.nrst = 'high_z'
        time.sleep(0.05)


def setup_platform(scope: scopes.ScopeTypes):
    """
    Prepare the platform, scope and target.

    Args:
        scope (scopes.ScopeTypes): The scope the target is attached to
    Returns:
        (scope, target, prog): the scope, the target board and programmer
    """
    log(DEBUG, "Setup")
    SS_VER = os.environ.get('SS_VER', 'SS_VER_1_1')
    try:
        if scope is None:
            scope = cw.scope()
        if not scope.connectStatus:
            scope.con()
    except NameError:
        scope = cw.scope()

    try:
        if SS_VER == "SS_VER_2_1":
            target_type = cw.targets.SimpleSerial2
        elif SS_VER == "SS_VER_2_0":
            raise OSError("SS_VER_2_0 is deprecated. Use SS_VER_2_1")
        else:
            target_type = cw.targets.SimpleSerial
    except Exception:
        SS_VER = "SS_VER_1_1"
        target_type = cw.targets.SimpleSerial

    try:
        target = cw.target(scope, target_type)
    except Exception:
        log(WARN, "Caught exception on reconnecting to target - attempting to reconnect to scope first.")
        log(WARN, "This is a work-around when USB has died without Python knowing. Ignore errors above this line.")
        scope = cw.scope()
        target = cw.target(scope, target_type)

    log(INFO, "Found ChipWhisperer😍")

    if "STM" in PLATFORM or PLATFORM == "CWLITEARM" or PLATFORM == "CWNANO":
        prog = cw.programmers.STM32FProgrammer
    elif PLATFORM == "CW303" or PLATFORM == "CWLITEXMEGA":
        prog = cw.programmers.XMEGAProgrammer
    elif "neorv32" in PLATFORM.lower():
        prog = cw.programmers.NEORV32Programmer
    elif PLATFORM == "CW308_SAM4S" or PLATFORM == "CWHUSKY":
        prog = cw.programmers.SAM4SProgrammer
    else:
        prog = None

    return (scope, target, prog)


def mangle(ins: bytes) -> bytes:
    """
    Actual fuzzing function.

    Args:
        ins (bytes): String to modify and mangle

    Returns:
        bytes: the modified string, which should be used for further fuzzing
    """
    global RAD
    pattern = bytes(random.choice(string.ascii_lowercase + string.digits + "#?&=%$/:\"'"), encoding="UTF-8")

    if RAD and random.choice("RN") == "R":
        return RAD.fuzz(ins, max_mut=LENGTH)

    if len(ins) == 0:
        return pattern * LENGTH

    i = random.randrange(0, len(ins))
    a = ins[0:i]
    b = ins[(i + 1):(len(ins))]
    ret = a + pattern + b
    return ret


def is_interesting(reply: str) -> bool:
    """
    Verify whether we found an interesting input by checking the targets reply.

    Args:
        reply (str): the reply to check

    Returns:
        bool: True if reply is interesting
    """
    return reply.find("granted") >= 0


def read_target(target) -> str:
    """
    Read data from the target via the serial connection.

    Args:
        target: The target board

    Returns:
        str: The string read
    """
    ret = ""
    num_char = target.in_waiting()
    while num_char > 0:
        ret = ret + target.read(num_char, 10)
        time.sleep(0.01)
        num_char = target.in_waiting()
    # log(DEBUG, "Received: {}".format(ret))
    return ret


def init_target(scope: scopes.ScopeTypes, target):
    """
    Initialize the target and do whatever is required to reach the input state.

    Args:
        scope (scopesScopeTypes): The scope the target is attached to
        target: The target
    """
    reset_target(scope)


def send_input(scope: scopes.ScopeTypes, target, data: bytes) -> np.ndarray:
    """
    Send input to the target and capture a trace of it being processed.

    Args:
        scope (scope.ScopeTypes): The scope the target is attached to
        target: The actual target
        data (str): Data to send to the target

    Returns:
        np.ndarray: An array containing the voltage readings
    """
    read_target(target)

    log(DEBUG, "Sending: '{}'".format(data.decode('unicode_escape')))

    scope.arm()
    target.write("{}\n".format(str(data.decode('unicode_escape'))))
    ret = scope.capture()
    if ret:
        log(WARN, 'Timeout happened during acquisition')

    trace = scope.get_last_trace()
    return trace


def xtest(scope: scopes.ScopeTypes, target, data: bytes) -> np.ndarray:
    """
    Start the testing, simple wrapper for send_input() in this case.

    Args:
        scope (scope.ScopeTypes): The scope the target is attached to
        target: The actual target
        data (str): Data to send to the target

    Returns:
        np.ndarray: An array containing the voltage readings
    """
    trace = send_input(scope, target, data)
    if len(trace) != SAMPLES:
        raise IOError("Reading sample trace failed")
    return trace


def check_abort(scope: scopes.ScopeTypes, target, data: bytes):
    """
    Check wheter we found a testcase that triggered an abort or similar condition that we want to detect.

    Args:
        scope (scope.ScopeTypes): The scope the target is attached to
        target: The actual target
        data (str): Data to send to the target
    """
    ret = read_target(target)
    if is_interesting(ret):
        log(WARN, "Found testcase that triggered an abort: {}".format(str(data, encoding='UTF-8')))
        log(WARN, "{}".format(ret))
        sys.exit(1)


def save_trace(ins: bytes, trace):
    """
    Save the corpus file and trace into the output folder.

    Args:
        ins (bytes): The corpus data
        trace: The power trace information
    """
    global COUNT

    if not args or not args.output:
        return

    m = hashlib.sha256()
    m.update(ins)
    shahash = m.hexdigest()

    csvout = os.path.join(args.output, "id:{:06d},src:{}.csv".format(COUNT, shahash))
    with open(csvout, 'w', newline="") as csvfile:
        x = csv.writer(csvfile)
        x.writerow(trace)

    datout = os.path.join(args.output, "id:{:06d},src:{}.dat".format(COUNT, shahash))
    with open(datout, 'wb') as file:
        file.write(ins)
        file.close()

    COUNT = COUNT + 1


def fuzz(scope: scopes.ScopeTypes, target, traces, ins: bytes):
    """
    Perfom the fuzzing.

    Args:
        scope (scope.ScopeTypes): The scope the target is attached to
        target: The actual target
        traces: Traces collected so far along with the data that caused then
        ins: (bytes): The new corpus testcase

    Returns:
        traces: full array of old and new traces along with the data.
    """
    global IDLEWARN

    rtraces = traces

    trace = xtest(scope, target, ins)
    check_abort(scope, target, ins)

    if IDLEWARN and (find_repeats(trace) < 3):
        log(WARN, "No idle patterns found at end of trace, maybe increase SAMPLES")
        IDLEWARN = False

    app = True
    for b in traces:
        (_, ref) = b
        diff = np.sum(np.abs(trace - ref))
        if diff < TRESHOLD:
            app = False
            break

    if app is True:
        init_target(scope, target)
        trace2 = xtest(scope, target, ins)
        diff2 = np.sum(np.abs(trace - trace2))

        if diff2 > TRESHOLD:
            log(INFO, "False positive: {} : {}/{}".format(str(ins), diff, diff2))
        else:
            log(INFO, "Found: {} : {}/{}".format(str(ins), diff, diff2))
            rtraces.append((ins, trace))
            save_trace(ins, trace)

    return rtraces


def afl_run(scope: scopes.ScopeTypes, target, traces):
    """
    Check AFL++ directories and check for additional inputs.

    Args:
        scope (scope.ScopeTypes): The scope the target is attached to
        target: The actual target
        traces: Traces collected so far along with the data that caused then

    Returns:
        traces: full array of old and new traces along with the data.
    """
    global args, AFL_TIME

    # only run if afl sync is enabled
    if not args or not args.afl:
        return traces

    rtraces = traces
    cnt = 0

    files = [f for f in pathlib.Path().glob(os.path.join(args.afl, "*/queue/*")) if f.is_file()]
    for file in files:
        # only get new files
        x = pathlib.Path(file).stat().st_mtime
        if x < AFL_TIME:
            continue

        with open(file, 'rb') as f:
            in1 = f.read()
            init_target(scope, target)
            rtraces = fuzz(scope, target, rtraces, in1)
            f.close()
        cnt = cnt + 1

    AFL_TIME = time.time()
    if cnt > 0:
        log(INFO, "Imported {} AFL++ corpus file(s)".format(cnt))

    return rtraces


def fuzzloop(scope: scopes.ScopeTypes, target, traces):
    """
    Magic happens here, we manage the traces and start fuzzing.

    Args:
        scope (scope.ScopeTypes): The scope the target is attached to
        target: The actual target
        traces: Traces collected so far along with the data that caused then

    Returns:
        traces: full array of old and new traces along with the data.
    """
    for a in traces:
        (ins, _) = a
        ins = mangle(ins)

        rtraces = fuzz(scope, target, traces, ins)
    return rtraces


def read_corpus(scope, target, traces):
    """
    Read input corpus files.

    Args:
        scope (scope.ScopeTypes): The scope the target is attached to
        target: The actual target
        traces: Traces collected so far along with the data that caused then
        mangle (boolean): True if testcases should be fuzzed

    Returns:
        traces: full array of old and new traces along with the data.
    """
    global args
    log(INFO, "Reading input corpus...")

    files = [f for f in pathlib.Path().glob(os.path.join(args.input, "*.dat")) if f.is_file()]
    for file in files:
        with open(file, 'rb') as f:
            in1 = f.read()
            traces = fuzz(scope, target, traces, in1)
            f.close()

    log(INFO, "Added {} corpus file(s)".format(len(files)))
    return traces


def parse_arguments():
    """Parse and handle command line arguments."""
    global RAD, parser, args, LOG_LEVEL, LENGTH

    parser.add_argument('--output', default=None, nargs='?', help="Output directory for traces and corpus", required=False)
    parser.add_argument('--input', default=None, nargs='?', help="Input corpus directory", required=False)
    if RAD:
        parser.add_argument('--radamsa', default=False, action='store_true', help="Use Radamsa for mutation", required=False)
    parser.add_argument('--loglevel', default=1, type=int, choices=range(0, 4), nargs='?', help="Log output verbosity", required=False)
    parser.add_argument('--length', default=5, type=int, nargs='?', help="Length of fuzzinput (0 for unlimited)", required=False)
    parser.add_argument('--afl', default=None, nargs='?', help="AFL sync directory", required=False)

    args = parser.parse_args()

    if args.radamsa is False:
        RAD = None
        log(INFO, "Radamsa mutator not enabled")

    if args.output:
        if os.path.exists(args.output):
            log(CRIT, "Output directory already exists: {}".format(args.output))
            sys.exit(-1)
        else:
            os.mkdir(args.output)

    if args.input:
        if not os.path.exists(args.input):
            log(CRIT, "Input directory does not exist: {}".format(args.input))
            sys.exit(-1)

    if args.loglevel:
        LOG_LEVEL = args.loglevel

    if args.length:
        LENGTH = args.length

    if args.afl:
        if not os.path.exists(args.afl):
            log(CRIT, "AFL sync directory does not exist: {}".format(args.input))
            sys.exit(-1)


if __name__ == "__main__":
    parse_arguments()

    # initialize scope
    (scope, target, prog) = setup_platform(None)
    time.sleep(0.05)
    scope.default_setup()
    scope.adc.samples = SAMPLES

    reset_target(scope)
    program_firmware(scope, prog)

    # make sure we have at least one trace to compare to
    traces = list()
    if LENGTH == 0:
        in1 = b'A' * 5
    else:
        in1 = b'A' * LENGTH

    init_target(scope, target)
    trace = xtest(scope, target, in1)
    traces.append((in1, trace))

    if args and args.input:
        traces = read_corpus(scope, target, traces)

    log(INFO, "Start fuzz testing...")
    while True:
        init_target(scope, target)
        traces = fuzzloop(scope, target, traces)
        traces = afl_run(scope, target, traces)

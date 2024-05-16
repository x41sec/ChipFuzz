# ChipFuzz

This project allows fuzzing on a ChipWhisperer-Nano. Other ChipWhisperer devices
might work as well but are not tested.


## Usage
~~~
usage: ChipFuzz [-h] [--output [OUTPUT]] [--input [INPUT]] [--radamsa]
                [--loglevel [{0,1,2,3}]] [--length [LENGTH]] [--afl [AFL]]
                [--force_len]

Use chipwhisperer power traces as fuzzing coverage information

optional arguments:
  -h, --help            show this help message and exit
  --output [OUTPUT]     Output directory for traces and corpus
  --input [INPUT]       Input corpus directory
  --radamsa             Use Radamsa for mutation
  --loglevel [{0,1,2,3}]
                        Log output verbosity
  --length [LENGTH]     Length of fuzzinput (0 for unlimited)
  --afl [AFL]           AFL sync directory
  --force_len           Only use testcases of the length set by --length, this
                        restricts AFL imported ones to this length

By eric.sesterhenn@x41-dsec.de
~~~

## Notes

Fuzz testing on a ChipWhisperer is slow, but it might generate different
corpus files than regular fuzzing that relies on more traditional
instrumentation. The main issue with the approach is the missing
depth-perception. We can only infer that two inputs cause a different
behavious, but we cannot see whether that is due do new code-paths
being traversed. 

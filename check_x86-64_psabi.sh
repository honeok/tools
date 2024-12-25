#!/usr/bin/env bash

flags=$(grep -oP '^flags\s+\K.+' /proc/cpuinfo)

[[ "$flags" =~ lm && "$flags" =~ cmov && "$flags" =~ cx8 && "$flags" =~ fpu && "$flags" =~ fxsr && "$flags" =~ mmx && "$flags" =~ syscall && "$flags" =~ sse2 ]] && level=1
[[ $level -eq 1 && "$flags" =~ cx16 && "$flags" =~ lahf && "$flags" =~ popcnt && "$flags" =~ sse4_1 && "$flags" =~ sse4_2 && "$flags" =~ ssse3 ]] && level=2
[[ $level -eq 2 && "$flags" =~ avx && "$flags" =~ avx2 && "$flags" =~ bmi1 && "$flags" =~ bmi2 && "$flags" =~ f16c && "$flags" =~ fma && "$flags" =~ abm && "$flags" =~ movbe && "$flags" =~ xsave ]] && level=3
[[ $level -eq 3 && "$flags" =~ avx512f && "$flags" =~ avx512bw && "$flags" =~ avx512cd && "$flags" =~ avx512dq && "$flags" =~ avx512vl ]] && level=4

((level > 0)) && echo "CPU supports x86-64-v$level" && exit $((level + 1))

exit 1

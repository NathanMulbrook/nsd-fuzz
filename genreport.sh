rm build/run/etc/nsd/*.profraw
rm default.profdata
cd build
export LLVM_PROFILE_FILE=nsd-%9m.profraw
#export DFSAN_OPTIONS=fast16labels=1:warn_unimplemented=0
 LSAN_OPTIONS=detect_leaks=0  ./nsd /home/admin/software/fuzzing/nsd-fuzz/build/corpus -runs=30000 -detect_leaks=0
cd run/etc/nsd/
rm coverage_txt.txt
rm coverage_HTML.html
/usr/bin/llvm-profdata merge -sparse *.profraw -o default.profdata
/usr/bin/llvm-cov show ../../../nsd  -format=html  -use-color -instr-profile=default.profdata > coverage_HTML.html
/usr/bin/llvm-cov report ../../../nsd -instr-profile=default.profdata > coverage_txt.txt

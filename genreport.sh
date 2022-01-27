rm *.profraw
rm default.profdata
 LSAN_OPTIONS=detect_leaks=0  ./nsd /home/admin/software/fuzzing/nsd-fuzz/build/corpus -runs=1000 -detect_leaks=0
rm coverage_txt.txt
rm coverage_HTML.html
/usr/bin/llvm-profdata merge -sparse *.profraw -o default.profdata
/usr/bin/llvm-cov show ./nsd  -format=html  -use-color -instr-profile=default.profdata > coverage_HTML.html
/usr/bin/llvm-cov report ./nsd -instr-profile=default.profdata > coverage_txt.txt

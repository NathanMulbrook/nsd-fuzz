cat logs/asan* | \
grep -v "SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior " | \
grep -v ": runtime error: " | \
grep -v "note: nonnull attribute specified here" | \
sed -E ':a;N;$!ba;s/\n/####/g'  | \
sed -E 's/(==)[0-9]{3,}(==)/==????==/g' | \
sed -E 's/(0x)[0-9a-fA-F]{3,}\:(.[0-9a-f]{2,2}){16}/???? ?????????????????????????????????/g' | \
sed -E 's/(0x)[0-9a-fA-F]{3,}/????/g' | \
sed -E 's/([Tt]hread T)[0-9]{0,3}/thread T???/g' | \
#sed -E 's/(Thread T)[0-9]{0,3}/Thread T???/g' | \
sed -E 's/(run_)[0-9]{1,2}/run_??/g' | \
sed -E 's/(\?\?\?\?\sT[0-9]{1,2})/???? T??/g' | \



sed  's/####=================================================================/\n=================================================================/g' | \
# grep -v "is located 0 bytes to the right of" | \
# grep -v "is located 1 bytes to the right of" | \
# grep -v "is located 2 bytes to the right of" | \
grep -v -e 'attempting\sfree\son\saddress\swhich\swas\snot\smalloc.*ch_malloc\.c\:266\:' | \


sort | \
uniq | \
#sed 's/=================================================================####/=================================================================\n/g' | \
sed  's/####/\n/g' > asanfiltered.log

sort asanfiltered.log | grep "ERROR" | grep "AddressSanitizer" | sort | uniq -c | sort


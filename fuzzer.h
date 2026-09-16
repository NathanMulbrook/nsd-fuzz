#ifndef NSD_FUZZER_H
#define NSD_FUZZER_H

void launchFuzzer(void);
void fuzzerShutdown(void);
void fuzzerPacketProcessed(void);
void fuzzerWorkerWait(void);
int fuzzerInitialize(void);

#endif

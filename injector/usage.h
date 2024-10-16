#ifndef USAGE_H
#define USAGE_H

#define INVALID "[-] Invalid arguments, please type \"gftrace.exe --help\"\n"

#define USAGE   "[+] Usage: gftrace.exe [options]\n\n"                                              \
                "Options:\n"                                                                        \
                "           -f      <file>      The executable to be traced. (required)\n"          \
				"           -o      <output>    The file which receives gftrace's output.\n"        \
                "           --help              Display this message.\n"                            \
                "\n[i] Example: gftrace.exe -f malware.exe -o trace.txt\n"

#endif //USAGE_H
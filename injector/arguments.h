#ifndef ARGUMENTS_H
#define ARGUMENTS_H

#include <stdint.h>
#include <stdbool.h>

#define mSetArg(s_args, arg) \
    ((s_args) |= (int)(arg))

#define mCheckArg(s_args, arg) \
    (((s_args) & (int)(arg)) == (int)(arg))

enum Args{
    file    = 1 << 0,      // -f
    output  = 1 << 1,      // -o
    help    = 1 << 2
};

typedef struct ProgramArguments {
    uint8_t s_args;
} PROGRAMARGUMENTS, * PPROGRAMARGUMENTS;

// Function prototypes
void SetArgBit(PPROGRAMARGUMENTS args, enum Args arg);
bool CheckArgBit(const PPROGRAMARGUMENTS args, enum Args arg);


#endif //ARGUMENTS_H
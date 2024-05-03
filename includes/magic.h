#ifndef MAGIC_H
#define MAGIC_H

#include <ntddk.h>

#pragma pack(push, 1)
typedef struct {
  UINT16 size;
  UINT64 base;
} GDTR, *PGDTR, IDTR, *PIDTR;
#pragma pack(pop)

typedef enum {
  ES = 0,
  CS,
  SS,
  DS,
  FS,
  GS,
  LDTR,
  TR,
} SelectorRegister;

typedef union {
  UINT16 value;
  struct {
    UINT16 rpl : 2;
    UINT16 ti : 1;
    UINT16 index : 13;
  } fields;
} SegmentSelector, *PSegmentSelector;

extern "C" UINT64 saved_rip = 0;
extern "C" UINT64 saved_rbp = 0;
extern "C" UINT64 saved_rsp = 0;

extern "C" void EnableVMXOperation(void);
extern "C" SegmentSelector GetCS(void);
extern "C" SegmentSelector GetDS(void);
extern "C" SegmentSelector GetES(void);
extern "C" SegmentSelector GetFS(void);
extern "C" void GetGDTR(PGDTR gdtr);
extern "C" SegmentSelector GetGS(void);
extern "C" void GetIDTR(PIDTR gdtr);
extern "C" SegmentSelector GetLDTR(void);
extern "C" SegmentSelector GetRFlags(void);
extern "C" SegmentSelector GetSS(void);
extern "C" SegmentSelector GetTR(void);
extern "C" void SaveState(void);
extern "C" void RestoreState(void);

#endif  // !MAGIC_H
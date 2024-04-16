#ifndef MAGIC_H
#define MAGIC_H

#include <ntddk.h>

#pragma pack(push, 1)
typedef struct {
  UINT16 size;
  UINT64 base;
} GDTR, *PGDTR, IDTR, *PIDTR;
#pragma pack(pop)

extern "C" void EnableVMXOperation(void);
extern "C" UINT64 GetCS(void);
extern "C" UINT64 GetDS(void);
extern "C" UINT64 GetES(void);
extern "C" UINT64 GetFS(void);
extern "C" void GetGDTR(PGDTR gdtr);
extern "C" UINT64 GetGS(void);
extern "C" void GetIDTR(PIDTR gdtr);
extern "C" UINT64 GetLDTR(void);
extern "C" UINT64 GetRFlags(void);
extern "C" UINT64 GetSS(void);
extern "C" UINT64 GetTR(void);

#endif  // !MAGIC_H
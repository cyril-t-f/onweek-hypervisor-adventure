#ifndef MAIN_H
#define MAIN_H

#include <ntddk.h>

#define DEVICE_NAME (L"\\Device\\my_hypervisor")
#define DOS_DEVICE_NAME (L"\\DosDevices\\my_hypervisor")

#define SIZE 0x1000
#define IA32_VMX_BASIC_MSR 0x480
#define REVISION_IDENTIFIER_MASK 0x7FFFFFFF

#define MAX_CPU_COUNT 64
#define EPT_N_ENTRIES 512
#define EPT_TABLE_WALK_LENGTH 3
#define EPT_INITIAL_N_PAGES 10

typedef struct {
  void* address;
  uintptr_t physical_address;
} Region, *PRegion;

typedef struct {
  Region vmxon_region;
  Region vmcs_region;
} VM, *PVM;

typedef struct {
  UINT64 memory_type : 3;
  UINT64 page_walk_length : 3;
  UINT64 enable_dirty_and_accessed : 1;
  UINT64 reserved_0 : 5;
  UINT64 pfn : 36;
  UINT64 reserved_1 : 16;
} EPTP, *PEPTP;

auto x = sizeof(EPTP);

typedef struct {
  UINT64 read : 1;
  UINT64 write : 1;
  UINT64 execute : 1;
  UINT64 memory_type : 3;
  UINT64 ignore_pat : 1;
  UINT64 ignored_0 : 1;
  UINT64 accessed : 1;
  UINT64 dirty : 1;
  UINT64 user_mode_execute : 1;
  UINT64 ignored_1 : 1;
  UINT64 pfn : 36;
  UINT64 reserved : 4;
  UINT64 ignored_2 : 11;
  UINT64 suppress_ve : 1;
} EPTTableEntry, *PEPTTableEntry;

PVM virtual_machines = nullptr;
PEPTP eptp = nullptr;

extern "C" void DriverUnload(PDRIVER_OBJECT DriverObject);
extern "C" void EnableVMXOperation(void);
void FreeEPTP(void);
void FreeEPTTable(PEPTTableEntry table);
void FreeEPTTable(PEPTTableEntry table, size_t walk_length);
void FreeRegion(PRegion region);
void FreeVirtualMachines(void);
UINT32 GetRevisionIdentifier(void);
bool InitializeEPTP(size_t initial_n_pages);
void InitializeMJFunctions(PDRIVER_OBJECT DriverObject);
NTSTATUS InitializeDevices(PDRIVER_OBJECT DriverObject);
bool InitializeRegion(PRegion region, UINT32 revision_identifier);
bool InitializeVirtualMachines(void);
bool IsAlignedTo4KB(uintptr_t ptr);
NTSTATUS MJDoNothing(PDEVICE_OBJECT DeviceObject, PIRP Irp);
PEPTP NewEPTP(void);
PEPTTableEntry NewEPTTable(void);
PVM NewVirtualMachines(void);

#endif  // !MAIN_H
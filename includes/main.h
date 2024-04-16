#ifndef MAIN_H
#define MAIN_H

#include <ntddk.h>

#define DEVICE_NAME (L"\\Device\\my_hypervisor")
#define DOS_DEVICE_NAME (L"\\DosDevices\\my_hypervisor")

#define SIZE 0x1000
#define IA32_DEBUGCTL_MSR 0x1D9
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

typedef struct {
  UINT64 limit_low : 16;
  UINT64 base_low : 16;
  UINT64 base_middle : 8;
  UINT64 access_byte : 8;
  UINT64 limit_high : 4;
  UINT64 flags : 4;
  UINT64 base_high : 8;
} SegmentDescriptor, *PSegmentDescriptor;

PVM virtual_machines = nullptr;
PEPTP eptp = nullptr;

PEPTP AllocateEPTP(void);
PEPTTableEntry AllocateEPTTable(void);
PVM AllocateVirtualMachines(void);
extern "C" void DriverUnload(PDRIVER_OBJECT DriverObject);
void FreeEPTP(void);
void FreeEPTTable(PEPTTableEntry table);
void FreeEPTTable(PEPTTableEntry table, size_t walk_length);
void FreeRegion(PRegion region);
void FreeVirtualMachines(void);
UINT32 GetRevisionIdentifier(void);
SegmentDescriptor GetSegmentDescriptor(UINT64 segment_selector);
void InitializeCurrentVMCS(void);
bool InitializeEPTP(size_t initial_n_pages);
void InitializeMJFunctions(PDRIVER_OBJECT DriverObject);
NTSTATUS InitializeDevices(PDRIVER_OBJECT DriverObject);
bool InitializeRegion(PRegion region, UINT32 revision_identifier);
bool InitializeVirtualMachine(PVM virtual_machine, size_t cpu_index,
                              size_t revision_identifier);
bool InitializeVirtualMachines(void);
bool IsAlignedTo4KB(uintptr_t ptr);
NTSTATUS MJDoNothing(PDEVICE_OBJECT DeviceObject, PIRP Irp);

#endif  // !MAIN_H
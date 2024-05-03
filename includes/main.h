#ifndef MAIN_H
#define MAIN_H

#include <ntddk.h>

#define DEVICE_NAME (L"\\Device\\my_hypervisor")
#define DOS_DEVICE_NAME (L"\\DosDevices\\my_hypervisor")

#define SIZE 0x1000
#define MAX_CPU_COUNT 64

#define IA32_DEBUGCTL_MSR 0x1D9

#define IA32_VMX_BASIC_MSR 0x480

#define IA32_SYSENTER_CS_MSR 0x174
#define IA32_SYSENTER_ESP_MSR 0x175
#define IA32_SYSENTER_EIP_MSR 0x176

#define IA32_FS_BASE_MSR 0xC0000100
#define IA32_GS_BASE_MSR 0xC0000101

#define REVISION_IDENTIFIER_MASK 0x7FFFFFFF

#define EPT_N_ENTRIES 512
#define EPT_TABLE_WALK_LENGTH 3
#define EPT_INITIAL_N_PAGES 10

typedef struct {
  void* address;
  uintptr_t physical_address;
} Memory, *PMemory, VMRegion, *PVMRegion;

typedef struct {
  VMRegion vmxon_region;
  VMRegion vmcs_region;
  Memory msr_bitmap;
  Memory stack;
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

typedef union {
  UINT64 value;
  struct {
    UINT64 limit_low : 16;
    UINT64 base_low : 16;
    UINT64 base_middle : 8;
    UINT64 segment_type : 4;
    UINT64 s : 1;
    UINT64 dpl : 2;
    UINT64 p : 1;
    UINT64 limit_high : 4;
    UINT64 reserved : 1;
    UINT64 l : 1;
    UINT64 db : 1;
    UINT64 g : 1;
    UINT64 base_high : 8;
  } fields;
} SegmentDescriptor, *PSegmentDescriptor;

typedef union {
  UINT16 value;
  struct {
    UINT16 rpl : 2;
    UINT16 ti : 1;
    UINT16 index : 13;
  } fields;
} SegmentSelector, *PSegmentSelector;

typedef union {
  UINT32 value;
  struct {
    UINT32 segment_type : 4;
    UINT32 s : 1;
    UINT32 dpl : 2;
    UINT32 p : 1;
    UINT32 reserved_0 : 4;
    UINT32 avl : 1;
    UINT32 l : 1;
    UINT32 db : 1;
    UINT32 g : 1;
    UINT32 segment_unusable : 1;
    UINT32 reserved_1 : 15;
  } fields;
} VMXSelectorAccessRights, *PVMXSelectorAccessRights;

PVM virtual_machines = nullptr;
PEPTP eptp = nullptr;

PEPTP AllocateEPTP(void);
PEPTTableEntry AllocateEPTTable(void);
PVM AllocateVirtualMachines(void);
extern "C" void DriverUnload(PDRIVER_OBJECT DriverObject);
void FreeEPTP(void);
void FreeEPTTable(PEPTTableEntry table);
void FreeEPTTable(PEPTTableEntry table, size_t walk_length);
void FreeMemory(PMemory memory);
void FreeRegion(PVMRegion region);
void FreeVirtualMachines(void);
UINT32 GetRevisionIdentifier(void);
SegmentDescriptor GetSegmentDescriptor(UINT64 segment_selector);
bool InitializeEPTP(size_t initial_n_pages);
void InitializeMJFunctions(PDRIVER_OBJECT DriverObject);
NTSTATUS InitializeDevices(PDRIVER_OBJECT DriverObject);
bool InitializeMemory(PMemory memory);
bool InitializeRegion(PVMRegion region, UINT32 revision_identifier);
bool InitializeVirtualMachine(PVM virtual_machine, size_t cpu_index,
                              size_t revision_identifier);
bool InitializeVirtualMachines(void);
bool IsAlignedTo4KB(uintptr_t ptr);
NTSTATUS MJDoNothing(PDEVICE_OBJECT DeviceObject, PIRP Irp);
void SetupCurrentVMCS(void);
void SetupCurrentVMCSHostArea(void);
void SetupCurrentVMCSGuestArea(void);
void SetupCurrentVMCSGuestSelectorData(UINT64 selector);

#endif  // !MAIN_H
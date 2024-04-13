#include "../includes/main.h"

#include <intrin.h>
#include <ntddk.h>

#define TO_PFN(address) ((address) >> 12)
#define FROM_PFN(pfn) ((pfn) << 12)
#define GOTO_ERROR(cond, msg, ...) \
  if (cond) {                      \
    DbgPrint(msg, __VA_ARGS__);    \
    goto error;                    \
  }

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject,
                                PUNICODE_STRING RegistryPath) {
  InitializeMJFunctions(DriverObject);
  DriverObject->DriverUnload = DriverUnload;

  GOTO_ERROR(!NT_SUCCESS(InitializeDevices(DriverObject)),
             "[-] Failed to initialize devices\n");

  GOTO_ERROR(!InitializeVirtualMachines(),
             "[-] Failed to initialize virtual machines\n");

  GOTO_ERROR(!InitializeEPTP(EPT_INITIAL_N_PAGES),
             "[-] Failed to initialize EPT tables\n");

  DbgPrint("[+] Driver finished initializing\n");
  return STATUS_SUCCESS;

error:
  return STATUS_UNSUCCESSFUL;
}

extern "C" void DriverUnload(PDRIVER_OBJECT DriverObject) {
  UNICODE_STRING dos_device_name = {0};
  PHYSICAL_ADDRESS pa = {0};
  size_t i = 0;

  RtlInitUnicodeString(&dos_device_name, DOS_DEVICE_NAME);
  IoDeleteSymbolicLink(&dos_device_name);
  IoDeleteDevice(DriverObject->DeviceObject);

  for (i = 0; i < KeQueryActiveProcessorCount(nullptr); i++) {
    KeSetSystemAffinityThread((KAFFINITY)(1 << i));
    __vmx_off();
    DbgPrint("[+] VMXOFF succeeded on CPU %d\n", i);
  }

  FreeVirtualMachines();
  FreeEPTP();

  DbgPrint("[+] Driver unloaded\n");
}

void FreeEPTP(void) {
  PEPTTableEntry pml4 = nullptr;
  PHYSICAL_ADDRESS pa = {0};

  if (!eptp) {
    DbgPrint("EPTP not initialized\n");
    return;
  }

  if (eptp->pfn) {
    pa.QuadPart = FROM_PFN(eptp->pfn);
    FreeEPTTable((PEPTTableEntry)MmGetVirtualForPhysical(pa));
    eptp->pfn = 0;
  }

  ExFreePool(eptp);
  eptp = nullptr;
}

void FreeEPTTable(PEPTTableEntry table) {
  FreeEPTTable(table, EPT_TABLE_WALK_LENGTH);
  ExFreePool(table);
}

void FreeEPTTable(PEPTTableEntry table, size_t walk_length) {
  size_t i = 0;
  void* ptr = nullptr;
  PHYSICAL_ADDRESS pa = {0};

  for (i = 0; i < EPT_N_ENTRIES; i++) {
    if (!table[i].pfn) continue;

    pa.QuadPart = FROM_PFN(table[i].pfn);
    ptr = MmGetVirtualForPhysical(pa);

    if (walk_length) FreeEPTTable((PEPTTableEntry)ptr, walk_length - 1);

    ExFreePool(ptr);
    table[i].pfn = 0;
  }
}

void FreeRegion(PRegion region) {
  if (!region->address) return;
  ExFreePool(region->address);
  region->address = nullptr;
  region->physical_address = 0;
}

void FreeVirtualMachines(void) {
  size_t i = 0;
  KIRQL old_irql = 0;

  if (virtual_machines) {
    for (i = 0; i < MAX_CPU_COUNT; i++) {
      FreeRegion(&virtual_machines[i].vmxon_region);
      FreeRegion(&virtual_machines[i].vmcs_region);
    }
  }

  ExFreePool(virtual_machines);
  virtual_machines = nullptr;
}

UINT32 GetRevisionIdentifier(void) {
  return __readmsr(IA32_VMX_BASIC_MSR) & REVISION_IDENTIFIER_MASK;
}

void InitializeMJFunctions(PDRIVER_OBJECT DriverObject) {
  size_t i = 0;
  for (i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++) {
    DriverObject->MajorFunction[i] = MJDoNothing;
  }
}

NTSTATUS InitializeDevices(PDRIVER_OBJECT DriverObject) {
  UNICODE_STRING device_name = {0};
  UNICODE_STRING dos_device_name = {0};
  PDEVICE_OBJECT device_object = nullptr;

  RtlInitUnicodeString(&device_name, DEVICE_NAME);
  GOTO_ERROR(!NT_SUCCESS(IoCreateDevice(DriverObject, 0, &device_name,
                                        FILE_DEVICE_UNKNOWN, 0, false,
                                        &device_object)),
             "[-] Failed to create device object\n");

  RtlInitUnicodeString(&dos_device_name, DOS_DEVICE_NAME);
  GOTO_ERROR(!NT_SUCCESS(IoCreateSymbolicLink(&dos_device_name, &device_name)),
             "[-] Failed to create symbolic link\n");

  return STATUS_SUCCESS;

error:
  return STATUS_UNSUCCESSFUL;
}

bool InitializeVirtualMachines(void) {
  size_t i = 0;
  UINT32 revision_identifier = 0;
  UINT8 status = 0;

  if (virtual_machines) {
    DbgPrint("Virtual machines already initialized\n");
    return true;
  }

  revision_identifier = GetRevisionIdentifier();

  virtual_machines = NewVirtualMachines();
  GOTO_ERROR(!virtual_machines, "[-] Failed to create virtual machines\n");

  for (i = 0; i < KeQueryActiveProcessorCount(nullptr); i++) {
    KeSetSystemAffinityThread((KAFFINITY)(1 << i));

    EnableVMXOperation();
    DbgPrint("[+] Enabled VMX operation on CPU %d\n", i);

    InitializeRegion(&virtual_machines[i].vmxon_region, revision_identifier);
    GOTO_ERROR(!virtual_machines[i].vmxon_region.address,
               "[-] Failed to create VMXON region\n");
    DbgPrint("[+] VMXON region address %p, physical %p\n",
             virtual_machines[i].vmxon_region.address,
             virtual_machines[i].vmxon_region.physical_address);

    status = __vmx_on(&virtual_machines[i].vmxon_region.physical_address);
    GOTO_ERROR(status, "[-] VMXON failed, status %d, CPU %d\n", status, i);
    DbgPrint("[+] VMXON succeeded on CPU %d\n", i);

    InitializeRegion(&virtual_machines[i].vmcs_region, revision_identifier);
    GOTO_ERROR(!virtual_machines[i].vmcs_region.address,
               "[-] Failed to create VMCS region\n");
    DbgPrint("[+] VMCS region address %p, physical %p\n",
             virtual_machines[i].vmcs_region.address,
             virtual_machines[i].vmcs_region.physical_address);

    status = __vmx_vmptrld(&virtual_machines[i].vmcs_region.physical_address);
    GOTO_ERROR(status, "[-] VMPTRLD failed, status %d, CPU %d\n", status, i);
    DbgPrint("[+] VMPTRLD succeeded on CPU %d\n", i);
  }

  return true;

error:
  return false;
}

bool IsAlignedTo4KB(uintptr_t ptr) { return (ptr & 0xfff) == 0; }

NTSTATUS MJDoNothing(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
  Irp->IoStatus.Status = STATUS_SUCCESS;
  Irp->IoStatus.Information = 0;
  IoCompleteRequest(Irp, IO_NO_INCREMENT);
  return STATUS_SUCCESS;
}

bool InitializeEPTP(size_t initial_n_pages) {
  PEPTTableEntry pml4 = nullptr;
  PEPTTableEntry pdpt = nullptr;
  PEPTTableEntry pd = nullptr;
  PEPTTableEntry pt = nullptr;
  void* page = nullptr;

  size_t i = 0;
  PHYSICAL_ADDRESS pa = {0};

  if (eptp) {
    DbgPrint("EPTP already initialized\n");
    return true;
  }

  eptp = (PEPTP)ExAllocatePool(NonPagedPool, sizeof(EPTP));
  GOTO_ERROR(!eptp, "[-] Failed to allocate EPTP\n");
  DbgPrint("[+] Successfully allocated EPTP %p\n", eptp);

  pml4 = NewEPTTable();
  GOTO_ERROR(!pml4, "[-] Failed to create EPT PML4\n");
  DbgPrint("[+] Successfully allocated EPT PML4 %p\n", pml4);

  eptp->enable_dirty_and_accessed = true;
  eptp->memory_type = 6;
  eptp->page_walk_length = EPT_TABLE_WALK_LENGTH;
  eptp->pfn = TO_PFN(MmGetPhysicalAddress(pml4).QuadPart);

  pdpt = NewEPTTable();
  GOTO_ERROR(!pdpt, "[-] Failed to create EPT PDPT\n");
  DbgPrint("[+] Successfully allocated EPT PDPT %p\n", pdpt);

  pml4[0].read = true;
  pml4[0].write = true;
  pml4[0].execute = true;
  pml4[0].pfn = TO_PFN(MmGetPhysicalAddress(pdpt).QuadPart);

  pd = NewEPTTable();
  GOTO_ERROR(!pd, "[-] Failed to create EPT PD\n");
  DbgPrint("[+] Successfully allocated EPT PD %p\n", pd);

  pdpt[0].read = true;
  pdpt[0].write = true;
  pdpt[0].execute = true;
  pdpt[0].pfn = TO_PFN(MmGetPhysicalAddress(pd).QuadPart);

  pt = NewEPTTable();
  GOTO_ERROR(!pt, "[-] Failed to create EPT PT\n");
  DbgPrint("[+] Successfully allocated EPT PT %p\n", pt);

  pd[0].read = true;
  pd[0].write = true;
  pd[0].execute = true;
  pd[0].pfn = TO_PFN(MmGetPhysicalAddress(pt).QuadPart);

  for (i = 0; i < initial_n_pages; i++) {
    page = ExAllocatePool(NonPagedPool, SIZE);
    GOTO_ERROR(!page, "[-] Failed to allocate EPT PTE %d page\n", i);
    DbgPrint("[+] Successfully allocated EPT PTE %d page %p\n", i, page);

    pt[i].read = true;
    pt[i].write = true;
    pt[i].execute = true;
    pt[i].memory_type = 6;
    pt[i].pfn = TO_PFN(MmGetPhysicalAddress(page).QuadPart);
  }

  return true;

error:
  if (eptp) FreeEPTP();
  return false;
}

bool InitializeRegion(PRegion region, UINT32 revision_identifier) {
  region->address = ExAllocatePool(NonPagedPool, SIZE);
  GOTO_ERROR(!region->address, "[-] Failed to allocate memory for region\n");

  region->physical_address = MmGetPhysicalAddress(region->address).QuadPart;
  GOTO_ERROR(!IsAlignedTo4KB(region->physical_address),
             "[-] Region is not physically aligned to 4KB\n");

  RtlSecureZeroMemory(region->address, SIZE);
  *(UINT32*)region->address = revision_identifier;

  return true;

error:
  if (region) FreeRegion(region);
  return false;
}

PEPTP NewEPTP(void) {
  PEPTP eptp = (PEPTP)ExAllocatePool(NonPagedPool, sizeof(EPTP));
  GOTO_ERROR(!eptp, "[-] Failed to allocate EPTP\n");
  RtlSecureZeroMemory(eptp, sizeof(EPTP));
  return eptp;

error:
  return nullptr;
}

PEPTTableEntry NewEPTTable(void) {
  PEPTTableEntry table = (PEPTTableEntry)ExAllocatePool(
      NonPagedPool, sizeof(EPTTableEntry) * EPT_N_ENTRIES);
  GOTO_ERROR(!table, "[-] Failed to allocate EPT table\n");
  RtlSecureZeroMemory(table, sizeof(EPTTableEntry) * EPT_N_ENTRIES);
  return table;

error:
  return nullptr;
}

PVM NewVirtualMachines(void) {
  PVM virtual_machines =
      (PVM)ExAllocatePool(NonPagedPool, MAX_CPU_COUNT * sizeof(VM));
  GOTO_ERROR(!virtual_machines, "[-] Failed to allocate virtual machines\n");
  RtlSecureZeroMemory(virtual_machines, MAX_CPU_COUNT * sizeof(VM));
  return virtual_machines;

error:
  return nullptr;
}
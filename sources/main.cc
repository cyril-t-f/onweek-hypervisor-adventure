#include "../includes/main.h"

#include <intrin.h>
#include <ntddk.h>

/*
  TODO: Fix double free in FreeEPTTable
*/

#define TO_PFN(address) ((address) >> 12)
#define FROM_PFN(pfn) ((pfn) << 12)

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject,
                                PUNICODE_STRING RegistryPath) {
  InitializeMJFunctions(DriverObject);

  if (!NT_SUCCESS(InitializeDevices(DriverObject))) {
    DbgPrint("[-] Failed to initialize devices\n");
    return STATUS_UNSUCCESSFUL;
  }
  DriverObject->DriverUnload = DriverUnload;

  if (!InitializeVirtualMachines()) {
    DbgPrint("[-] Failed to initialize virtual machines\n");
    return STATUS_UNSUCCESSFUL;
  }

  if (!InitializeEPTP(EPT_INITIAL_N_PAGES)) {
    DbgPrint("[-] Failed to initialize EPT tables\n");
    return STATUS_UNSUCCESSFUL;
  }

  DbgPrint("[+] Driver finished initializing\n");
  return STATUS_SUCCESS;
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
    pml4 = (PEPTTableEntry)MmGetVirtualForPhysical(pa);
    FreeEPTTable(pml4, EPT_TABLE_WALK_LENGTH);
    eptp->pfn = 0;
  }

  ExFreePool(eptp);
  eptp = nullptr;
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

  ExFreePool(table);
}

void FreeRegion(PRegion region) {
  if (!region->address) {
    ExFreePool(region->address);
    region->address = nullptr;
    region->physical_address = 0;
  }
  return;
}

void FreeVirtualMachines(void) {
  size_t i = 0;
  KIRQL old_irql = 0;

  if (virtual_machines) {
    for (i = 0; i < MAX_CPU_COUNT; i++) {
      if (virtual_machines[i].vmxon_region.address)
        FreeRegion(&virtual_machines[i].vmxon_region);

      if (virtual_machines[i].vmcs_region.address)
        FreeRegion(&virtual_machines[i].vmcs_region);
    }
  }

  ExFreePool(virtual_machines);
  virtual_machines = nullptr;
}

UINT32 GetRevisionIdentifier(void) {
  return __readmsr(IA32_VMX_BASIC_MSR) & 0x7FFFFFFF;
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
  RtlInitUnicodeString(&dos_device_name, DOS_DEVICE_NAME);

  if (!NT_SUCCESS(IoCreateDevice(DriverObject, 0, &device_name,
                                 FILE_DEVICE_UNKNOWN, 0, false,
                                 &device_object))) {
    DbgPrint("[-] Failed to create device object\n");
    return STATUS_UNSUCCESSFUL;
  }

  if (!NT_SUCCESS(IoCreateSymbolicLink(&dos_device_name, &device_name))) {
    DbgPrint("[-] Failed to create symbolic link\n");
    return STATUS_UNSUCCESSFUL;
  }

  return STATUS_SUCCESS;
}

bool InitializeVirtualMachines(void) {
  UINT32 revision_identifier = 0;
  UINT8 status = 0;
  size_t i = 0;
  Region vmxon_region = {0};
  Region vmcs_region = {0};

  if (virtual_machines) {
    DbgPrint("Virtual machines already initialized\n");
    return true;
  }

  virtual_machines =
      (PVM)ExAllocatePool(NonPagedPool, MAX_CPU_COUNT * sizeof(VM));
  if (!virtual_machines) {
    DbgPrint("[-] Failed to allocate memory for virtual machines\n");
    return false;
  }

  revision_identifier = GetRevisionIdentifier();

  for (i = 0; i < KeQueryActiveProcessorCount(nullptr); i++) {
    KeSetSystemAffinityThread((KAFFINITY)(1 << i));

    EnableVMXOperation();
    DbgPrint("[+] Enabled VMX operation on CPU %d\n", i);

    InitializeRegion(&vmxon_region, revision_identifier);
    if (!vmxon_region.address) {
      DbgPrint("[-] Failed to create VMXON region\n");
      return false;
    }
    DbgPrint("[+] VMXON region address %p, physical %p\n", vmxon_region.address,
             vmxon_region.physical_address);

    status = __vmx_on(&vmxon_region.physical_address);
    if (status) {
      DbgPrint("[-] VMXON failed, status %d, CPU %d\n", status, i);
      return false;
    }
    DbgPrint("[+] VMXON succeeded on CPU %d\n", i);

    InitializeRegion(&vmcs_region, revision_identifier);
    if (!vmcs_region.address) {
      DbgPrint("[-] Failed to create VMCS region\n");
      return false;
    }
    DbgPrint("[+] VMCS region address %p, physical %p\n", vmcs_region.address,
             vmcs_region.physical_address);

    status = __vmx_vmptrld(&vmcs_region.physical_address);
    if (status) {
      DbgPrint("[-] VMPTRLD failed, status %d, CPU %d\n", status, i);
      return false;
    }
    DbgPrint("[+] VMPTRLD succeeded on CPU %d\n", i);

    virtual_machines[i].vmxon_region = vmcs_region;
    virtual_machines[i].vmcs_region = vmcs_region;
  }

  return true;
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

  size_t i = 0;
  void* page = nullptr;
  PHYSICAL_ADDRESS pa = {0};

  if (eptp) {
    DbgPrint("EPTP already initialized\n");
    return true;
  }

  eptp = (PEPTP)ExAllocatePool(NonPagedPool, sizeof(EPTP));
  if (!eptp) {
    DbgPrint("[-] Failed to create EPTP\n");
    goto error;
  }
  DbgPrint("[+] Successfully allocated EPTP %p\n", eptp);

  pml4 = NewEPTTable();
  if (!pml4) {
    DbgPrint("[-] Failed to create EPT PML4\n");
    goto error;
  }
  DbgPrint("[+] Successfully allocated EPT PML4 %p\n", pml4);

  eptp->enable_dirty_and_accessed = true;
  eptp->memory_type = 6;
  eptp->page_walk_length = EPT_TABLE_WALK_LENGTH;
  eptp->pfn = TO_PFN(MmGetPhysicalAddress(pml4).QuadPart);

  pdpt = NewEPTTable();
  if (!pdpt) {
    DbgPrint("[-] Failed to create EPT PDPT\n");
    goto error;
  }
  DbgPrint("[+] Successfully allocated EPT PDPT %p\n", pdpt);

  pml4[0].read = true;
  pml4[0].write = true;
  pml4[0].execute = true;
  pml4[0].pfn = TO_PFN(MmGetPhysicalAddress(pdpt).QuadPart);

  pd = NewEPTTable();
  if (!pd) {
    DbgPrint("[-] Failed to create EPT PD\n");
    goto error;
  }
  DbgPrint("[+] Successfully allocated EPT PD %p\n", pd);

  pdpt[0].read = true;
  pdpt[0].write = true;
  pdpt[0].execute = true;
  pdpt[0].pfn = TO_PFN(MmGetPhysicalAddress(pd).QuadPart);

  pt = NewEPTTable();
  if (!pt) {
    DbgPrint("[-] Failed to create EPT PT\n");
    goto error;
  }
  DbgPrint("[+] Successfully allocated EPT PT %p\n", pt);

  pd[0].read = true;
  pd[0].write = true;
  pd[0].execute = true;
  pd[0].pfn = TO_PFN(MmGetPhysicalAddress(pt).QuadPart);

  for (i = 0; i < initial_n_pages; i++) {
    page = ExAllocatePool(NonPagedPool, SIZE);
    if (!page) {
      DbgPrint("[-] Failed to allocate PT %d page\n", i);
      goto error;
    }
    DbgPrint("[+] Successfully allocated PTE %d page %p\n", i, page);

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
  if (!region->address) {
    DbgPrint("[-] Failed to allocate memory for region\n");
    goto error;
  }

  region->physical_address = MmGetPhysicalAddress(region->address).QuadPart;
  if (!IsAlignedTo4KB(region->physical_address)) {
    DbgPrint("[-] Region is not physically aligned to 4KB\n");
    goto error;
  }

  RtlSecureZeroMemory(region->address, SIZE);
  *(UINT32*)region->address = revision_identifier;

  return true;

error:
  FreeRegion(region);
  return false;
}

PEPTP NewEPTP(void) {
  PEPTP eptp = nullptr;

  eptp = (PEPTP)ExAllocatePool(NonPagedPool, sizeof(EPTP));
  if (!eptp) {
    DbgPrint("[-] Failed to allocate EPTP\n");
    return nullptr;
  }
  RtlSecureZeroMemory(eptp, sizeof(EPTP));
  return eptp;
}

PEPTTableEntry NewEPTTable(void) {
  PEPTTableEntry table = nullptr;

  table = (PEPTTableEntry)ExAllocatePool(NonPagedPool,
                                         sizeof(EPTTableEntry) * EPT_N_ENTRIES);
  if (!table) {
    DbgPrint("[-] Failed to allocate EPT GEN\n");
    return nullptr;
  }
  RtlSecureZeroMemory(table, sizeof(EPTTableEntry) * EPT_N_ENTRIES);
  return table;
}

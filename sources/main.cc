#include "../includes/main.h"

#include <intrin.h>
#include <ntddk.h>

#include "../includes/magic.h"
#include "../includes/vmcs.h"

#define TO_PFN(address) ((address) >> 12)

#define FROM_PFN(pfn) ((pfn) << 12)

#define GOTO_ERROR(cond, msg, ...) \
  if (cond) {                      \
    DbgPrint(msg, __VA_ARGS__);    \
    goto error;                    \
  }

#define SEGMENT_DESCRIPTOR_BASE(descriptor) \
  ((descriptor.fields.base_high << 24) |    \
   (descriptor.fields.base_middle << 16) | descriptor.fields.base_low)

#define SEGMENT_DESCRIPTOR_LIMIT(descriptor) \
  ((descriptor.fields.limit_high << 16) | descriptor.fields.limit_low)

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject,
                                PUNICODE_STRING RegistryPath) {
  InitializeMJFunctions(DriverObject);
  DriverObject->DriverUnload = DriverUnload;

  GOTO_ERROR(!NT_SUCCESS(InitializeDevices(DriverObject)),
             "[-] Failed to initialize "
             "devices\n");

  GOTO_ERROR(!InitializeVirtualMachines(),
             "[-] Failed to initialize "
             "virtual machines\n");

  GOTO_ERROR(!InitializeEPTP(EPT_INITIAL_N_PAGES),
             "[-] Failed to initialize "
             "EPT tables\n");

  DbgPrint(
      "[+] Driver finished "
      "initializing\n");

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
  }

  FreeVirtualMachines();
  FreeEPTP();

  DbgPrint("[+] Driver unloaded\n");
}

void FreeEPTP(void) {
  PEPTTableEntry pml4 = nullptr;
  PHYSICAL_ADDRESS pa = {0};

  if (!eptp) {
    DbgPrint(
        "[*] Can't free EPTP: Not "
        "initialized\n");
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

void FreeMemory(PMemory memory) {
  if (!memory->address) return;
  ExFreePool(memory->address);
  memory->address = nullptr;
  memory->physical_address = 0;
}

void FreeRegion(PVMRegion region) { FreeMemory((PMemory)region); }

void FreeVirtualMachines(void) {
  size_t i = 0;
  KIRQL old_irql = 0;

  if (virtual_machines) {
    for (i = 0; i < MAX_CPU_COUNT; i++) {
      FreeRegion(&virtual_machines[i].vmxon_region);
      FreeRegion(&virtual_machines[i].vmcs_region);
      FreeMemory(&virtual_machines[i].msr_bitmap);
      FreeMemory(&virtual_machines[i].stack);
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

SegmentDescriptor GetSegmentDescriptor(SegmentSelector segment_selector) {
  GDTR gdtr = {0};
  GetGDTR(&gdtr);
  // TODO: handle those extended TSS_* extended descriptors that are 16 bytes
  // and not 8 bytes
  return ((SegmentDescriptor*)gdtr.base)[segment_selector.fields.index];
}

NTSTATUS InitializeDevices(PDRIVER_OBJECT DriverObject) {
  UNICODE_STRING device_name = {0};
  UNICODE_STRING dos_device_name = {0};
  PDEVICE_OBJECT device_object = nullptr;

  RtlInitUnicodeString(&device_name, DEVICE_NAME);
  GOTO_ERROR(!NT_SUCCESS(IoCreateDevice(DriverObject, 0, &device_name,
                                        FILE_DEVICE_UNKNOWN, 0, false,
                                        &device_object)),
             "[-] Failed to create device "
             "object\n");

  RtlInitUnicodeString(&dos_device_name, DOS_DEVICE_NAME);
  GOTO_ERROR(!NT_SUCCESS(IoCreateSymbolicLink(&dos_device_name, &device_name)),
             "[-] Failed to create "
             "symbolic link\n");

  return STATUS_SUCCESS;

error:
  return STATUS_UNSUCCESSFUL;
}

bool InitializeVirtualMachine(PVM virtual_machine, size_t cpu_index,
                              size_t revision_identifier) {
  UINT8 status = 0;

  KeSetSystemAffinityThread((KAFFINITY)(1 << cpu_index));

  EnableVMXOperation();
  DbgPrint(
      "[+] Enabled VMX operation "
      "on CPU %d\n",
      cpu_index);

  GOTO_ERROR(
      !InitializeRegion(&virtual_machine->vmxon_region, revision_identifier),
      "[-] Failed to initialize "
      "VMXON region\n");
  DbgPrint(
      "[+] VMXON region address "
      "%p, physical %p\n",
      virtual_machine->vmxon_region.address,
      virtual_machine->vmxon_region.physical_address);

  GOTO_ERROR(!InitializeMemory(&virtual_machine->stack),
             "[-] Failed to initialize VM "
             "stack\n");
  DbgPrint(
      "[+] VM stack address %p, "
      "physical %p\n",
      virtual_machine->stack.address, virtual_machine->stack.physical_address);

  GOTO_ERROR(!InitializeMemory(&virtual_machine->msr_bitmap),
             "[-] Failed to initialize "
             "MSR bitmap\n");
  DbgPrint(
      "[+] MSR bitmap address %p, "
      "physical %p\n",
      virtual_machine->msr_bitmap.address,
      virtual_machine->msr_bitmap.physical_address);

  status = __vmx_on(&virtual_machine->vmxon_region.physical_address);
  GOTO_ERROR(status,
             "[-] VMXON failed, "
             "status %d, CPU %d\n",
             status, cpu_index);
  DbgPrint(
      "[+] VMXON succeeded on CPU "
      "%d\n",
      cpu_index);

  GOTO_ERROR(
      !InitializeRegion(&virtual_machine->vmcs_region, revision_identifier),
      "[-] Failed to initialize "
      "VMCS region\n");
  DbgPrint(
      "[+] VMCS region address %p, "
      "physical %p\n",
      virtual_machine->vmcs_region.address,
      virtual_machine->vmcs_region.physical_address);

  status = __vmx_vmclear(&virtual_machine->vmcs_region.physical_address);
  GOTO_ERROR(status,
             "[-] VMCLEAR failed, "
             "status %d, CPU %d\n",
             status, cpu_index);
  DbgPrint(
      "[+] VMCLEAR succeeded on "
      "CPU %d\n",
      cpu_index);

  status = __vmx_vmptrld(&virtual_machine->vmcs_region.physical_address);
  GOTO_ERROR(status,
             "[-] VMPTRLD failed, "
             "status %d, CPU %d\n",
             status, cpu_index);
  DbgPrint(
      "[+] VMPTRLD succeeded on "
      "CPU %d\n",
      cpu_index);

  return true;

error:
  __vmx_off();
  FreeRegion(&virtual_machine->vmxon_region);
  FreeRegion(&virtual_machine->vmcs_region);
  return false;
}

bool InitializeVirtualMachines(void) {
  size_t i = 0;
  UINT32 revision_identifier = 0;
  UINT8 status = 0;

  if (virtual_machines) {
    DbgPrint(
        "[*] Can't initialize "
        "virtual machines: Already "
        "initialized\n");
    return true;
  }

  virtual_machines = AllocateVirtualMachines();
  GOTO_ERROR(!virtual_machines,
             "[-] Failed to create "
             "virtual machines\n");

  revision_identifier = GetRevisionIdentifier();
  for (i = 0; i < KeQueryActiveProcessorCount(nullptr); i++) {
    GOTO_ERROR(
        !InitializeVirtualMachine(&virtual_machines[i], i, revision_identifier),
        "[-] Failed to initialize "
        "virtual machine on CPU "
        "%d\n",
        i);
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
    DbgPrint(
        "[*] Can't initialize "
        "EPTP: Already "
        "initialized\n");
    return true;
  }

  eptp = (PEPTP)ExAllocatePool(NonPagedPool, sizeof(EPTP));
  GOTO_ERROR(!eptp,
             "[-] Failed to "
             "allocate EPTP\n");
  DbgPrint(
      "[+] Successfully allocated "
      "EPTP %p\n",
      eptp);

  pml4 = AllocateEPTTable();
  GOTO_ERROR(!pml4,
             "[-] Failed to create "
             "EPT PML4\n");
  DbgPrint(
      "[+] Successfully allocated "
      "EPT PML4 %p\n",
      pml4);

  eptp->enable_dirty_and_accessed = true;
  eptp->memory_type = 6;
  eptp->page_walk_length = EPT_TABLE_WALK_LENGTH;
  eptp->pfn = TO_PFN(MmGetPhysicalAddress(pml4).QuadPart);

  pdpt = AllocateEPTTable();
  GOTO_ERROR(!pdpt,
             "[-] Failed to create "
             "EPT PDPT\n");
  DbgPrint(
      "[+] Successfully allocated "
      "EPT PDPT %p\n",
      pdpt);

  pml4[0].read = true;
  pml4[0].write = true;
  pml4[0].execute = true;
  pml4[0].pfn = TO_PFN(MmGetPhysicalAddress(pdpt).QuadPart);

  pd = AllocateEPTTable();
  GOTO_ERROR(!pd,
             "[-] Failed to create "
             "EPT PD\n");
  DbgPrint(
      "[+] Successfully allocated "
      "EPT PD %p\n",
      pd);

  pdpt[0].read = true;
  pdpt[0].write = true;
  pdpt[0].execute = true;
  pdpt[0].pfn = TO_PFN(MmGetPhysicalAddress(pd).QuadPart);

  pt = AllocateEPTTable();
  GOTO_ERROR(!pt,
             "[-] Failed to create "
             "EPT PT\n");
  DbgPrint(
      "[+] Successfully allocated "
      "EPT PT %p\n",
      pt);

  pd[0].read = true;
  pd[0].write = true;
  pd[0].execute = true;
  pd[0].pfn = TO_PFN(MmGetPhysicalAddress(pt).QuadPart);

  for (i = 0; i < initial_n_pages; i++) {
    page = ExAllocatePool(NonPagedPool, SIZE);
    GOTO_ERROR(!page,
               "[-] Failed to allocate "
               "EPT PTE %d page\n",
               i);
    DbgPrint(
        "[+] Successfully "
        "allocated EPT PTE %d page "
        "%p\n",
        i, page);

    pt[i].read = true;
    pt[i].write = true;
    pt[i].execute = true;
    pt[i].memory_type = 6;
    pt[i].pfn = TO_PFN(MmGetPhysicalAddress(page).QuadPart);
  }

  return true;

error:
  FreeEPTP();
  return false;
}

bool InitializeMemory(PMemory memory) {
  memory->address = ExAllocatePool(NonPagedPool, SIZE);
  GOTO_ERROR(!memory->address,
             "[-] Failed to allocate "
             "memory for region\n");

  memory->physical_address = MmGetPhysicalAddress(memory->address).QuadPart;
  GOTO_ERROR(!IsAlignedTo4KB(memory->physical_address),
             "[-] Region is not "
             "physically aligned to "
             "4KB\n");

  RtlSecureZeroMemory(memory->address, SIZE);
  return true;

error:
  FreeMemory(memory);
  return false;
}

bool InitializeRegion(PVMRegion region, UINT32 revision_identifier) {
  if (!InitializeMemory((PMemory)region)) {
    return false;
  }
  *(UINT32*)region->address = revision_identifier;
  return true;
}

PEPTP AllocateEPTP(void) {
  PEPTP eptp = (PEPTP)ExAllocatePool(NonPagedPool, sizeof(EPTP));
  GOTO_ERROR(!eptp,
             "[-] Failed to "
             "allocate EPTP\n");
  RtlSecureZeroMemory(eptp, sizeof(EPTP));
  return eptp;

error:
  return nullptr;
}

PEPTTableEntry AllocateEPTTable(void) {
  PEPTTableEntry table = (PEPTTableEntry)ExAllocatePool(
      NonPagedPool, sizeof(EPTTableEntry) * EPT_N_ENTRIES);
  GOTO_ERROR(!table,
             "[-] Failed to allocate EPT "
             "table\n");
  RtlSecureZeroMemory(table, sizeof(EPTTableEntry) * EPT_N_ENTRIES);
  return table;

error:
  return nullptr;
}

PVM AllocateVirtualMachines(void) {
  PVM virtual_machines =
      (PVM)ExAllocatePool(NonPagedPool, MAX_CPU_COUNT * sizeof(VM));
  GOTO_ERROR(!virtual_machines,
             "[-] Failed to allocate "
             "virtual machines\n");
  RtlSecureZeroMemory(virtual_machines, MAX_CPU_COUNT * sizeof(VM));
  return virtual_machines;

error:
  return nullptr;
}

void SetupCurrentVMCSGuestSelectorData(SelectorRegister selector_register,
                                       SegmentSelector selector) {
  SegmentDescriptor descriptor = GetSegmentDescriptor(selector);
  VMXSelectorAccessRights access_rights = {0};

  __vmx_vmwrite(VMCS_GUEST_ES_SELECTOR + (2 * selector_register),
                selector.value);

  __vmx_vmwrite(VMCS_GUEST_ES_BASE + (2 * selector_register),
                SEGMENT_DESCRIPTOR_BASE(descriptor));

  __vmx_vmwrite(VMCS_GUEST_ES_LIMIT + (2 * selector_register),
                SEGMENT_DESCRIPTOR_LIMIT(GetSegmentDescriptor(selector)));

  // Null descriptor is the first descriptor (index = 0) of the GDT (ti = 0)
  if (!selector.fields.index && !selector.fields.ti) {
    access_rights.fields.segment_unusable = 1;
  } else {
    access_rights.fields.segment_type = descriptor.fields.segment_type;
    access_rights.fields.s = descriptor.fields.s;
    access_rights.fields.dpl = descriptor.fields.dpl;
    access_rights.fields.p = descriptor.fields.p;
    access_rights.fields.l = descriptor.fields.l;
    access_rights.fields.db = descriptor.fields.db;
    access_rights.fields.g = descriptor.fields.g;
  }

  __vmx_vmwrite(VMCS_GUEST_ES_ACCESS_RIGHTS + (2 * selector_register),
                access_rights.value);
}

void SetupCurrentVMCSHostArea(void) {
  GDTR gdtr = {0};
  IDTR idtr = {0};

  GetGDTR(&gdtr);
  GetIDTR(&idtr);

  __vmx_vmwrite(VMCS_HOST_CR0, __readcr0());
  __vmx_vmwrite(VMCS_HOST_CR3, __readcr3());
  __vmx_vmwrite(VMCS_HOST_CR4, __readcr4());

  // 27.2.3: In the selector field for each of CS, SS, DS, ES, FS, GS, and TR,
  // the RPL (bits 1:0) and the TI flag (bit 2) must be 0.
  __vmx_vmwrite(VMCS_HOST_CS_SELECTOR, GetCS().value & ~7ui64);
  __vmx_vmwrite(VMCS_HOST_DS_SELECTOR, GetDS().value & ~7ui64);
  __vmx_vmwrite(VMCS_HOST_ES_SELECTOR, GetES().value & ~7ui64);
  __vmx_vmwrite(VMCS_HOST_FS_SELECTOR, GetFS().value & ~7ui64);
  __vmx_vmwrite(VMCS_HOST_GS_SELECTOR, GetGS().value & ~7ui64);
  __vmx_vmwrite(VMCS_HOST_SS_SELECTOR, GetSS().value & ~7ui64);
  __vmx_vmwrite(VMCS_HOST_TR_SELECTOR, GetTR().value & ~7ui64);

  __vmx_vmwrite(VMCS_HOST_FS_BASE, __readmsr(IA32_FS_BASE_MSR));
  __vmx_vmwrite(VMCS_HOST_GS_BASE, __readmsr(IA32_GS_BASE_MSR));
  __vmx_vmwrite(VMCS_HOST_TR_BASE,
                SEGMENT_DESCRIPTOR_BASE(GetSegmentDescriptor(GetTR())));
  __vmx_vmwrite(VMCS_HOST_GDTR_BASE, gdtr.base);
  __vmx_vmwrite(VMCS_HOST_IDTR_BASE, idtr.base);

  __vmx_vmwrite(VMCS_HOST_IA32_SYSENTER_CS, __readmsr(IA32_SYSENTER_CS_MSR));
  __vmx_vmwrite(VMCS_HOST_IA32_SYSENTER_CS, __readmsr(IA32_SYSENTER_CS_MSR));
  __vmx_vmwrite(VMCS_HOST_IA32_SYSENTER_ESP, __readmsr(IA32_SYSENTER_ESP_MSR));
  __vmx_vmwrite(VMCS_HOST_IA32_SYSENTER_EIP, __readmsr(IA32_SYSENTER_EIP_MSR));
}

void SetupCurrentVMCSGuestArea(void) {
  GDTR gdtr = {0};
  IDTR idtr = {0};

  GetGDTR(&gdtr);
  GetIDTR(&idtr);

  __vmx_vmwrite(VMCS_GUEST_CR0, __readcr0());
  __vmx_vmwrite(VMCS_GUEST_CR3, __readcr3());
  __vmx_vmwrite(VMCS_GUEST_CR4, __readcr4());

  __vmx_vmwrite(VMCS_GUEST_DR7, __readdr(7));
}

void SetupCurrentVMCS(void) {
  SetupCurrentVMCSHostArea();
  SetupCurrentVMCSGuestArea();

  __vmx_vmwrite(VMCS_LINK_POINTER, VMCS_INITIAL);

  __vmx_vmwrite(VMCS_GUEST_IA32_DEBUGCTL, __readmsr(IA32_DEBUGCTL_MSR));
}

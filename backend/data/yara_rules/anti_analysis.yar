rule Anti_Debug_Techniques {
    meta:
        description = "Detects anti-debugging techniques commonly used by malware"
        author = "SecAgent"
        date = "2026"
        category = "Anti-Analysis"
        severity = "Medium"

    strings:
        $is_debugger = "IsDebuggerPresent" ascii wide
        $check_remote = "CheckRemoteDebuggerPresent" ascii wide
        $nt_query = "NtQueryInformationProcess" ascii wide
        $output_debug = "OutputDebugString" ascii wide
        $set_unhandled = "SetUnhandledExceptionFilter" ascii wide
        $tls_callback = "TLS callback" ascii wide nocase
        $int3 = "int 3" ascii
        $int3_2 = "int3" ascii
        $debug_break = "DebugBreak" ascii wide
        $trap_flag = "pushfd" ascii

    condition:
        2 of them
}

rule Anti_Virtual_Machine {
    meta:
        description = "Detects VM detection and sandbox evasion techniques"
        author = "SecAgent"
        date = "2026"
        category = "Anti-Analysis"
        severity = "Medium"

    strings:
        $vmware = "VMware" ascii wide nocase
        $vbox = "VBox" ascii wide
        $virtualbox = "VirtualBox" ascii wide nocase
        $qemu = "QEMU" ascii wide nocase
        $sandboxie = "Sandboxie" ascii wide nocase
        $wine = "wine_get_version" ascii wide
        $cpuid = "cpuid" ascii wide nocase
        $rdtsc = "rdtsc" ascii
        $hypervisor = "hypervisor" ascii wide nocase
        $xen = "Xen" ascii wide

    condition:
        2 of them
}

rule Process_Injection {
    meta:
        description = "Detects process injection techniques"
        author = "SecAgent"
        date = "2026"
        category = "Defense Evasion"
        severity = "High"

    strings:
        $virtual_alloc_ex = "VirtualAllocEx" ascii wide
        $write_process = "WriteProcessMemory" ascii wide
        $create_remote = "CreateRemoteThread" ascii wide
        $nt_map = "NtMapViewOfSection" ascii wide
        $nt_unmap = "NtUnmapViewOfSection" ascii wide
        $set_thread = "SetThreadContext" ascii wide
        $resume_thread = "ResumeThread" ascii wide
        $queue_apc = "QueueUserAPC" ascii wide
        $create_process = "CreateProcess" ascii wide
        $set_windows_hook = "SetWindowsHookEx" ascii wide

    condition:
        3 of them
}

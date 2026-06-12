rule Keylogger_Indicators {
    meta:
        description = "Detects keylogging capabilities through Windows API imports and strings"
        author = "SecAgent"
        date = "2026"
        category = "Keylogger"
        severity = "High"

    strings:
        $set_hook = "SetWindowsHookEx" ascii wide
        $get_async = "GetAsyncKeyState" ascii wide
        $get_key = "GetKeyState" ascii wide
        $get_foreground = "GetForegroundWindow" ascii wide
        $get_keyboard = "GetKeyboardState" ascii wide
        $keylogger_str = "keylog" ascii wide nocase
        $keyboard_hook = "WH_KEYBOARD" ascii wide
        $keyboard_ll = "WH_KEYBOARD_LL" ascii wide
        $clipboard = "GetClipboardData" ascii wide
        $open_clipboard = "OpenClipboard" ascii wide

    condition:
        3 of them
}

rule Downloader_Trojan {
    meta:
        description = "Detects trojan downloader patterns (URL download + execution)"
        author = "SecAgent"
        date = "2026"
        category = "Trojan"
        severity = "High"

    strings:
        $url_download = "URLDownloadToFile" ascii wide
        $url_download_cache = "URLDownloadToCacheFile" ascii wide
        $winhttp = "WinHttpOpen" ascii wide
        $winhttp_req = "WinHttpOpenRequest" ascii wide
        $winhttp_send = "WinHttpSendRequest" ascii wide
        $wininet_open = "InternetOpenA" ascii wide
        $wininet_open_url = "InternetOpenUrlA" ascii wide
        $wininet_read = "InternetReadFile" ascii wide
        $http_send = "HttpSendRequest" ascii wide
        $ftp_get = "FtpGetFile" ascii wide

    condition:
        any of ($url_download, $url_download_cache, $winhttp_req, $wininet_open_url)
        and 2 of them
}

rule Backdoor_Remote_Access {
    meta:
        description = "Detects backdoor and remote access trojan (RAT) indicators"
        author = "SecAgent"
        date = "2026"
        category = "Backdoor"
        severity = "Critical"

    strings:
        $socket = "socket" ascii wide
        $connect = "connect" ascii wide
        $send = "send(" ascii wide
        $recv = "recv(" ascii wide
        $bind = "bind(" ascii wide
        $listen = "listen(" ascii wide
        $accept = "accept(" ascii wide
        $cmd_exec = "cmd.exe" ascii wide nocase
        $powershell = "powershell" ascii wide nocase
        $wscript = "wscript.shell" ascii wide nocase
        $startup = "Startup" ascii wide
        $task_scheduler = "Task Scheduler" ascii wide nocase

    condition:
        (any of ($socket, $connect, $send, $recv))
        and 3 of them
}

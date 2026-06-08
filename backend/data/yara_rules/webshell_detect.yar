rule PHP_Webshell_Backdoor {
    meta:
        description = "Detects common PHP webshell patterns"
        author = "SecAgent"
        date = "2024"
        category = "Webshell"
        severity = "High"

    strings:
        $eval = "eval(" ascii
        $assert = "assert(" ascii
        $system = "system(" ascii
        $shell_exec = "shell_exec(" ascii
        $exec = "exec(" ascii
        $passthru = "passthru(" ascii
        $popen = "popen(" ascii
        $proc_open = "proc_open(" ascii
        $base64_decode = "base64_decode(" ascii
        $str_rot13 = "str_rot13(" ascii
        $gzuncompress = "gzuncompress(" ascii
        $gzinflate = "gzinflate(" ascii

    condition:
        3 of them
}

rule ASP_Webshell {
    meta:
        description = "Detects ASP/ASP.NET webshell indicators"
        author = "SecAgent"
        date = "2024"
        category = "Webshell"
        severity = "High"

    strings:
        $createobject = "CreateObject" ascii
        $wscript = "WScript.Shell" ascii
        $shell_application = "Shell.Application" ascii
        $response_write = "Response.Write" ascii
        $adodb = "ADODB.Stream" ascii

    condition:
        2 of them
}

rule JSP_Webshell {
    meta:
        description = "Detects JSP webshell indicators"
        author = "SecAgent"
        date = "2024"
        category = "Webshell"
        severity = "High"

    strings:
        $runtime = "Runtime.getRuntime()" ascii
        $processbuilder = "ProcessBuilder" ascii
        $getruntime = "getRuntime()" ascii
        $exec_jsp = ".exec(" ascii
        $inputstream = "InputStream" ascii

    condition:
        2 of them
}

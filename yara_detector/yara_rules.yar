/* -----------------------------------------------------------------------------
   Unified YARA Rules for .py / .pyc / .exe (incl. PyInstaller & UPX)
   Author: Juan Herbst | Student ID: 13840146
   Purpose: Report-only string matches across Python source, bytecode, and PE
----------------------------------------------------------------------------- */

import "pe"

/* ========================= DETECTORS (PE context) ========================= */

private rule is_pe           { condition: pe.is_pe }
rule UPX_Packer
{
    meta: family="packer" scope="generic-pe" author="Juan Herbst"
    strings:
        $u1 = "UPX!" ascii
        $u2 = ".UPX0" ascii
        $u3 = ".UPX1" ascii
    condition:
        is_pe and any of ($u*)
}

rule PyInstaller_Fingerprint
{
    meta: family="pyinstaller" scope="windows-pe" author="Juan Herbst"
    strings:
        $b1 = "_MEIPASS" ascii wide
        $b2 = "pyiboot01_bootstrap" ascii wide
        $b3 = "pyimod01_os_path" ascii wide
        $b4 = "pyimod02_importers" ascii wide
        $b5 = "pyi_rth_" ascii wide
        $b6 = "pyinstaller" nocase ascii
    condition:
        is_pe and 2 of ($b*)
}

/* ========================= CONTENT RULES (all types) ====================== */
/* These match in text (.py), bytecode (.pyc), and binaries (.exe).
   Use ascii+wide so strings embedded in PE/UTF-16 also trigger.           */

rule Any_URLs : url
{
    meta: category="url" author="Juan Herbst" purpose="Detect HTTP/HTTPS URLs"
    strings:
        $url = /\bhttps?:\/\/[A-Za-z0-9\-._~:\/?#\[\]@!$&'()*+,;=%]+\b/ nocase
    condition:
        any of them
}

rule Any_IPv4s : ipv4
{
    meta: category="ipv4" author="Juan Herbst" purpose="Detect IPv4-like tokens"
    strings:
        // Portable (no lookarounds/boundaries)
         $ip = /[0-9]{3}\.[0-9]{3}\.[0-9]{3}\.[0-9]{3}/ ascii wide
    condition:
        any of them
}

rule Any_Email_Addresses : email
{
    meta: category="email" author="Juan Herbst" purpose="Detect email addresses"
    strings:
        $em = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/ ascii wide
    condition:
        any of them
}

rule Any_Bitcoin_Address_Relaxed : btc
{
    meta: category="cryptoaddr" author="Juan Herbst" purpose="Detect BTC-like addr (relaxed)"
    strings:
        $btc = /\b[13][A-Za-z0-9]{25,34}\b/ ascii wide
    condition:
        any of them
}

rule Any_Suspicious_Python_Calls : pycalls
{
    meta: category="pycalls" author="Juan Herbst" purpose="Detect risky Python calls"
    strings:
        $s1 = "eval(" ascii wide
        $s2 = "exec(" ascii wide
        $s3 = "__import__(" ascii wide
        $s4 = "compile(" ascii wide
        $s5 = "subprocess.Popen(" ascii wide
        $s6 = "subprocess.run(" ascii wide
        $s7 = "os.system(" ascii wide
    condition:
        any of them
}

rule Any_WinAPI_Strings : winapi
{
    meta: category="winapi" author="Juan Herbst" purpose="Detect WinAPI names"
    strings:
        $w1 = "OpenProcess(" ascii wide
        $w2 = "VirtualAllocEx(" ascii wide
        $w3 = "WriteProcessMemory(" ascii wide
        $w4 = "CreateRemoteThread(" ascii wide
    condition:
        any of them
}

rule Any_EICAR_Test_String : eicar
{
    meta: category="eicar" author="Juan Herbst" purpose="Detect EICAR test string"
    strings:
        $e = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*" ascii wide
    condition:
        any of them
}

rule Any_Ransom_Note_Phrases : ransom
{
    meta: category="ransom" author="Juan Herbst" purpose="Detect ransom-note phrases"
    strings:
        $r1 = "Your files have been encrypted!" nocase ascii wide
        $r2 = "Contact us at" nocase ascii wide
    condition:
        any of them
}

rule Any_Crypto_Usage_Strings : crypto
{
    meta: category="crypto" author="Juan Herbst" purpose="Detect AES/CBC usage cues"
    strings:
        $c1 = "algorithms.AES(" ascii wide
        $c2 = "modes.CBC(" ascii wide
    condition:
        any of them
}

rule Any_Decompiler_Banners : decompiler
{
    meta: category="decompiler" author="Juan Herbst" purpose="Detect decompiler banner lines"
    strings:
        $d1 = "# Source Generated with Decompyle++" ascii wide nocase
        $d2 = /#\s*File:\s*[^\r\n]*\.pyc\s*\(Python\s*[0-9.]+\)/ ascii wide
        $d3 = "# WARNING: Decompyle incomplete" ascii wide nocase
    condition:
        any of ($d*)
}

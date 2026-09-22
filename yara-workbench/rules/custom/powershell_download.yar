rule Suspicious_PS_DownloadCradle {
    meta:
        description = "Detects obfuscated or direct PowerShell download cradles"
        author = "Khutso"
        date = "2026-09-22"
        severity = "High"

    strings:
        $s1 = "System.Net.WebClient" nocase
        $s2 = "DownloadString" nocase
        $s3 = "DownloadFile" nocase

    condition:
        $s1 and ($s2 or $s3)
}

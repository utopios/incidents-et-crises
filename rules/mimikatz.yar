rule Mimikatz_Detection
{
    meta:
        description = "Detecte Mimikatz via strings caracteristiques"
        author = "Formateur"
        date = "2024-01-27"
        reference = "https://github.com/gentilkiwi/mimikatz"
        severity = "high"

    strings:
        $str1 = "gentilkiwi" nocase
        $str2 = "sekurlsa::logonpasswords" nocase
        $str3 = "mimikatz" nocase
        $str4 = "kerberos::golden" nocase
        $str5 = "lsadump::sam" nocase

    condition:
        2 of them
}

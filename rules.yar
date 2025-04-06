import "pe"

rule MyCustomMalware
{
    meta:
        description = "Detects my custom-built malware"
        author = "Your Name"
        date = "2023-10-01"
    strings:
        // Replace with unique strings from your malware
        $str1 = "UniqueStringFromMalware" ascii wide
        $str2 = "AnotherUniqueString" ascii wide
        // Unique byte sequence (hexadecimal)
        $bytes = { E8 ?? ?? ?? ?? 5D C3 }  // Example byte pattern
    condition:
        uint16(0) == 0x5A4D and          // MZ header check
        filesize < 5MB and               // Optional: file size limit
        any of ($str*) or                // Matches any of the unique strings
        $bytes                           // Matches the unique byte sequence
}

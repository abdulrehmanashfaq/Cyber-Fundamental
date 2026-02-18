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



























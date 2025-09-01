# Objective

Identify impossible travel and unfamiliar sign-in activity in Splunk. Create transformation queries using Splunk to help identify anomalous logins.
Impossible travel & unfamiliar sign-ins are two use cases that are quite popular when it comes to identity-related alerts. The purpose of these use cases is to quickly identify suspicious logins by users from where they do not typically log in from.

Note: This data was generated using 3rd party VPN providers. In real-world environments, identifying the usage of 3rd party VPNs can be an indicator of suspicious activity. In this specific lab, we are more focused on the location rather than the VPN. In other words, pretend there was no VPN being used and focus on the location.

Context: This company is located in Vancouver, BC, Canada.
Ressource: mydfir-identity.tgz 

SHA256: 1c82890603554b2329394c5df17ff666718480eb8a8102132e0541972c9de892 Index: cloud
Date: 2024-02-11 00:00 to 2024-02-12 00:00 Total events: 242

## Lab Takeaways

In this lab, I learned that impossible travel events can sometimes be triggered by legitimate activity, such as when a user is connected through a VPN. However, I also noted that many organizations do not allow the use of 3rd-party VPNs, instead requiring employees to connect through the company’s official VPN. This makes it important for me to understand which applications are not authorized in the environment I’m analyzing.

If VPNs are not authorized, one of the first things I should do is check whether the IP address involved belongs to a 3rd-party VPN. A site like ipinfo.io is helpful for making that determination.

When reviewing Microsoft 365 sign-in events, I also need to pay close attention to the Operations field, since it reveals the specific actions taken on a mailbox — a critical detail when investigating potentially suspicious activity (cf https://learn.microsoft.com/en-us/purview/audit-mailboxes).


## Recap of Findings

-Successful login activity seen for JChan from Singapore IP: 188.214.125.138

-An email forwarding rule was set up for JChan, directing that emails received from schan be forwarded to stoicellis@imcourageous[.]com. Additionally, these emails are moved to the deleted items folder and marked as read.

-Viewed two emails: RE: First Invoice of the month & URGENT: Client Bank Account

-Sent one email: URGENT: Client Bank Account with a PDF attached called NEW-BANK-ACCOUNT.pdf
Email was deleted "Re: First Invoice of the month!" from drafts under JChan's account.

# Investigation:

1) What account was compromised?

Answer: Account compromised: JChan@7pd6vr[.]onmicrosoft[.]com

2) According to OSINT, where did this user login from?

Answer: Country: Singapore

3) What date & time did this login occur (UTC)?

Answer: Date & Time: 2024-01-11 20:46:39 UTC

4) What activities were done from this IP?

Answer: Activities:

-Logged into the email account: JChan

-An email forwarding rule was set up for JChan, directing that emails received from schan be forwarded to stoicellis@imcourageous[.]com. Additionally, these emails are moved to the deleted items folder and marked as read.

-Viewed two emails: RE: First Invoice of the month & URGENT: Client Bank Account

-Sent one email: URGENT: Client Bank Account with a PDF attached called NEW-BANK-ACCOUNT.pdf

Did any other account login from this IP?

Answer: No other accounts logged in from this IP.

## Lab Step-By-Step

### Step 1: Reviewing the First Event

I started by reviewing the first event from the top to identify which field names could be useful for a transformation command.  
The following fields stood out as potentially useful:

- **ClientIPAddress**  
- **Nested Folders**  
- **MailboxOwnerUPN**  
- **Operation** (contains the action performed)  
- **UserId**  
- **Workload**  

<img width="664" height="511" alt="1" src="https://github.com/user-attachments/assets/c90a04f7-b31e-4445-b47c-038ac2b4c983" />

### Step 2: Creating a Transformation Command  

Next, I created a transformation command using the `table` function to focus on key fields from the events.  
I chose to display the following fields: **ClientIPAddress**, **Operation**, **UserId**, and **Workload**.  

**Query Used:**  index=cloud | table ClientIPAddress, Operation, UserId, Workload

<img width="751" height="119" alt="2" src="https://github.com/user-attachments/assets/3f2a126f-46d3-400d-9eef-58ef2a474809" />

### Step 3: Understanding the Table Command  

**Note:** The `table` command was used so I could see everything, even if some fields did not contain data.  
If I had used the `stats` command instead, it would only display fields that have data, and I might have missed important information.  

When reviewing the **Workload** column, I noticed that it contained both **Exchange** and **AzureActiveDirectory**.  
In a larger environment, I would also expect to see other workloads such as **Microsoft Teams**, **SharePoint**, **OneDrive**, and more.  


<img width="1373" height="664" alt="3" src="https://github.com/user-attachments/assets/faa7bf43-cf93-485c-908e-06d219e37cf8" />

### Step 4: Filtering for Login Events  

For instances of impossible travel or unfamiliar sign-ins, I examined logs generated by login events.  
I focused on the **Operation** field, which contained an activity labeled **UserLoggedIn**.  
I used this operation as a filter to narrow down my search.  

**Query Used:**  index=cloud Operation=UserLoggedIn | table ClientIPAddress, Operation, UserId, Workload

<img width="1290" height="624" alt="4" src="https://github.com/user-attachments/assets/ee6ed8e4-b53e-49f7-a08b-20c65b87f0cd" />

### Step 5: Narrowing Down Results  

This search reduced my dataset from **242 events to 23 events**.  
I noticed that the **ClientIPAddress** field was blank, and the **Workload** was consistently **AzureActiveDirectory**.  

This indicated that the **ClientIPAddress** field does not exist under the **AzureActiveDirectory** workload.  
If it did, I would expect to see IP addresses populated here.  

To investigate further, I navigated to the **Events tab** and switched to **Verbose Mode**.  
The goal was to identify which field name AzureActiveDirectory uses for IP addresses.  

<img width="801" height="435" alt="5" src="https://github.com/user-attachments/assets/08bb0b49-fdb2-4bc5-92da-db21fa9c0916" />

### Step 6: Identifying Correct IP Fields  

When I looked at the first event from the top, I found two fields that could be useful:  
- **ActorIpAddress**  
- **ClientIP**  

To ensure full coverage, I decided to use both fields in case there were differences.  
This time, I switched from the `table` command to the `stats` command in order to aggregate and count the data.  

**Query Used:**  index=cloud Operation=UserLoggedIn
                | stats count by ActorIpAddress, ClientIP, Operation, UserId, Workload


<img width="791" height="270" alt="6" src="https://github.com/user-attachments/assets/7b3e144a-39c6-4dc0-ba63-b0c40ca60a06" />

We now have a total of 4 statistic events. There is one “Not Available” UserId. A quick google search reveals that these will typically be generated due to a system account, and system accounts will have a field value of 4 under the field name: UserType. As we are not interested in system accounts, we will filter this out by excluding events where the UserType = 4.

<img width="619" height="452" alt="7" src="https://github.com/user-attachments/assets/f9570fc4-ea3c-4637-8a1f-f4a7b5169501" />

**Query Used:**  index=cloud Operation=UserLoggedIn UserType!=4 | stats count by ActorIpAddress,ClientIP, Operation, UserId, Workload

<img width="796" height="249" alt="8" src="https://github.com/user-attachments/assets/faadfb7c-76a0-42d1-869d-34a1e7e4cf0d" />

### Step 7: Reviewing Statistic Events  

After running the query, I now have a total of **3 statistic events**.  

Looking at both the **IP addresses** and **UserId** fields, I observed:  
- **2 users:** `jchan` and `schan`  
- The first two IPs both begin with `181.214.153`  

To investigate further, I ran a quick **OSINT check** on these IPs using [ipinfo.io](https://ipinfo.io).  
This helped me determine where these IPs are located and whether the locations align with the users’ expected sign-in activity.  

<img width="464" height="380" alt="9" src="https://github.com/user-attachments/assets/8e136430-c6e6-46d3-b28b-ddf2c3d3b02b" />

The first one for jchan is located in Vancouver, BC, which is expected since the company is located there - Next, check the IP for schan.

<img width="481" height="368" alt="10" src="https://github.com/user-attachments/assets/00080f9a-612f-478b-9f1f-0c9377a2264d" />

This IP is located in Vancouver, BC as well indicating that these two logins from JChan & SChan are likely expected. However, there was another IP that began with 188 where JChan's account was used to login, perform a quick check on that IP.

<img width="531" height="420" alt="11" src="https://github.com/user-attachments/assets/dffab457-f375-418a-b5b9-7eb594b55abb" />

The location is set to Singapore, which is quite suspicious, especially if this user has never been to Singapore.

### Step 8: Filtering Out schan & Adding Time Field  

> **Note:** This type of activity can sometimes be legitimate if the user is known to use a **3rd party VPN provider**. However, if the organization does not authorize 3rd party VPNs, then this login activity becomes a potential **red flag**.  

Since the login from **Singapore** was identified as an anomaly, I filtered out `schan` to focus only on events related to `jchan`.  
Additionally, I added the **`_time` field** to the transformation command so I could review when the login events occurred.  

#### Query:  index=cloud Operation=UserLoggedIn UserType!=4 UserId!=schan@7pd6vr.onmicrosoft.com
| stats count by _time,ActorIpAddress,ClientIP, Operation, UserId, Workload
| sort +_time


This query helps isolate **jchan’s login activity** over time, along with IP addresses and workloads involved. 

<img width="800" height="457" alt="12" src="https://github.com/user-attachments/assets/7df72e06-489d-4df1-b4fe-38e60ece035f" />

### Step 9: Identifying Impossible Travel & Unfamiliar Sign-In  

From the statistics, there are now a total of **8 events**.  

- The **third event** involves the IP starting with **188**, which is geolocated in **Singapore**.  
  - Login Time: **2024-02-11 20:46:39 UTC**  
- The **second event** involves the IP starting with **181**, which is geolocated in **Vancouver**.  
  - Login Time: **2024-02-11 20:33:37 UTC**  

These two logins occurred only **~13 minutes apart**. Since it is impossible to physically travel from Vancouver, BC to Singapore within 13 minutes, this clearly qualifies as an **Impossible Travel activity**.  

Additionally:  
- The successful login from **Singapore** represents an **Unfamiliar Sign-In**, as user **jchan** had **no prior logins** from Singapore in the available dataset.  
- Because we only have access to **a single day of logs**, we cannot perform trending analysis over 30–90 days. In a real SOC environment, you should always check for longer-term login activity to confirm anomalies.  

At this stage, many SOC analysts would stop and submit a report, but that would be incomplete.  
Instead, we should ask **bigger-picture investigative questions**, such as:  
- **What did this IP do after logging in?**  
- **Did this IP attempt to access other accounts?**  


### Step 10: Investigating the Singapore IP  

To expand the investigation, I modified the query to focus on the **Singapore IP address** (the one beginning with `188`).  
This allows us to determine if other users or operations are associated with the same suspicious IP.  

#### Query:  index=cloud ActorIpAddress=188.*
| stats count by _time,ActorIpAddress,ClientIP, Operation, UserId, Workload
| sort +_time


This query provides visibility into all users and actions tied to the suspicious IP — helping to uncover whether the attacker attempted to compromise additional accounts.  


<img width="1130" height="567" alt="13" src="https://github.com/user-attachments/assets/5b7c9978-347c-4813-a16b-b857bb5f9500" />

There are 18 statistical events linked to this IP, and the sole user associated with it is JChan. Beyond logins, we begin to see the bigger picture as this IP was also involved in creating a new inbox rule, accessing, sending, and deleting emails. This activity helps us understand the extent of actions taken from this IP address. Always scope and ask questions.

As there was a new inbox rule created by this IP, modify the query and add the operation "New-InboxRule" to review inbox rule creations.

#### Query: index=cloud 188.214.125.138 Operation=New-InboxRule | stats count by _time, Operation, UserId, Workload | sort +_time

<img width="834" height="254" alt="14" src="https://github.com/user-attachments/assets/598d0072-66bf-4e67-8c73-a347063fb890" />

There is 1 event. Click on the Events tab and expand all the parameters. This inbox rule was created by the IP located in Singapore where it does the following:

-Forward emails to the email address: stoicellis@imcourageous[.]com
-From the address: schan@7pd6vr.onmicrosoft.com
-Move the email received to the deleted items folder
-Mark the email as read

<img width="831" height="616" alt="15" src="https://github.com/user-attachments/assets/65cbbdf7-7e9b-455b-a4f3-d1ee0c8804be" />

To summarize, emails sent to the email address schan@7pd6vr.onmicrosoft.com will be automatically marked as read, moved to the deleted items folder, and forwarded to stoicellis@incourageous[.]com. This is a common technique used by attackers who gain access to a mailbox and then set up a forwarding rule to redirect emails to their own address, enabling them to gather sensitive information.

### Step 11: Scoping for Attacker Domain  

As a quick scoping activity, I searched for the attacker domain across the environment to check for related activity.  
In a **real-world SOC workflow**, this search would cover **30–90 days** of historical data. However, in this lab we are constrained to a **single day of data**, so the scope is limited.  

#### Query: spl index=cloud imcourageous.com

This query helps determine whether the attacker’s domain appears elsewhere in the logs, which could indicate broader malicious activity such as phishing links, credential harvesting attempts, or connections from compromised accounts.  

<img width="834" height="165" alt="16" src="https://github.com/user-attachments/assets/ffcd54dc-1cb0-406b-90ff-8e53fd238c7d" />

### Step 12: Findings – Attacker Domain Activity  

The search for `imcourageous[.]com` returned a **total of 2 events**.  
This type of scoping check should always be done when encountering similar suspicious activity, as it can reveal persistence mechanisms or additional attacker actions.  

#### Key Observation:  
Looking at the **first event** (from the top) where the `Operation` is `Set-Mailbox`, I expanded its parameters and found:  

- **ForwardingSmtpAddress** → set to the attacker’s email address  
- **Affected Account** → `jchan`  

#### Analysis:  
This means the attacker configured the mailbox to automatically **forward emails** from JChan’s account to their own email address, effectively creating a **backdoor for data exfiltration** and maintaining persistence even if the initial access method is blocked.  

✅ **Critical Takeaway:** Anytime you see mailbox changes such as forwarding rules being set to external domains, treat it as **high-risk compromise activity** that requires immediate remediation.  


<img width="846" height="758" alt="17" src="https://github.com/user-attachments/assets/0692b4c3-aec7-435f-91b5-3897566baa02" />

The other event was the one we had analyzed previously.

<img width="831" height="240" alt="18" src="https://github.com/user-attachments/assets/add57b33-ce0b-4e7f-9a03-4a11c0ce5a18" />

### Step 13: Filtering for Singapore IP – Excluding Known Operations  

We now re-ran the query, focusing **only on the Singapore IP** (`188.214.125.138`).  
The goal is to filter out the previously analyzed operations (`New-InboxRule`, `Set-Mailbox`, and `UserLoggedIn`) so we can focus on **other activities** tied to this attacker IP.  

#### Query:
```spl
index=cloud 188.214.125.138 Operation!=New-InboxRule Operation!=Set-Mailbox Operation!=UserLoggedIn 
| stats count by _time, Operation, UserId, Workload 
| sort +_time 
```

<img width="714" height="208" alt="19" src="https://github.com/user-attachments/assets/f971f60e-c93e-4d35-bca9-99446cb4577c" />

<img width="829" height="137" alt="20" src="https://github.com/user-attachments/assets/51e08e60-b2ae-4dd3-986c-39678d9ee87a" />

There are 4 unique operations left: MailItemsAccessed, Create, MoveToDeletedItems & Send.

<img width="830" height="228" alt="21" src="https://github.com/user-attachments/assets/7bfefd12-ca17-42c2-b391-2b87e202dbe5" />

Filter for MailItemsAccessed to see what the IP accessed.

#### Query:
```spl
index=cloud 188.214.125.138 Operation!=New-InboxRule Operation!=Set-Mailbox Operation!=UserLoggedIn Operation=MailItemsAccessed | stats count by _time, Operation, UserId, Workload | sort +_time
```

<img width="829" height="238" alt="22" src="https://github.com/user-attachments/assets/f42263da-6540-45c3-aae2-c1c9d4f6f701" />

### Step 14: Reviewing Additional Events

There are a total of **6 events**.  

Looking at the first event from the top, we can identify several interesting fields that provide more context about the activity:  

- **ClientInfoString** → This field shows the **user agent** that was used during the login session.  
- **InternetMessageId** → Found under the *Folders* section. This can be extremely valuable because it allows us to **correlate exactly what emails were accessed** (if message logs are available).  
- **SizeInBytes** → Shows the size of the accessed message.  
- **Path** → Displays the folder path where the activity occurred (e.g., Inbox, Sent Items).  

These fields provide **deeper forensic insight**, especially when analyzing mailbox operations linked to suspicious IP addresses.

<img width="674" height="448" alt="23" src="https://github.com/user-attachments/assets/9c74ba5e-a191-4ba6-a417-92eb26b6f328" />

Expanding OperationProperties, there is MailAccessType of Bind.

<img width="519" height="559" alt="24" src="https://github.com/user-attachments/assets/432585d4-c82a-4e4f-80be-159cc3087b84" />

### Step: Mail Access Operations (Sync vs Bind)

**Note:**  
As per Microsoft documentation, there are two operation values for **MailAccessType**:  

- **Sync** → Recorded when a mailbox is accessed by the desktop version of Outlook (Windows or Mac). During sync, a large set of mail items is typically downloaded from the cloud to a local machine.  
- **Bind** → Recorded when an individual email message is accessed. For bind access, the `InternetMessageId` of each message is stored in the audit record.  

In this scenario, we are observing **bind operations**, which means we can trace specific email messages that were accessed.  

📌 Under the **Interesting Fields** section in Splunk, you’ll find:  
`Folders{}.FolderItems{}.InternetMessageId`  
This field can be used to identify the exact emails accessed (when available).  

<img width="823" height="261" alt="25" src="https://github.com/user-attachments/assets/eaa13c89-86f0-4cbd-8590-322d44ca592b" />

---

### Query to Create a transformation command using "stats count by" and add the InternetMessageId field name. 

```spl
index=cloud 188.214.125.138 Operation!=New-InboxRule Operation!=Set-Mailbox Operation!=UserLoggedIn Operation=MailItemsAccessed 
| stats count by Folders{}.FolderItems{}.InternetMessageId
```

<img width="839" height="309" alt="26" src="https://github.com/user-attachments/assets/6b02675c-c7da-476d-b160-f324de148572" />

**Observation:**  
A total of **4 individual emails** were accessed during this suspicious session.  

- If emails were **not** being ingested into a SIEM, you could provide these `InternetMessageId`s to the client.  
- The client (or Exchange admin) could then run a **forensic audit search** against these IDs to determine the exact emails accessed.  

Since in this lab scenario, **emails are being ingested into the SIEM**, we can take the `InternetMessageId` values and **normalize them** by:  

- Stripping everything **after the `@` symbol**  
- Keeping only the **unique message ID prefix**  

This allows correlation against ingested email logs to identify which emails were accessed.  

<img width="824" height="220" alt="27" src="https://github.com/user-attachments/assets/60b1dfc1-9621-4999-9e0f-65cc8783f589" />

As an example, search for the 3rd ID to see if we can find what email it is tied to. I used a transforming stats command to better visualize the data.


<img width="659" height="169" alt="28" src="https://github.com/user-attachments/assets/aa55d67b-15a6-4f98-8dc8-e201230a549a" />

#### Query: index=cloud 188.214.125.138 PH7PR19MB8188D8A00DEAFD4DA081406F91492 | stats count by _time,Operation,UserId,Workload |sort +_time

<img width="827" height="284" alt="29" src="https://github.com/user-attachments/assets/bc99070e-29cb-40a4-a91a-a80ccdbff46b" />

In addition to MailItemsAccessed, we see there is a Create operation and MoveToDeletedItems associated with this ID. We are going to look at the events and scroll down to the last event.

<img width="831" height="605" alt="30" src="https://github.com/user-attachments/assets/d961d426-44d6-4e08-a8c8-602e6cbb5274" />

The last event is the Create operation. Expand "Item" and look at the Subject field. We see this IP had interacted with the email containing the Subject: RE: First Invoice of the month! Then i will remove everything and filter for the operation Create to see what was created by this IP.

<img width="829" height="165" alt="31" src="https://github.com/user-attachments/assets/0b31f03d-4f79-4c1f-af0d-417fe4b106a7" />

We have a total of 4 events. Looking at the available field names on the left, there is a field called Item.Subject with 2 values meaning that out of the 4 events, 2 contain the field name: Item.Subject. Clicking on this, we can see that 2 emails with the subjects “URGENT: Client Bank Account” and “RE: First Invoice of the month!” were involved with this IP.


<img width="826" height="293" alt="32" src="https://github.com/user-attachments/assets/f01fa2c6-b0a1-4d64-92ff-e87e15660f82" />

Note: Based on Microsoft’s documentation, the Create operation is where an item was created in the calendar, contacts, draft, notes or tasks in the user’s mailbox.

Expand the Item parameter of the first event from the top. We can see there is an email with the Subject: URGENT: Client Bank Account and if you expand the Parent Folder parameter, the path of this email is located under Drafts.

<img width="769" height="332" alt="33" src="https://github.com/user-attachments/assets/c875e4dd-adfa-4858-854b-c281a0c1e07b" />

Note: This does not necessarily mean the attacker created these emails from scratch, but it can indicate that the attacker likely saw the contents within these two emails.

Next, we will take a look at the other operation MoveToDeletedItems.

Query: index=cloud 188.214.125.138 Operation=MoveToDeletedItems


<img width="832" height="150" alt="34" src="https://github.com/user-attachments/assets/f9e08c9f-5677-4bd0-9aa3-a82f8f80b315" />

We have a total of 10 events. Similar to Create, there is a field name called AffectedItems.Subject in the available field names on the left side. Clicking on it, we see the First invoice of the month!.

<img width="843" height="253" alt="35" src="https://github.com/user-attachments/assets/f98624c3-bc8d-4ad0-b211-2999ccc0545d" />

There is also a field called AffectedItems.ParentoFolder.Path, and clicking on that shows the parent folder path of \Drafts. This means that the attacker had deleted the email from drafts.

<img width="833" height="261" alt="36" src="https://github.com/user-attachments/assets/4d138372-15ec-4f4c-8f3a-49db0e2a84a6" />

Lastly, let's filter for the Operation Send.

Query: index=cloud 188.214.125.138 Operation=send

<img width="827" height="160" alt="37" src="https://github.com/user-attachments/assets/891fc29b-28f7-427c-b233-3989a959ae2e" />

Note: Recall that for Splunk, the field VALUES are NOT case sensitive whereas field NAMES are. I am showing you an example here, the field VALUE is "send" and this will work.

There is 1 event where the attacker had sent an email with the Subject “URGENT: Client Bank Account” on 2024-02-11 20:58:54 with an attachment called “NEW-BANK-ACCOUNT.pdf”.


<img width="834" height="352" alt="38" src="https://github.com/user-attachments/assets/e55971bf-b063-4831-811a-ee3b158c1ff5" />

Then i will search for the Subject to get some additional context as to who might have received this email, we will make sure to remove the IP as we are only interested in the Subject.

Query: index=cloud "URGENT: Client Bank Account"

<img width="831" height="169" alt="39" src="https://github.com/user-attachments/assets/e012c161-e4de-47bb-b842-4c73188915f7" />

There are a total of 9 events. Looking at the event on 2024-02-11 21:01:08 right after the email was sent by JChan on 2024-02-11 20:58:54, the data shows the account schan logged a Create operation for the same email where the Subject is Re: URGENT: Client Bank Account, indicating that the user schan had likely replied to it.

<img width="826" height="516" alt="40" src="https://github.com/user-attachments/assets/32572a15-dec4-47de-9c07-dcc57205b458" />

Looking at the UserId field, aside from JChan, it appears only schan had interacted with this email.

<img width="825" height="253" alt="41" src="https://github.com/user-attachments/assets/536ae875-aaa9-4a61-80df-d7b407ca1aee" />


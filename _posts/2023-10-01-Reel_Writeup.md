# Reel Writeup
![Reel HTB Icon](https://www.hackthebox.com/storage/avatars/55d0de0cfa8b70e916abbb3f513dc1a7.png)
---

## Summary
Reel was a pretty tricky box, and is over 6 years old, releasing in 2018, as the name implies, it involved a phishing attack, which is pretty uncommon in CTFs! 
After obtaining command execution via phishing (using a malicious macro) we find an XML credential file allowing us to pivot to a new user. 
Using bloodhound (after some intense proxying) we can eventually find out this user can abuse ACLs to reset the password of another user. This new user has GenericWrite over a group with full access to the filesystem, meaning we can add our controlled users to this group.




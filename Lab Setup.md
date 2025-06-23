#### Victim Machine
Kali Linux

---
#### Step 1: **Install Samba on Kali Linux**

Open a terminal in Kali and run:
```
sudo apt update sudo apt install samba -y
```

---

#### Step 2: **Create a Shared Directory**

```
sudo mkdir -p /srv/smbshare sudo chown nobody:nogroup /srv/smbshare sudo chmod 0777 /srv/smbshare
```

You can add some test files inside:
```
echo "testuser: testpass123" | sudo tee /srv/smbshare/creds.txt
```

---

#### Step 3: **Configure the Samba Share**

```
sudo nano /etc/samba/smb.conf
```

Scroll to the bottom and add this:

```
[smbshare]
path = /srv/smbshare
browseable = yes
read only = no
guest ok = yes
force user = nobody
```

This creates an open share with guest access (no authentication), perfect for your anonymous access test.

---

#### Step 4: **Restart Samba Service**

```
sudo systemctl restart smbd
```

Check status:
```
sudo systemctl status smbd
```

---

#### Step 5: **Allow SMB Through Firewall (if active)**

If ufw is active:

```
sudo ufw allow Samba
```

Otherwise, ensure ports **139** and **445** are open from the VM settings or NAT/bridge settings in VMware.

---

#### Step 6: **Find Kali's IP Address**

On Kali:
```
ip a | grep inet
```

Look for something like `192.168.1.x`. That’s the IP you’ll scan from Windows.

---

#### Step 7: **From Windows, Run Your Script**

Run your Python script (as admin if needed), select:
```
- Option `2` (Enter a Scope)
    
- Input a scope like: `192.168.1.0/24` or just the Kali IP `/32`
```

---
----
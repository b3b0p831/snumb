# snumb


![image](/imgs/snumb.png)

(Please use responsibly and with permission only. I'm not responsible for your actions.)

Tool for finding juicy secrets in SMB Shares.

snumb aids red teamers and system admins in enumerating smb shares.


# Usage
```sh
user@compooter ~> git clone https://github.com/b3b0p831/snumb.git
user@compooter ~> cd snumb/
user@compooter ~/snumb> python3 -m venv venv # Create virtual env
user@compooter ~/snumb> . ./venv/bin/activate(.fish) #use .fish if needed else leave out
(venv) user@compooter ~/snumb> pip3 install -r requirements.txt
...
user@compooter ~/snumb> python3 snumb.py -h
```
![image](/imgs/help.png)


Given an smb server, snumb will list shares and available permissions.

```sh
(venv) user@compooter ~/snumb> python3 snumb.py 127.0.0.1:5050
```

![image](/imgs/ex0.png)


Providing a share name with -s will recursivly list files, MIME type, and possible secrets.

```
(venv) user@compooter ~/snumb> python3 snumb.py 127.0.0.1:5050 -s "SHARE"
```

![image](/imgs/ex1.png)



Here are the file types thats snumb currently supports:

- PDF, XML
- ASCII/Unicode Text 
- ZIP (File listing only)

Comming Soon: Microsoft Office Docs (docx, xlsx, ppt), PCAP



Here are the things that snumb performs on each file that is within the max file size. By default every file that is 50MB and below will be analyzed for secrets (can be specified with -f filesize option)

- Regex Matching
- Keyword detection
- MIME type analysis 

Coming Soon: ML Based detection using pandas/scikit-learn





Ascii Art - https://patorjk.com/software/taag/#p=testall&h=0&v=0&f=Slant&t=SNUMB

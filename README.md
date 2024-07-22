# snumb
Tool for finding juicy secrets in SMB Shares

snumb is a cli-based tool built using python3 and impacket.

Here are some things that snumb looks outfor:

Here are the file types thats snumb supports:

- Microsoft Office Docs (docx, xlsx, ppt)
- PDF
- Text based files (.txt, .html, .py, etc)

## 1.) Connect to share, log into smb share, list shares and perms 
- [x] Connect
- [x] Login
- [x] List Shares
- [x] List Share perms

## 2.) Recurse through fs and get files names. Open file based on type (txt, pdfs, cvs, etc)
- [x] Recurse through fs, filenames
- [x] Get file type

## 3.) Parse file contents, attempt to detect credentials. Both regex and ML approach?
- [ ] Parse file contents aka regex credentials and secrets detection
- [ ] Perform context analysis using AI?

## 4.) Display results, format text


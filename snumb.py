#!/usr/bin/python3

import argparse, io
from impacket.smbconnection import SMBConnection, SessionError

def list_files_in_directory(conn : SMBConnection, share_name, path, fs):
    try:
        # List contents of the current directory
        files = conn.listPath(share_name, f"{path}/*")
        for file in files:
            filename = file.get_longname()
            if filename not in [".", ".."]:  # Skip special directories
                new_path = f"{path}/{filename}"
                
                # If it's a directory, recurse into it
                if file.is_directory():
                    list_files_in_directory(conn, share_name, new_path, fs)
                else:
                    fs.append(new_path)
                    contents = read_file_contents(conn, share_name, new_path)
                    # Do some things with file contents
                    

    except Exception as e:
        print(f"Error accessing {path}: {e}")

def read_file_contents(conn, share, path):
    file_obj = io.BytesIO()
    conn.getFile(share, path, file_obj.write)
    file_obj.seek(0)
    return file_obj.read()


def parse_file_contents(file_contents):
    pass

def is_readable(smb_con : SMBConnection, shareName : str):
    try:
        smb_con.listPath(shareName, "/")
        return True
    except SessionError as e:
        return False
    
def is_writable(smb_con : SMBConnection, shareName : str):
    try:
        test_filename = "test.txt"
        smb_con.putFile(shareName, test_filename, io.BytesIO(b'Test').read)
        smb_con.deleteFile(shareName, test_filename)
        return True
    except SessionError as e:
        return False
    
def enumerate_share(smb_con : SMBConnection, shareName : str):
    pass

def printShareNames(smb_con : SMBConnection):
    print("Share           Permissions           Comment")
    for x in smb_con.listShares():
        perms = ""
        shareName = x['shi1_netname'][:-1]
        remarks = x['shi1_remark'][:-1]
       
        if is_readable(smb_con, shareName):
            perms += "R"

        if is_writable(smb_con, shareName):
            perms += "W"

        

        
        
        print(f"{shareName}               {perms}              {remarks}")

def main():

    parser = argparse.ArgumentParser(prog="snumb", usage="./snumb.py -i <IP> -p <PORT>")
    parser.add_argument("-i", "--ip", dest="addr", required=True, default=None, help="IP:PORT")
    parser.add_argument("-u", "--user", dest="username", default="", help="username")
    parser.add_argument("-p", "--password", dest="password", default="", help="password")
    parser.add_argument("-o", "--output", dest="outfile", required=False, default=None, help="Results will be written to this file.")
    parser.add_argument("-d", "--domain", dest="domain", required=False, default="", help="domain name for Kerberos login.")
    parser.add_argument("-s", "--share", dest="shareName", required=False, default="", help="Share name to enumerate.")
    parser.add_argument("-a", action="store_true", help="anonymous login", default=False)


    args = parser.parse_args()

    if args.a:
         args.username = "anonymous"
         args.password = "anonymous"

    if(args.addr):
        addr_port = args.addr.split(":")

        smb_con : SMBConnection = None
        try:
            smb_con = SMBConnection(remoteName="SMBServer", remoteHost=addr_port[0], sess_port=int(addr_port[1]))
            print(f"Connected to SMB Server {args.addr}!")
            smb_con.login(user=args.username, password=args.password, domain=args.domain)
        except SessionError:
            print("Login Failed")
            return
        except:
            print(f"Connection to {args.addr} could not be established.")
            return

        if smb_con.isGuestSession():
            print(f"[+] Anonymous Login OK!")
        else:
            print(f"[+] Login OK!")
        
        if not args.shareName:
            print("No share provided, listing all shares")
            printShareNames(smb_con)
            exit(0)

        if is_readable(smb_con=smb_con, shareName=args.shareName):
            print(f'[+] "{args.shareName}" is readable!')
        else:
            print(f'[+] "\\\\{args.addr}\\{args.shareName}" is not readable or doesn\'t exist!')
            exit(-1)

        if is_writable(smb_con=smb_con, shareName=args.shareName):
            print(f'[+] "{args.shareName}" is writable!')



        print(f"[+] Enumerating \\\\{args.addr}\{args.shareName} for pdfs, text files, scripts and any other usefull stuff...")
            
        files = []
        enumerate_share(smb_con=smb_con, shareName=args.shareName)
        list_files_in_directory(conn=smb_con, share_name=args.shareName, path="", fs=files)
        print(files)

        
        smb_con.close()

main()



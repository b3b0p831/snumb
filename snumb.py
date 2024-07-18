#!/usr/bin/python3

import argparse, io, tabulate, magic
from impacket.smbconnection import SMBConnection, SessionError
from colorama import Fore, Back, Style


def list_share_path(conn : SMBConnection, share_name : str, path : str, fs : str, file_size : int):
    try:
        # List contents of the current directory
        files = conn.listPath(share_name, f"{path}/*")
        for file in files:
            filename = file.get_longname()
            if filename not in [".", ".."]:  # Skip special directories
                new_path = f"{path}/{filename}"
                full_path = ("\\\\"+conn.getRemoteHost() + "\\"+share_name + new_path).replace("/", "\\")
                
                # If it's a directory, recurse into it
                if file.is_directory():
                    list_share_path(conn, share_name, new_path, fs, file_size)
                else:
                    #do something with file size here?
                    fs.append(new_path)
                    cur_file_size_mb = file.get_filesize() / 1_000_000 #Convert bytes to megabytes 
                    if(cur_file_size_mb <= file_size):
                        contents = read_file_contents(conn, share_name, new_path)
                        # Do some things with file contents
                        # parse_file_contents(full_path, contents)
                        mime = magic.from_buffer(contents)
                        if "empty" not in mime:
                            print(full_path, ",",mime)
                    else:
                        print(f"{full_path} is too large. {cur_file_size_mb}MB")

    except SessionError as se:
        pass

    except Exception as e:
        print(f"Error accessing {path}\n{e}")

def read_file_contents(conn, share, path):
    file_obj = io.BytesIO()
    conn.getFile(share, path, file_obj.write)
    file_obj.seek(0)
    return file_obj.read()


def parse_file_contents(file_path, file_contents):
    print(f"file: {file_path}")

def is_readable(smb_con : SMBConnection, shareName : str, path : str = "\*"):
    try:
        smb_con.listPath(shareName, path)
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

def move_cursor(row, column):
  # Move cursor to specified position
  print(f"\033[{row};{column}H", end="")


def printShareNames(smb_con : SMBConnection):
    share_headers = ["Share", "Perms", "Comment"]
    shares = []

    for x in smb_con.listShares():
        perms = ""
        shareName = x['shi1_netname'][:-1]
        remarks = x['shi1_remark'][:-1]
       
        if is_readable(smb_con, shareName, "/*"):
            perms += "R"

        if is_writable(smb_con, shareName):
            perms += "W"

        shares.append([shareName, Fore.GREEN+perms+Style.RESET_ALL, remarks])    


    print(tabulate.tabulate(shares, share_headers, colalign=['left', 'center', 'center']))
        
def main():

    parser = argparse.ArgumentParser(prog="snumb", usage="./snumb.py -i <IP> -p <PORT>")
    parser.add_argument("-i", "--ip", dest="addr", required=True, default=None, help="IP:PORT")
    parser.add_argument("-u", "--user", dest="username", default="", help="username")
    parser.add_argument("-p", "--password", dest="password", default="", help="password")
    parser.add_argument("-o", "--output", dest="outfile", required=False, default=None, help="Results will be written to this file.")
    parser.add_argument("-d", "--domain", dest="domain", required=False, default="", help="domain name for Kerberos login.")
    parser.add_argument("-s", "--share", dest="shareName", required=False, default="", help="Share name to enumerate.")
    parser.add_argument("-f", "--file-size", dest="fileSize", required=False, default=50, type=int, help="Max file size in MB for file enum, inclusive. Default 50MB.")
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
        except Exception as e:
            print(f"Connection to {addr_port[0]}:{addr_port[1]} could not be established.")
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
        print(f"[+] Max filesize: {args.fileSize}MB")
        list_share_path(conn=smb_con, share_name=args.shareName, path="", fs=files, file_size=args.fileSize)
            
        print(files)
        
        smb_con.close()


main()



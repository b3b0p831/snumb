#!/usr/bin/python3

import argparse, io, tabulate, magic, os, time, sys, re, chardet
from impacket.smbconnection import SMBConnection, SessionError
from impacket.smb import SharedFile, FILE_READ_DATA, FILE_WRITE_DATA, FILE_NON_DIRECTORY_FILE, GENERIC_ALL
from colorama import Fore, Back, Style

concerned_file_types = [
    "ASCII text",
    "Unicode text",
    "XML",
    "PDF",
    "Microsoft"
]

regex_patterns = [
    r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+",  # email addresses
    r"\$.{8,}$", # hash $y$39dkt...
    r".{8,}$", # hash
    r".{8,}$", # password

]

CLEAR_LINE = "\r\033[K"
MAX_FILE_SIZE = 50
DEFAULT_TIMEOUT = 10
DEBUG = False

def info_msgf(msg : str, prefix : str = "[+] ") -> str:
    return Fore.YELLOW + prefix + Fore.WHITE + f"{msg}" + Fore.RESET

def success_msgf(msg : str, prefix : str = "[+] ") -> str:
    return Fore.GREEN + prefix + Fore.WHITE + f"{msg}" + Fore.RESET

def fail_msgf(msg : str, prefix : str = "[+] ") -> str:
    return Fore.RED + prefix + f"{msg}" + Fore.RESET
    


def list_share_files(conn : SMBConnection, share_name : str, max_file_size : int):
    file_types = []
    print()
    tid = conn.connectTree(share_name)
    get_path_contents(conn, share_name, "", file_types, max_file_size, tid)
    conn.disconnectTree(tid)
    print()
    return file_types

def get_path_contents(conn : SMBConnection, share_name : str, path : str, files: list, max_file_size : int, tid : int):
        # List contents of the current directory
    dir_contents = conn.listPath(share_name, f"{path}\\*")

    for item in dir_contents:
        try:
    
            item_name = item.get_longname()
            curr_path = path + "\\" + item_name

            if item_name not in [".", ".."]:
                # If it's a directory, recurse into it
                if item.is_directory():
                    # Pretty print
                    get_path_contents(conn, share_name, curr_path, files, max_file_size, tid)
                else:
                    file_info = parse_file_contents(conn, share_name, path, max_file_size, item, tid)
                    print(f"{file_info[0]}: {file_info[1]}")

                    if(len(file_info) > 2):
                        print(fail_msgf(file_info[2], ""))

                    files.append(file_info)

        except SessionError as e:
            if DEBUG:
                if "STATUS_ACCESS_DENIED" not in e.getErrorString():
                    print(f"\n{path}: {e}")

        except Exception as e:
            if DEBUG:
                print(f"\n{path}: {e}")


def parse_file_contents(conn : SMBConnection, share_name : str, path : str, max_file_size : int, item : SharedFile, tid : int):
    # List contents of the current directory
    
    file_path = path + "\\" + item.get_longname()
    full_path = "\\\\" + conn.getRemoteHost() + "\\"+share_name + file_path

    cur_file_size_mb = item.get_filesize() / 1_000_000 #Convert bytes to megabytes
    

    bytes_read =  read_file_contents(conn, file_path, tid, 1024)
    mime = magic.from_buffer(bytes_read).split(",")[0]
    full_path if len(full_path) <= os.get_terminal_size().columns-5 else full_path[:os.get_terminal_size().columns - 8]+"..."
    if "ASCII" in mime or "XML" in mime:
        if cur_file_size_mb <= max_file_size:
            bytes_read = read_file_contents(conn, file_path, tid, item.get_filesize() )
            # Perform secrets extraction                         
            secrets = detect_secrets_with_regex(bytes_read.decode("utf-8"))
            return [full_path, mime, secrets]
    
    
    return [full_path, mime]
    

def detect_secrets_with_regex(text):
    secrets = []
    for pattern in regex_patterns:
        matches = re.findall(pattern, text)
        secrets.extend(matches)
    return secrets

def read_file_contents(conn : SMBConnection, path : str, tid : int, btr : int = 512):

    fid = conn.openFile(tid, path, FILE_READ_DATA)
    contents = conn.readFile(tid, fid, 0, btr) # btr = bytesToRead
    conn.closeFile(tid, fid)
    return contents

def is_readable(smb_con : SMBConnection, shareName : str, path : str = "\*"):
    try:
        smb_con.listPath(shareName, path)
        return True
    
    except SessionError as e:
        if DEBUG:
            if "STATUS_ACCESS_DENIED" not in e.getErrorString() or "STATUS_OBJECT_NAME_NOT_FOUND" not in e.getErrorString():
                    print(e)
    
    except Exception as e:
        if DEBUG:
            print(e)
        return False


def is_writable(smb_con : SMBConnection, shareName : str):
    try:
        import secrets, string
        test_filename = "".join(secrets.choice(string.ascii_letters) for i in range(15)) + ".txt"

        #Create file and write
        test_buffer = io.BytesIO(b"micCheck123")
        tid = smb_con.connectTree(shareName)
        fid = smb_con.createFile(tid, test_filename)
        smb_con.writeFile(tid,fid, test_buffer.read())
        smb_con.closeFile(tid, fid)

        #Open file and read
        read_file_contents(smb_con, test_filename, tid, 512)
        

        smb_con.deleteFile(shareName, test_filename)
        return True
    except SessionError as e:
        if DEBUG:
            if "STATUS_ACCESS_DENIED" not in e.getErrorString() or "STATUS_OBJECT_NAME_NOT_FOUND" not in e.getErrorString():
                    print(e)
    
    except Exception as e:
        if DEBUG:
            print(e)
        return False


def get_share_names(smb_con : SMBConnection):
    share_headers = ["Share", "Perms", "Comment"]
    shares = []

    for x in smb_con.listShares():
        perms = ""
        shareName = x['shi1_netname'][:-1]
        remarks = x['shi1_remark'][:-1]

        if is_writable(smb_con=smb_con, shareName=shareName):
            perms += Fore.GREEN + "RW" + Fore.RESET
 
        elif is_readable(smb_con=smb_con, shareName=shareName):
            perms += Fore.GREEN + "R" + Fore.RESET
        

        shares.append([shareName, Fore.GREEN+perms+Style.RESET_ALL, remarks])


    return tabulate.tabulate(shares, share_headers, colalign=['left', 'center', 'center'])

def main():

    parser = argparse.ArgumentParser(add_help=True, description="Tool for finding juicy secrets in SMB Shares")
    parser.add_argument("target", default=None, help="IP:PORT (Default port 445)")
    parser.add_argument("-a", action="store_true", help="enable anonymous login", default=False)
    parser.add_argument("-v", action="store_true", help="verbose logging", default=False)
    parser.add_argument("-u", dest="username", default="", help="username")
    parser.add_argument("-p", dest="password", default="", help="password")
    parser.add_argument("-o", dest="outfile", required=False, default=None, help="results will be written to this file")
    parser.add_argument("-d", dest="domain", required=False, default="", help="domain name")
    parser.add_argument("-s", dest="shareName", required=False, default="", help="share drive to enumerate")
    parser.add_argument("-f", dest="fileSize", required=False, default=MAX_FILE_SIZE, type=int, help="max file size in MB for file enumeration, inclusive. default 50MB.")
    parser.add_argument("--download", default=None, help="Download a file or directory")


    if len(sys.argv) < 2:
        parser.print_help()
        sys.exit(1)


    args = parser.parse_args()

    if args.a:
         args.username = "anonymous"
         args.password = "anonymous"
         

    if(args.target):

        # Connect to share
        target_port = args.target.split(":")       
        if len(target_port) < 2:
            target_port.append(445)

        smb_con : SMBConnection = None
        try:
            smb_con = SMBConnection(remoteName="SMBServer", remoteHost=target_port[0], sess_port=int(target_port[1]), timeout=DEFAULT_TIMEOUT)
            print(success_msgf(f"Connected to SMB Server {args.target}!"))
            smb_con.login(user=args.username, password=args.password, domain=args.domain)
        except SessionError:
            print(fail_msgf("Login Failed"))
            return
        except Exception as e:
            print(fail_msgf(f"Connection to {target_port[0]}:{target_port[1]} could not be established."))
            return

        if smb_con.isGuestSession():
            print(success_msgf(f"Anonymous Login OK!"))
        else:
            print(success_msgf(f"Login OK!"))


        # List Available shares if no share name provided
        if not args.shareName:
            #General Enum
            server_info = f"""\nServer Info:\n------------\nMachine Name: {smb_con.getServerName()}\nServer OS: {smb_con.getServerOS()}\n"""
            share_names = get_share_names(smb_con)
            if(args.outfile):
                with open(args.outfile, "w") as outFile:
                    outFile.write(server_info)
                    outFile.write("\n")
                    outFile.write(share_names)
            print(server_info)
            print(share_names)
            return

        # Determine share permissions
        if is_writable(smb_con=smb_con, shareName=args.shareName):
            print(info_msgf(f'"{args.shareName}" is readable!'))
            print(info_msgf(f'"{args.shareName}" is writable!'))
        
        elif is_readable(smb_con=smb_con, shareName=args.shareName):
            print(info_msgf(f'"{args.shareName}" is readable!'))

        else:
            print(fail_msgf(f'"\\\\{args.target}\\{args.shareName}" is not readable or doesn\'t exist!'))
            exit()

        if args.download:
            try:
                print(info_msgf(f"Downloading {args.download} to {os.getcwd()}"))
                file_name = args.download.split("\\")[-1]
                tid = smb_con.connectTree(args.shareName)
                fd = open(os.path.join(os.getcwd(), file_name), "wb")
                fd.write(read_file_contents(smb_con, args.download, tid, 1000000))


                print(success_msgf(f"Done!"))
                sys.exit()
                
            
            except SessionError as e:
                print(e)
                if "STATUS_NO_SUCH_FILE" in e.getErrorString():
                    print(fail_msgf(f"{args.download} not found on {args.shareName}"))

            except Exception as e:
                print(e)

            finally:
                sys.exit(-1)
            

        #Server info and file size, turn into subroutine        
        print(info_msgf(f"Max filesize: {args.fileSize}MB"))
        print(info_msgf(f"Enumerating \\\\{args.target}\{args.shareName} for pdfs, Microsoft Office files, text files, scripts and any other juicy info..."))

        t_start = time.time()
        file_info = list_share_files(conn=smb_con, share_name=args.shareName, max_file_size=args.fileSize)
        t_stop = time.time()
        print(success_msgf(f"Elapsed Time: {t_stop - t_start:.2f}s"))

        if(args.outfile):
            with open(args.outfile, "w") as outFile:
                for inf in file_info:
                    outFile.write(f"{inf[0]}: {inf[1]}\n")


        smb_con.close()

if __name__ == "__main__":
    main()



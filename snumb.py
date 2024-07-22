#!/usr/bin/python3

import argparse, io, tabulate, magic, os, time, sys, re
from impacket.smbconnection import SMBConnection, SessionError
from impacket.smb import SharedFile, FILE_READ_DATA, FILE_WRITE_DATA, FILE_NON_DIRECTORY_FILE
from colorama import Fore, Back, Style

concerned_file_types = [
    "ASCII text",
    "UTF-8 Unicode text",
    "ISO-8859 text",
    "ELF 32-bit LSB executable",
    "ELF 64-bit LSB executable",
    "Bourne-Again shell script",
    "Python script",
    "JPEG image data",
    "PNG image data",
    "GIF image data",
    "PDF document",
    "HTML document",
    "Rich Text Format data",
    "Microsoft Word 2007+",
    "Microsoft Excel 2007+",
    "Microsoft PowerPoint 2007+",
    "Composite Document File V2 Document",
    "Zip archive data",
    "gzip compressed data",
    "bzip2 compressed data",
    "tar archive",
    "RAR archive data",
    "MP3 audio",
    "MPEG video",
    "AVI video",
    "ISO 9660 CD-ROM filesystem data",
    "SQLite 3.x database"
]

CLEAR_LINE = "\r\033[K"
MAX_FILE_SIZE = 50
DEFAULT_TIMEOUT = 10

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

    try:
        for item in dir_contents:
        
            item_name = item.get_longname()
            curr_path = path + "\\" + item_name
            full_path = "\\\\" + conn.getRemoteHost() + "\\"+share_name + curr_path
            tmp_path = full_path if len(full_path) <= os.get_terminal_size().columns-5 else full_path[:os.get_terminal_size().columns - 8]+"..."                    

            if item_name not in [".", ".."]:
                # If it's a directory, recurse into it
                if item.is_directory():
                    # Pretty print
                    get_path_contents(conn, share_name, curr_path, files, max_file_size, tid)
                else:
                    file_info = parse_file_contents(conn, share_name, path, max_file_size, item, tid)
                    print(f"{file_info[0]}: {file_info[1]}")
                    if(len(file_info) > 2):
                        print(fail_msgf(file_info[2][:100], ""))
                    files.append(file_info)

                    
    except Exception as e:
        print(f"\n{path}: {e}")


def parse_file_contents(conn : SMBConnection, share_name : str, path : str, max_file_size : int, item : SharedFile, tid : int):
    # List contents of the current directory
    
    file_path = path + "\\" + item.get_longname()
    full_path = "\\\\" + conn.getRemoteHost() + "\\"+share_name + file_path

    # cur_file_size_mb = item.get_filesize() / 1_000_000 #Convert bytes to megabytes
    

    # Do some things with file contents
    # fid = conn.openFile(tid, file_path, FILE_READ_DATA)
    # contents = conn.readFile(tid, fid, 0, 1024)
    # conn.closeFile(tid, fid)
    bytes_read = read_file_contents(conn, file_path, tid)
    mime = magic.from_buffer(bytes_read).split(",")[0]
    full_path if len(full_path) <= os.get_terminal_size().columns-5 else full_path[:os.get_terminal_size().columns - 8]+"..."
    if "ASCII" in mime or "XML" in mime or "Unicode" in mime:
        #print(detect_secrets_with_regex(contents.decode()))
        return [full_path, mime, bytes_read]
    
    return [full_path, mime]
    

def detect_secrets_with_regex(text):
    regex_patterns = [
        r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+',  # email addresses
        r'[A-Za-z0-9-_]{32,}',  # API keys
        r'^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[a-zA-Z]).{8,}$'  # passwords
    ]
    secrets = []
    for pattern in regex_patterns:
        matches = re.findall(pattern, text)
        secrets.extend(matches)
    return secrets

def read_file_contents(conn : SMBConnection, path : str, tid : int, btr : int = 1024, fid = None):

    if not fid:
     fid = conn.openFile(tid, path, FILE_READ_DATA)
     
    contents = conn.readFile(tid, fid, 0, btr) # btr = bytesToRead
    conn.closeFile(tid, fid)
    return contents

def is_readable(smb_con : SMBConnection, shareName : str, path : str = "\*"):
    try:
        smb_con.listPath(shareName, path)
        return True
    except SessionError as e:
        return False

def is_writable(smb_con : SMBConnection, shareName : str):
    try:
        test_filename = "test.txt"
        test_buffer = io.BytesIO(b"micCheck123")
        tid = smb_con.connectTree(shareName)
        fid = smb_con.createFile(tid, test_filename)
        smb_con.writeFile(tid,fid, test_buffer.read())
        read_file_contents(smb_con, test_filename, tid, 3, fid)
        smb_con.deleteFile(shareName, test_filename)
        return True
    except SessionError as e:
        if "STATUS_ACCESS_DENIED" not in e.getErrorString()[0]:
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
        else:
            print(fail_msgf(f'"\\\\{smb_con.getRemoteHost()}\\{shareName}" is not readable or doesn\'t exist!'))
            exit()

        shares.append([shareName, Fore.GREEN+perms+Style.RESET_ALL, remarks])


    return tabulate.tabulate(shares, share_headers, colalign=['left', 'center', 'center'])

def main():

    parser = argparse.ArgumentParser(add_help=True, description="Tool for finding juicy secrets in SMB Shares")
    parser.add_argument("target", default=None, help="IP:PORT (Default port 445)")
    parser.add_argument("-a", action="store_true", help="enable anonymous login", default=False)
    parser.add_argument("-u", dest="username", default="", help="username")
    parser.add_argument("-p", dest="password", default="", help="password")
    parser.add_argument("-o", dest="outfile", required=False, default=None, help="results will be written to this file")
    parser.add_argument("-d", dest="domain", required=False, default="", help="domain name")
    parser.add_argument("-s", dest="shareName", required=False, default="", help="share drive to enumerate")
    parser.add_argument("-f", dest="fileSize", required=False, default=MAX_FILE_SIZE, type=int, help="max file size in MB for file enumeration, inclusive. default 50MB.")


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

        # Determine permissions

        if is_writable(smb_con=smb_con, shareName=args.shareName):
            print(info_msgf(f'"{args.shareName}" is readable!'))
            print(info_msgf(f'"{args.shareName}" is writable!'))
        
        elif is_readable(smb_con=smb_con, shareName=args.shareName):
            print(info_msgf(f'"{args.shareName}" is readable!'))

        else:
            print(fail_msgf(f'"\\\\{args.target}\\{args.shareName}" is not readable or doesn\'t exist!'))
            exit()


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



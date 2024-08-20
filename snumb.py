#!/usr/bin/python3

import pdfminer.high_level
import argparse, io, tabulate, magic, os, time, sys, re, chardet, zipfile, openpyxl, pandas, pdfminer
from impacket.smbconnection import SMBConnection, SessionError
from impacket.smb import SharedFile, FILE_READ_DATA, FILE_WRITE_DATA, FILE_NON_DIRECTORY_FILE, GENERIC_ALL
from colorama import Fore, Back, Style
from urllib.parse import urlparse

concerned_file_types = [
    "ASCII text",
    "Unicode text",
    "XML",
    "PDF",
    "Microsoft"
]

# ASCII art with hacker-style green colors
ascii_art = f"""{Style.NORMAL + Fore.GREEN}
███████╗███╗   ██╗██╗   ██╗███╗   ███╗██████╗ 
██╔════╝████╗  ██║██║   ██║████╗ ████║██╔══██╗
███████╗██╔██╗ ██║██║   ██║██╔████╔██║██████╔╝
╚════██║██║╚██╗██║██║   ██║██║╚██╔╝██║██╔══██╗
███████║██║ ╚████║╚██████╔╝██║ ╚═╝ ██║██████╔╝
╚══════╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝     ╚═╝╚═════╝ 
{Style.RESET_ALL}
"""
print(ascii_art)

regex_patterns = [
    r".*[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.].*",  # Email addresses with spaces
    r".*assword.*",                                        # Matches any occurance of "password"
    r".[uU]ser[nN]ame.*",                                  # Matches any occurance of "username"
    r".*[A-Za-z0-9=]{15,}.*",                              # Alphanumeric, min 15 chars. Mainly for hashes.
]


CLEAR_LINE = "\r\033[K"
MAX_FILE_SIZE = 50
DEFAULT_TIMEOUT = 10
VERBOSE = True

def info_msgf(msg : str, prefix : str = "[+] ") -> str:
    return Fore.YELLOW + prefix + Fore.WHITE + f"{msg}" + Fore.RESET

def success_msgf(msg : str, prefix : str = "[+] ") -> str:
    return Fore.GREEN + prefix + Fore.WHITE + f"{msg}" + Fore.RESET

def fail_msgf(msg : str, prefix : str = "[+] ") -> str:
    return Fore.RED + prefix + f"{msg}" + Fore.RESET


def enumerate_share_files(conn : SMBConnection, share_name : str, max_file_size : int):
    file_types = []

    tid = conn.connectTree(share_name)
    print()
    parse_dir_contents(conn, share_name, "", file_types, max_file_size, tid)
    print()

    conn.disconnectTree(tid)

    return file_types

def parse_dir_contents(conn : SMBConnection, share_name : str, path : str, files: list, max_file_size : int, tid : int):
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
                    parse_dir_contents(conn, share_name, curr_path, files, max_file_size, tid)
                else:
                    file_info = parse_file_contents(conn, share_name, path, max_file_size, item, tid)
                    print(f"{file_info[0]}: {file_info[1]}")

                    if(len(file_info) > 2 and file_info[2]):
                        print(info_msgf("Possible Secrets Found"))
                        print(fail_msgf(file_info[2], ""))

                    print()
                    files.append(file_info)
        except Exception as e:
            if VERBOSE:
                print(e)


def parse_file_contents(conn : SMBConnection, share_name : str, path : str, max_file_size : int, item : SharedFile, tid : int):
    # List contents of the current directory

    file_path = path + "\\" + item.get_longname()
    full_path = "\\\\" + conn.getRemoteHost() + "\\"+share_name + file_path

    cur_file_size_mb = item.get_filesize() / 1_000_000 #Convert bytes to megabytes


    bytes_read =  read_file_contents(conn, file_path, tid, 2048)
    mime = f'{(magic.from_buffer(bytes_read).split(",")[0])}, {cur_file_size_mb}MB'
    full_path if len(full_path) <= os.get_terminal_size().columns-5 else full_path[:os.get_terminal_size().columns - 8]+"..."
    if cur_file_size_mb <= max_file_size:
        secrets = []
        contents = read_file_contents(conn, file_path, tid, item.get_filesize())
        file_obj = io.BytesIO(contents)

        # Perform secrets extraction
        if "ASCII" in mime or "XML" in mime:
            enc_type = chardet.detect(contents)["encoding"]
            if enc_type:
                secrets = detect_secrets_with_regex(contents.decode(encoding=enc_type))
            else:
                secrets = detect_secrets_with_regex(contents.decode("utf-8"))

        elif "Zip" in mime:
            zip = zipfile.ZipFile(file_obj, "r")
            buf = ""
            for x in zip.filelist:
                buf += str(x.filename) +"\n"
            secrets = fail_msgf(buf, "")
            zip.close()


        elif "PDF" in mime:
            text = pdfminer.high_level.extract_text(file_obj)
            secrets = detect_secrets_with_regex(text)


        # elif "Excel" in mime:
        #     # secrets = pandas.read_excel(file_obj)
        #     # secrets.map(str)
        #     # secrets.map(lambda x: x.strip() if isinstance(x, str) else x)
        #     wb = openpyxl.load_workbook(file_obj)
        #     ws = wb.active
        #     for mc in list(ws.merged_cells):
        #         ws.unmerge_cells(str(mc))
        #     wb.save(os.path.join(os.getcwd(), "tmp.xlsx"))
        #     secrets = pandas.read_excel(os.path.join(os.getcwd(), "tmp.xlsx"))


        #     # for row in ws.iter_rows(values_only=True):
        #     #     for cell in row:
        #     #         file_str += f"{cell} "
        #     #     file_str += "\n"

        #file_obj.close()
        #secrets = detect_secrets_with_regex(contents)

        return [full_path, mime, secrets]


    return [full_path, mime]


def detect_secrets_with_regex(text : str):
    secrets = []
    for pattern in regex_patterns:
        matches = re.findall(pattern, text)
        for match in matches:
            if match not in secrets:
                secrets.append(match)

    return secrets

def read_file_contents(conn : SMBConnection, path : str, tid : int, btr : int = 512, offset : int = 0):

    fid = None
    contents = b''

    try:
        fid = conn.openFile(treeId=tid, pathName=path, desiredAccess=FILE_READ_DATA)
        file_info = conn.queryInfo(tid, fid)
        total_file_size = file_info.fields['EndOfFile']
        if(total_file_size <= 0):
            return contents

        contents = conn.readFile(treeId=tid, fileId=fid, offset=offset, bytesToRead=btr) # btr = bytesToRead
        while(len(contents) < btr and len(contents) < total_file_size):
            contents += conn.readFile(treeId=tid, fileId=fid, offset=len(contents))

        #print(f"Size: {total_file_size}, Requested: {btr}, Read: {len(contents)}")
        return contents
    except SessionError as e:
        if "STATUS_NO_SUCH_FILE" in e.getErrorString():
            print(fail_msgf(f"{path} not found"))
        elif "STATUS_ACCESS_DENIED" in e.getErrorString():
            print(fail_msgf(f"{path} access denied"))


    except Exception as e:
        if VERBOSE:
            print(e)

    finally:
        if fid:
            conn.closeFile(tid, fid)

    return contents


def is_readable(smb_con : SMBConnection, shareName : str, path : str = "\*"):
    try:
        smb_con.listPath(shareName, path)
        return True

    except SessionError as e:
        if "STATUS_ACCESS_DENIED" in e.getErrorString():
            print(fail_msgf(f'"{shareName}" read access denied'))

        elif "STATUS_OBJECT_NAME_NOT_FOUND" not in e.getErrorString():
            print(f"object not found")

        return False

    except Exception as e:
        if VERBOSE:
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
        if "STATUS_ACCESS_DENIED" in e.getErrorString():
            print(fail_msgf(f'"{shareName}" write access denied'))

        elif "STATUS_OBJECT_NAME_NOT_FOUND" not in e.getErrorString():
            print(f"object not found")

        return False
    except Exception as e:
        if VERBOSE:
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

def download_remote_file(conn : SMBConnection, shareName : str, path : str, dest : str = os.getcwd()):
    try:
        tid = conn.connectTree(shareName)
        fid = conn.openFile(tid, path, FILE_READ_DATA)
        info = conn.queryInfo(tid, fid)
        conn.closeFile(tid, fid)

        file_size = int(info.fields['AllocationSize'])
        file_contents = read_file_contents(conn, path, tid, file_size)

        print(info_msgf(f"Downloading {path} to {dest}"))
        file_name = path.split("\\")[-1]
        with open(os.path.join(os.getcwd(), file_name), "wb") as fd:
            fd.write(file_contents)
        return True

    except SessionError as e:
        if "STATUS_ACCESS_DENIED" in e.getErrorString():
            print(fail_msgf(f'"{path} access denied'))

        elif "STATUS_OBJECT_NAME_NOT_FOUND" not in e.getErrorString():
            print(fail_msgf(f"{path} not found"))

            return False

    except Exception as e:
        if VERBOSE:
            print(e)
        return False
        


def main():

    parser = argparse.ArgumentParser(add_help=True, description="Tool for finding juicy secrets in SMB Shares")
    parser.add_argument("target", default=None, help="IPv4:PORT OR [IPv6]:PORT (Default port 445)")
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
        if(args.target.count(":") > 2 and "[" not in args.target):
            target_port = [args.target, "445"]
        else:
            url = urlparse(f"http://{args.target}")
            target_port = [url.hostname, url.port]
            if (not target_port[1]):
                target_port[1] = "445"
        

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
                    outFile.write(ascii_art + "\n")
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
            if download_remote_file(smb_con, args.shareName, args.download):
                print(success_msgf(f"Done!"))
            else:
                print(fail_msgf(f"Failed to download {args.download} to {args.download}"))

            sys.exit()

        #Server info and file size, turn into subroutine
        print(info_msgf(f"Max filesize: {args.fileSize}MB"))
        #print(info_msgf(f"Enumerating \\\\{args.target}\{args.shareName} for pdfs, Microsoft Office files(comming soon), text files, scripts and any other juicy info..."))
        print(info_msgf(f"Enumerating \\\\{args.target}\{args.shareName} for pdfs, text files, scripts and any other juicy info..."))

        t_start = time.time()
        file_info = enumerate_share_files(conn=smb_con, share_name=args.shareName, max_file_size=args.fileSize)
        t_stop = time.time()
        print(success_msgf(f"Elapsed Time: {t_stop - t_start:.2f}s"))

        if(args.outfile):
            with open(args.outfile, "w") as outFile:
                for inf in file_info:
                    outFile.write(f"{inf[0]}: {inf[1]}\n")
                    if(len(inf) > 2 and inf[2]):
                        outFile.write(info_msgf("Possible Secrets Found\n"))
                        outFile.write(fail_msgf(inf[2], "") + "\n\n")   


        smb_con.close()

if __name__ == "__main__":
    main()

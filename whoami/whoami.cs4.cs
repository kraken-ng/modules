using System;
using System.IO;
using System.Text;
using System.Security;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using System.Runtime.InteropServices;

using System.Diagnostics;
using System.ComponentModel;
using System.Security.Principal;


public class Module_whoami
{
    public const string SUCC_CODE       = "0";
    public const string ERR_CODE        = "1";
    public const string NON_TOKEN_VALUE = "0";
    public const string SEPARATOR       = "\t";

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

    public const int SE_PRIVILEGE_DISABLED = 0x00000000;
    public const int SE_PRIVILEGE_ENABLED = 0x00000002;
    public const int SE_PRIVILEGE_ENABLED_BY_DEFAULT  = 0x00000003;

    public const int TOKEN_QUERY = 0x0008;

    public enum TOKEN_INFORMATION_CLASS
    {
        TokenUser = 1,
        TokenGroups,
        TokenPrivileges,
        TokenOwner,
        TokenPrimaryGroup,
        TokenDefaultDacl,
        TokenSource,
        TokenType,
        TokenImpersonationLevel,
        TokenStatistics,
        TokenRestrictedSids,
        TokenSessionId,
        TokenGroupsAndPrivileges,
        TokenSessionReference,
        TokenSandBoxInert,
        TokenAuditPolicy,
        TokenOrigin,
        TokenElevationType,
        TokenLinkedToken,
        TokenElevation,
        TokenHasRestrictions,
        TokenAccessInformation,
        TokenVirtualizationAllowed,
        TokenVirtualizationEnabled,
        TokenIntegrityLevel,
        TokenUIAccess,
        TokenMandatoryPolicy,
        TokenLogonSid,
        TokenIsAppContainer,
        TokenCapabilities,
        TokenAppContainerSid,
        TokenAppContainerNumber,
        TokenUserClaimAttributes,
        TokenDeviceClaimAttributes,
        TokenRestrictedUserClaimAttributes,
        TokenRestrictedDeviceClaimAttributes,
        TokenDeviceGroups,
        TokenRestrictedDeviceGroups,
        TokenSecurityAttributes,
        TokenIsRestricted,
        TokenProcessTrustLevel,
        TokenPrivateNameSpace,
        TokenSingletonAttributes,
        TokenBnoIsolation,
        TokenChildProcessFlags,
        TokenIsLessPrivilegedAppContainer,
        TokenIsSandboxed,
        TokenIsAppSilo,
        MaxTokenInfoClass
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct LUID 
    {
        public uint LowPart;
        public int HighPart;
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
        public uint PrivilegeCount;
        [MarshalAs(UnmanagedType.ByValArray,SizeConst=100)]
        LUID_AND_ATTRIBUTES[] Privileges;
    }

    [DllImport("Advapi32.dll")]
    public static extern bool OpenProcessToken(
        IntPtr ProcessHandle,
        int DesiredAccess,
        ref IntPtr TokenHandle
    );

    [DllImport("Advapi32.dll")]
    public static extern bool GetTokenInformation(
        IntPtr TokenHandle,
        TOKEN_INFORMATION_CLASS TokenInformationClass,
        IntPtr TokenInformation,
        int TokenInformationLength,
        ref int ReturnLength
    );

    [DllImport("Kernel32.dll")]
    public static extern bool CloseHandle(IntPtr phandle);

    [DllImport("Advapi32.dll")]
    public static extern bool LookupPrivilegeNameW(
        string lpSystemName,
        IntPtr lpLuid,
        [param:MarshalAs(UnmanagedType.LPWStr)] StringBuilder lpName,
        ref int cchName
    );

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr GetCurrentThread();

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool OpenThreadToken(
        IntPtr ThreadHandle,
        TokenAccessLevels DesiredAccess,
        bool OpenAsSelf,
        out IntPtr TokenHandle);

    private IntPtr GetCurrentThreadToken()
    {
        IntPtr currTkn = IntPtr.Zero;
        bool retOt = OpenThreadToken(GetCurrentThread(), TokenAccessLevels.Query, true, out currTkn);
        if (retOt == false)
            return IntPtr.Zero;        
        return currTkn;
    }

    private IntPtr GetCurrentProcessToken()
    {
        IntPtr pId = (Process.GetCurrentProcess().Handle);
        IntPtr hToken = IntPtr.Zero;
        if (!OpenProcessToken(pId, TOKEN_QUERY, ref hToken))
        {
            int errno = Marshal.GetLastWin32Error();
            throw new Win32Exception(errno);
        }
        return hToken;
    }

    private string[] getUserInfo()
    {
        string result = "Username" + SEPARATOR + "SID" + Environment.NewLine;

        try
        {
            using(WindowsIdentity currEntity = WindowsIdentity.GetCurrent())
            {
                string userName = (currEntity.Name != "") ? currEntity.Name : "-";
                string userSID = (currEntity.User.Value != "") ? currEntity.User.Value : "-";
                
                result += userName;
                result += SEPARATOR;
                result += userSID;
                result += Environment.NewLine;
            }
        }
        catch (Exception ex)
        {
            result += ex.ToString() + Environment.NewLine;
            return new string[]{ERR_CODE, result};
        }

        return new string[]{SUCC_CODE, result};
    }

    private string[] getGroupInfo()
    {
        string result = "Group Name" + SEPARATOR + "SID" + Environment.NewLine;

        try
        {
            using(WindowsIdentity currEntity = WindowsIdentity.GetCurrent())
            {
                foreach (IdentityReference groupId in currEntity.Groups)
                {
                    try
                    {
                        SecurityIdentifier s = new SecurityIdentifier(groupId.Value);
                        NTAccount groupAccount = (NTAccount)s.Translate(typeof(NTAccount));

                        string group_name = (groupAccount.ToString() != "") ? groupAccount.ToString() : "-";
                        string group_id = (groupId.Value != "") ? groupId.Value : "-";
                        
                        result += group_name;
                        result += SEPARATOR;
                        result += group_id;
                        result += Environment.NewLine;
                    }
                    catch(Exception)
                    {
                        continue;
                    }
                }
            }
        }
        catch (Exception ex)
        {
            result += ex.ToString() + Environment.NewLine;
            return new string[]{ERR_CODE, result};
        }

        return new string[]{SUCC_CODE, result};
    }

    private string[] getPrivsInfo()
    {
        string result = "Privilege Name" + SEPARATOR + "Status" + Environment.NewLine;

        try
        {
            IntPtr tokenhandle = GetCurrentThreadToken();
            if (tokenhandle == IntPtr.Zero)
                tokenhandle = GetCurrentProcessToken();
            
            int privlength = 0;
            GetTokenInformation(
                tokenhandle,
                TOKEN_INFORMATION_CLASS.TokenPrivileges,
                IntPtr.Zero,
                privlength,
                ref privlength
            );

            IntPtr tpptr = Marshal.AllocHGlobal(privlength);
            GetTokenInformation(
                tokenhandle,
                TOKEN_INFORMATION_CLASS.TokenPrivileges,
                tpptr,
                privlength,
                ref privlength
            );

            TOKEN_PRIVILEGES tp = (TOKEN_PRIVILEGES)Marshal.PtrToStructure(tpptr, typeof(TOKEN_PRIVILEGES));
            IntPtr startingptr = new IntPtr(tpptr.ToInt64() + sizeof(uint));
            LUID_AND_ATTRIBUTES laa_init = (LUID_AND_ATTRIBUTES)Marshal.PtrToStructure(startingptr, typeof(LUID_AND_ATTRIBUTES));

            for (int i = 0; i < tp.PrivilegeCount; i++)
            {
                IntPtr tempptr = new IntPtr(startingptr.ToInt64() + (i * Marshal.SizeOf(laa_init)));
                LUID_AND_ATTRIBUTES laa = (LUID_AND_ATTRIBUTES)Marshal.PtrToStructure(tempptr, typeof(LUID_AND_ATTRIBUTES));
                
                int cchName = 100;
                StringBuilder sb = new StringBuilder(100);
                IntPtr luidptr = Marshal.AllocHGlobal(Marshal.SizeOf(laa.Luid));
                Marshal.StructureToPtr(laa.Luid, luidptr, true);
                LookupPrivilegeNameW(
                    null,
                    luidptr,
                    sb,
                    ref cchName
                );
                
                string priv_name = (sb.ToString() != "") ? sb.ToString() : "-";
                string priv_status = "-";

                if (laa.Attributes == SE_PRIVILEGE_DISABLED)
                    priv_status = "Disabled";
                else if (laa.Attributes == SE_PRIVILEGE_ENABLED)
                    priv_status = "Enabled";
                else if (laa.Attributes == SE_PRIVILEGE_ENABLED_BY_DEFAULT)
                    priv_status = "Enabled";

                result += priv_name;
                result += SEPARATOR;
                result += priv_status;
                result += Environment.NewLine;
            }

            result = result.TrimEnd('\n');

            CloseHandle(tokenhandle);
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

        if (nargs.Count == 0)
            return getUserInfo();
        
        if (nargs.Count == 1)
        {
            string option = nargs[0];
            switch (option) 
            {
                case "-u":
                    return getUserInfo();
                case "-g":
                    return getGroupInfo();
                case "-p":
                    return getPrivsInfo();
                default:
                    result = "Invalid argument '" + option + "'" + Environment.NewLine;
                    return new string[]{ERR_CODE, result};
            }
        }
        else
        {
            result = "Invalid arguments provided" + Environment.NewLine;
            return new string[]{ERR_CODE, result};
        }
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
        Module_whoami m = new Module_whoami();
        String[] results = m.go(cwd, args, token);
        Console.WriteLine(results[0]);
        Console.WriteLine(results[1]);
        return;
    }

    public static void Main(string[] args)
    {
        Module_whoami m = new Module_whoami();
        String[] results = m.execute(args);
        Console.WriteLine(results[0]);
        Console.WriteLine(results[1]);
        return;
    }
}
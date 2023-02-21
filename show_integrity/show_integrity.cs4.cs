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


public class Module_show_integrity
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

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool OpenThreadToken(
        IntPtr ThreadHandle,
        TokenAccessLevels DesiredAccess,
        bool OpenAsSelf,
        out IntPtr TokenHandle);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr GetCurrentThread();

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern IntPtr GetSidSubAuthority(IntPtr sid, UInt32 subAuthorityIndex);

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern IntPtr GetSidSubAuthorityCount(IntPtr sid);

    const int SECURITY_MANDATORY_UNTRUSTED_RID = (0x00000000);
    const int SECURITY_MANDATORY_LOW_RID = (0x00001000);
    const int SECURITY_MANDATORY_MEDIUM_RID = (0x00002000);
    const int SECURITY_MANDATORY_HIGH_RID = (0x00003000);
    const int SECURITY_MANDATORY_SYSTEM_RID = (0x00004000);
    const int SECURITY_MANDATORY_PROTECTED_PROCESS_RID = (0x00005000);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool OpenProcessToken(
        IntPtr ProcessHandle,
        UInt32 DesiredAccess,
        out IntPtr TokenHandle
        );

    const UInt32 TOKEN_QUERY = 0x0008;

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool GetTokenInformation(
        IntPtr TokenHandle,
        TOKEN_INFORMATION_CLASS TokenInformationClass,
        IntPtr TokenInformation,
        uint TokenInformationLength,
        out uint ReturnLength
        );

    enum TOKEN_INFORMATION_CLASS {
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
        MaxTokenInfoClass
    }

    const int ERROR_INVALID_PARAMETER = 87;

    public enum IntegrityLevel
    {
        Low, Medium, High, System, None,
    }

    private IntPtr GetCurrentProcessToken()
    {
        IntPtr pId = (Process.GetCurrentProcess().Handle);
        IntPtr hToken = IntPtr.Zero;
        if (!OpenProcessToken(pId, TOKEN_QUERY, out hToken))
        {
            int errno = Marshal.GetLastWin32Error();
            throw new Win32Exception(errno);
        }
        return hToken;
    }

    private IntPtr GetCurrentThreadToken()
    {
        IntPtr currTkn = IntPtr.Zero;
        bool retOt = OpenThreadToken(GetCurrentThread(), TokenAccessLevels.AdjustPrivileges | TokenAccessLevels.Query, false, out currTkn);
        if (retOt == false)
            return IntPtr.Zero;        
        return currTkn;
    }

    private string GetIntegrityLevel(IntPtr hToken)
    {
        IntPtr pb = Marshal.AllocCoTaskMem(1000);
        try
        {
            uint cb = 1000;
            if (GetTokenInformation(hToken, TOKEN_INFORMATION_CLASS.TokenIntegrityLevel, pb, cb, out cb))
            {
                IntPtr pSid = Marshal.ReadIntPtr(pb);

                int dwIntegrityLevel = Marshal.ReadInt32(GetSidSubAuthority(pSid, (Marshal.ReadByte(GetSidSubAuthorityCount(pSid)) - 1U)));

                if (dwIntegrityLevel == SECURITY_MANDATORY_LOW_RID)
                {
                    return "LOW";
                }
                else if (dwIntegrityLevel >= SECURITY_MANDATORY_MEDIUM_RID && dwIntegrityLevel < SECURITY_MANDATORY_HIGH_RID)
                {
                    return "MEDIUM";
                }
                else if (dwIntegrityLevel >= SECURITY_MANDATORY_SYSTEM_RID)
                {
                    return "SYSTEM";
                }
                else if (dwIntegrityLevel >= SECURITY_MANDATORY_HIGH_RID)
                {
                    return "HIGH";
                }
                return "NONE";
            }
            else
            {
                int errno = Marshal.GetLastWin32Error();
                if (errno == ERROR_INVALID_PARAMETER)
                {
                    throw new NotSupportedException();
                }
                throw new Win32Exception(errno);
            }
        }
        finally
        {
            Marshal.FreeCoTaskMem(pb);
        }
    }

    private string[] doShowIntegrity()
    {
        string result = "";

        try
        {
            IntPtr ctToken = GetCurrentThreadToken();
            if (ctToken == IntPtr.Zero)
                ctToken = GetCurrentProcessToken();

            result += "Current Integrity Level: '" + GetIntegrityLevel(ctToken) + "'" + Environment.NewLine;
        }
        catch(Exception ex)
        {
            result += ex.ToString() + Environment.NewLine;
            return new string[]{ERR_CODE, result};
        }

        return new string[]{SUCC_CODE, result};
    }

    public string[] execute(string[] args)
    {
        return doShowIntegrity();
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
        Module_show_integrity m = new Module_show_integrity();
        String[] results = m.execute(args);
        Console.WriteLine(results[0]);
        Console.WriteLine(results[1]);
        return;
    }
}
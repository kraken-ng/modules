import java.io.*;
import java.util.*;
import java.text.*;
import java.util.regex.*;


public class Module_id
{
    private final String SUCC_CODE = "0";
    private final String ERR_CODE  = "1";
    private final String JAVA_EOL  = getLineSeparator();

    private String getLineSeparator()
    {
        String os_name = System.getProperty("os.name");
        if (os_name.startsWith("Windows"))
            return "\r\n";
        else
            return "\n";
    }

    private byte[] hex2bin(String data) throws Exception
    {
        if ((data.length() % 2) == 1)
            throw new Exception("hex2bin(): data cannot have an odd number of digits");
        
        byte[] data_bytes = new byte[data.length() / 2];
        for (int i = 0; i < data.length(); i += 2)
        {
            String hs = data.substring(i, i + 2);
            try
            {
                int val = Integer.parseInt(hs, 16);
                data_bytes[i/2] = (byte)val;
            }
            catch(Exception e)
            {
                throw new Exception("hex2bin() failed to convert hex:'" + hs + "' to byte");
            }
        }
        return data_bytes;
    }

    private String bin2hex(byte[] ba) throws Exception
    {
        try
        {
            StringBuilder sb = new StringBuilder(ba.length * 2);
            for (byte b: ba)
                sb.append(String.format("%02x", b));
            return sb.toString();
        }
        catch(Exception e)
        {
            throw new Exception("bin2hex() failed");
        }
    }

    private String hex2str(String data) throws Exception
    {
        byte[] data_bytes = hex2bin(data);
        String data_string = new String(data_bytes);
        return data_string;
    }

    private String normalizePath(String currPath)
    {
        currPath = currPath.replace("\"", "");
        currPath = currPath.replace("'", "");
        currPath = currPath.replace("\\", "/");
        return currPath;
    }

    private String[] parseArgs(String args)
    {
        String regex = "\"[^\"]+\"|'[^']+'|\\S+";
        Pattern pattern = Pattern.compile(regex);
        Matcher matcher = pattern.matcher(args);
        List<String> arguments = new ArrayList<String>();

        while (matcher.find())
            arguments.add(matcher.group(0));

        String[] arguments_arr = new String[arguments.size()];
        arguments_arr = arguments.toArray(arguments_arr);
        return arguments_arr;
    }

    private String changeCWD(String cwd) throws Exception
    {
        File target_dir = new File(cwd).getAbsoluteFile();

        if (target_dir.exists() == false)
            throw new Exception("Directory: '" + cwd + "': does not exist");

        if (target_dir.canRead() == false)
            throw new Exception("Can't move to path: '" + cwd + "': permission denied");

        if (target_dir.isDirectory() == false)
            throw new Exception("Path: '" + cwd + "': is not a directory");

        System.setProperty("user.dir", target_dir.getCanonicalPath());

        return normalizePath(target_dir.getCanonicalPath());
    }

    private String getOS()
    {
        String OS = System.getProperty("os.name").toLowerCase();
        if (OS.contains("win"))
            return "Windows";
        if (OS.contains("nix") || OS.contains("nux") || OS.contains("aix"))
            return "Unix";
        return OS;
    }

    private String readFile(File file) throws Exception
    {
        String result = "";
        Scanner freader = new Scanner(file);
        
        while (freader.hasNextLine())
            result += freader.nextLine() + JAVA_EOL;
        
        freader.close();

        return result;
    }

    private List<String> parsePasswdFile() throws Exception
    {
        List<String> results = new ArrayList<String>();

        File passwd_file = new File("/etc/passwd");
        String passwd_content = readFile(passwd_file);
        String[] passwd_lines = passwd_content.split("\n");
        for (String passwd_line: passwd_lines)
        {
            String[] passwd_line_fields = passwd_line.split(":", 7);
            
            String user_name          = passwd_line_fields[0];
            String encrypted_password = passwd_line_fields[1];
            String user_id            = passwd_line_fields[2];
            String default_group_id   = passwd_line_fields[3];
            String user_info          = passwd_line_fields[4];
            String home_dir           = passwd_line_fields[5];
            String login_shell        = passwd_line_fields[6];

            String line = user_name + ":" + user_id + ":" + default_group_id + JAVA_EOL;
            results.add(line);
        }
        return results;
    }

    private List<String> parseGroupFile() throws Exception
    {
        List<String> results = new ArrayList<String>();

        File group_file = new File("/etc/group");
        String group_content = readFile(group_file);
        String[] group_lines = group_content.split("\n");
        for (String group_line: group_lines)
        {
            String[] group_line_fields = group_line.split(":", 4);
            
            String group_name          = group_line_fields[0];
            String encrypted_password  = group_line_fields[1];
            String group_id            = group_line_fields[2];
            String users_in_group      = group_line_fields[3];

            String line = group_name + ":" + group_id + ":" + users_in_group + JAVA_EOL;
            results.add(line);
        }
        return results;
    }

    private String uid2Name(List<String> passwd_users, String uid)
    {
        for (String passwd_user : passwd_users)
        {
            String[] passwd_user_fields = passwd_user.split(":", 3);
            if (uid.equals(passwd_user_fields[1]))
            {
                return passwd_user_fields[0];
            }
        }
        return "?";
    }

    private String gid2Name(List<String> group_users, String gid)
    {
        for (String group_user : group_users)
        {
            String[] group_user_fields = group_user.split(":", 3);
            if (gid.equals(group_user_fields[1]))
            {
                return group_user_fields[0];
            }
        }
        return "?";
    }

    private String doID()
    {
        String result = "";

        try
        {
            String current_os = getOS();

            if (current_os.equals("Unix"))
            {
                List<String> passwd_file_content = parsePasswdFile();
                List<String> group_file_content = parseGroupFile();
                
                File status_file = new File("/proc/self/status");
                String status_file_data = readFile(status_file);
                String[] status_file_lines = status_file_data.split("\n");

                for (String status_file_line : status_file_lines)
                {
                    if (status_file_line.startsWith("Uid:"))
                    {
                        String[] status_uid_fields = status_file_line.split("\t");
                        
                        if (status_uid_fields.length >= 2)
                        {
                            String user_id = status_uid_fields[1];
                            String user_name = uid2Name(passwd_file_content, user_id);
                            result += "uid=" + user_id + "(" + user_name + ")";
                        }
                    }

                    if (status_file_line.startsWith("Gid:"))
                    {
                        String[] status_uid_fields = status_file_line.split("\t");
                        
                        if (status_uid_fields.length >= 2)
                        {
                            String group_id = status_uid_fields[1];
                            String group_name = gid2Name(group_file_content, group_id);
                            result += " gid=" + group_id + "(" + group_name + ")";
                        }
                    }

                    if (status_file_line.startsWith("Groups:"))
                    {
                        String[] status_uid_fields = status_file_line.split("\t");
                        
                        if (status_uid_fields.length >= 2)
                        {
                            String groups_id_line = status_uid_fields[1];
                            String[] groups_ids = groups_id_line.split(" ");

                            String grp_res = " groups=";
                            for (String groups_id : groups_ids)
                            {
                                String group_name = gid2Name(group_file_content, groups_id);
                                grp_res += groups_id + "(" + group_name + "),";
                            }

                            if (grp_res.endsWith(","))
                            {
                                result += grp_res.substring(0, grp_res.length() - 1);
                            }
                        }
                    }
                }

                result += JAVA_EOL;
            }
        }
        catch (Exception ex)
        {
            result += ex.getMessage() + JAVA_EOL;
        }

        return result;
    }

    public String[] execute(String[] args)
    {
        String result = "";
        
        result = doID();

        return new String[]{SUCC_CODE, result};
    }

    public String[] go(String module_cwd, String module_args)
    {
        try
        {
            String new_cwd = changeCWD(hex2str(module_cwd));
            String[] args = parseArgs(hex2str(module_args));
            return execute(args);
        }
        catch(Exception ex)
        {
            return new String[]{ERR_CODE, ex.getMessage() + JAVA_EOL};
        } 
    }

    public static void main(String[] args)
    {
        Module_id m = new Module_id();
        String[] results = m.execute(args);
        System.out.println(results[1]);
        return;
    }
}
import java.io.*;
import java.util.*;
import java.text.*;
import java.util.regex.*;

import java.nio.file.*;
import java.nio.file.attribute.*;


public class Module_ls
{
    private final String SUCC_CODE   = "0";
    private final String ERR_CODE    = "1";
    private final String DATE_FORMAT = "yyyy/MM/dd HH:mm:ss";
    private final String JAVA_EOL    = getLineSeparator();

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

    private String getPermissions(File file)
    {
        String result = "";
        if (file.canRead())
            result += "r";
        else
            result += "-";
            
        if (file.canWrite())
            result += "w";
        else
            result += "-";

        if (file.canExecute())
            result += "x";
        else
            result += "-";
        
        return result;
    }

    private String getLastModified(File file)
    {
        String date = "";
        SimpleDateFormat sdf = new SimpleDateFormat(DATE_FORMAT);
        date = sdf.format(file.lastModified());
        return date;
    }

    private String getSize(File file)
    {
        String result = "";
        long size = file.length();
        
        long KILO = 1024;
        long MEGA = KILO * KILO;
        long GIGA = MEGA * KILO;
        long TERA = GIGA * KILO;
        
        double kb = (double)size / KILO;
        double mb = kb / KILO;
        double gb = mb / KILO;
        double tb = gb / KILO;

        if (size < KILO)
            result = size + "b";
        else if (size >= KILO && size < MEGA)
            result =  String.format("%.2f", kb) + "Kb";
        else if (size >= MEGA && size < GIGA)
            result = String.format("%.2f", mb) + "Mb";
        else if (size >= GIGA && size < TERA)
            result = String.format("%.2f", gb) + "Gb";
        else if (size >= TERA)
            result = String.format("%.2f", tb) + "Tb";

        return result;
    }

    private String getType(File file)
    {
        String result = "";
        if (file.isFile())
            result = "-";
        else if (file.isDirectory())
            result = "d";
        else
            result = "?";
        return result;
    }

    private String posixPerms2Str(PosixFileAttributes attr)
    {
        String output = "";
        Set<PosixFilePermission> perms = attr.permissions();
        
        if (perms.contains(PosixFilePermission.OWNER_READ))
            output += "r";
        else
            output += "-";
        if (perms.contains(PosixFilePermission.OWNER_WRITE))
            output += "w";
        else
            output += "-";
        if (perms.contains(PosixFilePermission.OWNER_EXECUTE))
            output += "x";
        else
            output += "-";
        
        if (perms.contains(PosixFilePermission.GROUP_READ))
            output += "r";
        else
            output += "-";
        if (perms.contains(PosixFilePermission.GROUP_WRITE))
            output += "w";
        else
            output += "-";
        if (perms.contains(PosixFilePermission.GROUP_EXECUTE))
            output += "x";
        else
            output += "-";
        
        if (perms.contains(PosixFilePermission.OTHERS_READ))
            output += "r";
        else
            output += "-";
        if (perms.contains(PosixFilePermission.OTHERS_WRITE))
            output += "w";
        else
            output += "-";
        if (perms.contains(PosixFilePermission.OTHERS_EXECUTE))
            output += "x";
        else
            output += "-";
        
        return output;
    }

    private String getFileAttrsNix(String filepath) throws IOException
    {
        String result = "";
        Path path = Paths.get(filepath);
        PosixFileAttributes attr = Files.readAttributes(path, PosixFileAttributes.class);
        attr = Files.getFileAttributeView(path, PosixFileAttributeView.class).readAttributes();

        File lfile = new File(filepath);

        result += getType(lfile);
        result += posixPerms2Str(attr);
        result += "\t" + getSize(lfile);
        result += "\t" + attr.owner().getName();
        result += "\t" + attr.group().getName();
        result += "\t" + getLastModified(lfile);
        
        return result;
    }

    private String getFileAttrsWin(String filepath) throws IOException
    {
        String result = "";
        Path path = Paths.get(filepath);
        FileOwnerAttributeView ownerAttributeView = Files.getFileAttributeView(path, FileOwnerAttributeView.class);

        File lfile = new File(filepath);

        result += getType(lfile);
        result += getPermissions(lfile);
        result += "\t" + getSize(lfile);
        try
        {
            UserPrincipal owner = ownerAttributeView.getOwner();
            result += "\t" + owner.getName();
        }
        catch(Exception e)
        {
            result += "\t" + "?";
        }
        result += "\t" + getLastModified(lfile);
        
        return result;
    }

    private String doList(String path, Boolean recursive)
    {
        String result = "";
        ArrayList<String> results = new ArrayList<String>();
        
        try 
        {
            path = normalizePath(path);
            File file = new File(path).getAbsoluteFile();

            if (file.exists() == false)
                throw new Exception("ls: can't access " + path + ": file or directory does not exist");

            if (file.canRead() == false)
                throw new Exception("ls: can't open directory " + path + ": Permission denied");

            if (file.isDirectory())
            {
                results.add(file.getCanonicalPath() + File.separator + ".");
                results.add(file.getCanonicalPath() + File.separator + "..");

                String StrFiles[] = file.list();
                for(String StrFile : StrFiles)
                {
                    File tmp_file = new File(path + File.separator + StrFile);
                    results.add(tmp_file.getCanonicalPath());
                }
            }
            else
            {
                results.add(file.getCanonicalPath());
            }

            Collections.sort(results);

            for(String filepath : results)
            {
                try
                {
                    File lfile = new File(filepath);
                    String os_name = System.getProperty("os.name");

                    if (os_name.startsWith("Windows"))
                        result += getFileAttrsWin(filepath);
                    else
                        result += getFileAttrsNix(filepath);

                    if (recursive)
                        result += "\t" + filepath + JAVA_EOL;
                    else
                        result += "\t" + lfile.getName() + JAVA_EOL;

                    if (filepath.endsWith(File.separator + ".") || filepath.endsWith(File.separator + ".."))
                        continue;

                    if (recursive && lfile.isDirectory())
                        result += doList(filepath, recursive);
                }
                catch(Exception ex)
                {
                    continue;
                }
            }
        }
        catch(Exception ex)
        {
            result += "ls: " + ex.getMessage() + JAVA_EOL;
        }

        return result;
    }

    public String[] execute(String[] args)
    {
        String result = "";
        Boolean recursive = false;
        String[] files = new String[]{};
        
        if (args.length > 0)
        {            
            if (args[0].equals("-R"))
            {
                recursive = true;
                files = Arrays.copyOfRange(args, 1, args.length);
            }
            else
            {
                files = Arrays.copyOfRange(args, 0, args.length);
            }
        }

        if (files.length == 0)
            files = new String[]{System.getProperty("user.dir")};

        for (String file : files)
            result += doList(file, recursive);

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
        Module_ls m = new Module_ls();
        String[] results = m.execute(args);
        System.out.println(results[1]);
        return;
    }
}
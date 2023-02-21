import java.io.*;
import java.util.*;
import java.text.*;
import java.util.regex.*;

import java.security.*;


public class Module_upload
{
    private final String SUCC_CODE        = "0";
    private final String ERR_CODE         = "1";
    private final String CUSTOM_SEPARATOR = "|";
    private final Integer MAX_CHUNK_SIZE  = 1048576;
    private final String JAVA_EOL         = getLineSeparator();

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

    private boolean isNumeric(String strNum)
    {
        if (strNum == null)
            return false;
        
        try
        {
            Integer i = Integer.parseInt(strNum);
        }
        catch (NumberFormatException nfe)
        {
            return false;
        }
        return true;
    }

    private void writeChunk(String filepath, byte[] chunk_data, Integer seek) throws IOException
    {
        RandomAccessFile fp = new RandomAccessFile(filepath, "rw");
        fp.seek(seek);
        fp.write(chunk_data);
        fp.close();
    }

    private String getMd5File(String filePath) throws Exception
    {
        String returnVal = "";
        InputStream   input   = new FileInputStream(filePath); 
        byte[]        buffer  = new byte[1024];
        MessageDigest md5Hash = MessageDigest.getInstance("MD5");
        int           numRead = 0;
        while (numRead != -1)
        {
            numRead = input.read(buffer);
            if (numRead > 0)
                md5Hash.update(buffer, 0, numRead);
        }
        input.close();

        byte [] md5Bytes = md5Hash.digest();
        for (int i=0; i < md5Bytes.length; i++)
            returnVal += Integer.toString( ( md5Bytes[i] & 0xff ) + 0x100, 16).substring( 1 );
        
        return returnVal.toLowerCase();
    }

    private String[] doUpload(String filepath, String filesize, String seek, String chunk_size, String chunk_data)
    {
        String output = "";
        String checksum = "";
        
        try 
        {
            filepath = normalizePath(filepath);
            File file = new File(filepath);
            String parent_filepath = file.getParent();
            File filep = new File(parent_filepath);

            if (filep.canWrite() == false)
                throw new Exception("can't perform stat on '" + filepath + "': Permission denied");

            if (isNumeric(filesize) == false)
                throw new Exception("invalid file size '" + filesize + "': not a number");

            if (isNumeric(seek) == false)
                throw new Exception("invalid seek position '" + seek + "': not a number");

            if (isNumeric(chunk_size) == false)
                throw new Exception("invalid chunk size '" + chunk_size + "': not a number");

            Integer seek_position = Integer.parseInt(seek);
            if (seek_position == 0 && file.exists())
                throw new Exception("can't perform stat on '" + filepath + "': File or directory exist");
            
            Integer file_size = Integer.parseInt(filesize);

            Integer chunk_size_value = Integer.parseInt(chunk_size);
            if (chunk_size_value > MAX_CHUNK_SIZE)
                throw new Exception("chunk size: " + Integer.toString(chunk_size_value) + " exceeds MAX_CHUNK_SIZE: " + Integer.toString(MAX_CHUNK_SIZE));
            
            if (file_size < seek_position)
                throw new Exception("invalid seek position '" + Integer.toString(seek_position) + "': exceeds '" + filepath + "' total length '" + Integer.toString(file_size) + "'");

            byte[] chunk_data_raw = hex2bin(chunk_data);
            writeChunk(filepath, chunk_data_raw, seek_position);

            String chunk_data_written_raw = Integer.toString(chunk_data_raw.length);
            byte[] chunk_data_written_bytes = chunk_data_written_raw.getBytes();
            String chunk_data_written_str = bin2hex(chunk_data_written_bytes);

            if ((chunk_data_raw.length < chunk_size_value) || (file_size <= (seek_position + chunk_size_value)))
            {
                String checksum_raw = getMd5File(filepath);
                byte[] checksum_bytes = checksum_raw.getBytes();
                checksum = bin2hex(checksum_bytes);
            }

            output = chunk_data_written_str + CUSTOM_SEPARATOR + checksum;
        }
        catch(Exception ex)
        {
            return new String[]{ERR_CODE, "upload: " + ex.getMessage() + JAVA_EOL};
        }

        return new String[]{SUCC_CODE, output};
    }

    public String[] execute(String[] args)
    {        
        if (args.length != 5)
            return new String[]{ERR_CODE, "Invalid arguments provided. Specify a filepath to upload, file size, seek, chunk size and chunk data" + JAVA_EOL};

        return doUpload(args[0], args[1], args[2], args[3], args[4]);
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
        Module_upload m = new Module_upload();
        String[] results = m.execute(args);
        System.out.println(results[0]);
        System.out.println(results[1]);
        return;
    }
}
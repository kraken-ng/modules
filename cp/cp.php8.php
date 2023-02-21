#<?php


class Module_cp
{
    private $SUCC_CODE        = 0;
    private $ERR_CODE         = 1;

    private $FIELD_SEPARATOR  = ",";
    private $VALUE_SEPARATOR  = "=";

    private $RESPONSE_STATUS  = "status";
    private $RESPONSE_MESSAGE = "message";

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

    private function doCopy($ins, $dest)
    {
        $result = "";
        $dest = $this->normalizePath($dest);

        if ((sizeof($ins) > 1) && (!is_dir($dest)))
            throw new Exception("cp: target '$dest' is not a directory");

        foreach ($ins as $input_file)
        {
            try
            {
                $dest_file_path = "";
                $input_file = $this->normalizePath($input_file);

                if (@is_dir($dest))
                    $dest_file_path = $dest  . DIRECTORY_SEPARATOR  . basename($input_file);
                else
                    $dest_file_path = $dest;

                if (@file_exists($input_file) === false)
                    throw new Exception("cp: can't perform stat on '$input_file': File does not exist");
        
                if (@is_readable($input_file) === false)
                    throw new Exception("cp: can't perform stat on '$input_file': Permission denied");

                if (@copy($input_file, $dest_file_path) === false)
                    throw new Exception("cp: file '$input_file' to '$dest_file_path': Failed");

            }
            catch (Exception $e)
            {
                $result .= $e->getMessage() . PHP_EOL;
            }
        }

        return $result;
    }

    public function execute($args)
    {
        $result = "";

        try
        {
            $parsed_args = $this->parseArgs(hex2bin($args));

            if (sizeof($parsed_args) <= 1)
                throw new Exception("Invalid arguments provided. Specify one or multiple files to be copied and destination");

            $ins = array_slice($parsed_args, 0, -1);
            $dest = end($parsed_args);

            $result = $this->doCopy($ins, $dest);
  
        }
        catch (Exception $e)
        {
            $result = $e->getMessage() . PHP_EOL;
            $this->return_code = $this->ERR_CODE;
        }

        return $this->generateResponse($result);
    }
}


$cwd = '#{CWD}';
$args = '#{ARGS}';
$module = new Module_cp($cwd);
print($module->execute($args));
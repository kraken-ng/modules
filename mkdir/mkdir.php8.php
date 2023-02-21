#<?php


class Module_mkdir
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

    private function doMkdir($filepaths)
    {
        $result = "";

        foreach ($filepaths as $filepath)
        {
            try
            {
                $filepath = $this->normalizePath($filepath);

                if (@file_exists($filepath) === true)
                    throw new Exception("mkdir: dir '$filepath': already exists");

                if(!@mkdir($filepath, 0755, true))
                    throw new Exception("mkdir: dir '$filepath': Failed");

                $result .= "Directory: '$filepath' created" . PHP_EOL;
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

        $parsed_args = $this->parseArgs(hex2bin($args));

        if (sizeof($parsed_args) == 0)
        {
            $result = "Invalid arguments provided. Specify one or multiple directories to be created.";
            $this->return_code = $this->ERR_CODE;
        }
        else
        {
            $result .= $this->doMkdir($parsed_args);
        }
        return $this->generateResponse($result);
    }
}


$cwd = '#{CWD}';
$args = '#{ARGS}';
$module = new Module_mkdir($cwd);
print($module->execute($args));
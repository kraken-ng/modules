#<?php


class Module_rm
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
    
    private function doRemove($files)
    {
        $result = "";

        foreach ($files as $filepath)
        {
            try
            {
                $filepath = $this->normalizePath($filepath);

                if (@file_exists($filepath) === false)
                    throw new Exception("rm: can't perform stat on '$filepath': File or directory does not exist");

                if (!@is_readable($filepath) || !@is_writable($filepath))
                    throw new Exception("rm: can't perform stat on '$filepath': Permission denied");

                if (@is_dir($filepath))
                {
                    if (@rmdir($filepath) === false)
                    {
                        throw new Exception("rm: dir '$filepath': Failed");
                    }
                }
                else
                {
                    if (@unlink($filepath) === false)
                    {
                        throw new Exception("rm: file '$filepath': Failed");
                    }
                }
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

            if (sizeof($parsed_args) === 0)
                throw new Exception("Invalid arguments provided. Specify one or multiple files to remove");

            $result = $this->doRemove($parsed_args);
  
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
$module = new Module_rm($cwd);
print($module->execute($args));
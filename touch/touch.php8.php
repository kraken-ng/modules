#<?php


class Module_touch
{
    private $SUCC_CODE        = 0;
    private $ERR_CODE         = 1;

    private $FIELD_SEPARATOR  = ",";
    private $VALUE_SEPARATOR  = "=";

    private $RESPONSE_STATUS  = "status";
    private $RESPONSE_MESSAGE = "message";

    private $DATE_FORMAT      = 'd/m/Y-H:i:s';

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

    private function doTouch($str_date, $files)
    {
        $result = "";

        $obj_date = @DateTime::createFromFormat($this->DATE_FORMAT, $str_date);
        if ($obj_date === false)
            throw new Exception("Invalid date format to '$str_date'. Required '" . $this->DATE_FORMAT . "' format");

        foreach ($files as $file)
        {
            try
            {
                $file = $this->normalizePath($file);

                if (@file_exists($file) === false)
                    throw new Exception("touch: can't perform stat on '$file': File or directory does not exist");
        
                if (@is_readable($file) === false || @is_writable($file) === false)
                    throw new Exception("touch: can't perform stat on '$file': Permission denied");

                if (@touch($file, $obj_date->getTimestamp()) === false)
                    throw new Exception("touch: file '$file': Failed");
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
                throw new Exception("Invalid arguments provided. Specify datetime and one or multiple files to change date");

            $str_date = $parsed_args[0];
            $files = array_slice($parsed_args, 1);

            $result = $this->doTouch($str_date, $files);
  
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
$module = new Module_touch($cwd);
print($module->execute($args));
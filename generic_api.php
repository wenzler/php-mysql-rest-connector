<?php
/* This MySQL rest API was designed to deal with tables having a numeric primary key present.
   It will otherwise default to use the first column of a table as key for some GET calls.
   Licensed under GPL v3
   Copyright (C) 2019 S Wenzler 
*/


/* Apache setup
<IfModule mod_rewrite.c>
RewriteEngine On
RewriteCond %{REQUEST_FILENAME} !-f
RewriteCond %{REQUEST_FILENAME} !-d
RewriteRule api/v1/(.*)$ /generic_api.php/$1 [QSA,NC,L]
</IfModule>
*/

/* my.cnf
[mysqld]
max_allowed_packet = 1024M
query_cache_size = 1024M
key_buffer_size = 1024M
innodb_log_buffer_size          = 32M
innodb_buffer_pool_size         = 3G
innodb_log_file_size            = 768M
sql_mode = STRICT_TRANS_TABLES,NO_ZERO_IN_DATE,NO_ZERO_DATE,ERROR_FOR_DIVISION_BY_ZERO,NO_AUTO_CREATE_USER,NO_ENGINE_SUBSTITUTION

[mysqldump]
max_allowed_packet = 1024M
*/

/* Database

CREATE TABLE IF NOT EXISTS `api_privs` (
    `Host` char(60) COLLATE utf8_bin DEFAULT NULL,
    `User` char(32) COLLATE utf8_bin DEFAULT NULL,
    `Table_name` char(64) COLLATE utf8_bin NOT NULL DEFAULT '',
    `Grantor` char(93) COLLATE utf8_bin NOT NULL DEFAULT '',
    `Timestamp` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    `Table_priv` set('GET','PUT','POST','DELETE') CHARACTER SET utf8 NOT NULL DEFAULT 'GET'
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_bin COMMENT='API table privileges';


INSERT INTO `api_privs` (`Host`, `User`, `Table_name`, `Grantor`, `Timestamp`, `Table_priv`) VALUES(NULL, NULL, 'apitest', '', '2019-04-18 12:59:30', 'GET,PUT,POST,DELETE');

ALTER TABLE `api_privs`  ADD UNIQUE KEY `api_privs_unique` (`Host`,`User`,`Table_name`);


CREATE TABLE IF NOT EXISTS `apitest` (
    `apitestid` bigint(20) NOT NULL,
    `field1` int(11) NOT NULL,
    `field2` text NOT NULL,
    `field3` varchar(255) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

ALTER TABLE `apitest`  ADD PRIMARY KEY (`apitestid`);

ALTER TABLE `apitest`  MODIFY `apitestid` bigint(20) NOT NULL AUTO_INCREMENT;
*/

// config
define('MYSQL_HOST','127.0.0.1');
define('MYSQL_PORT','');
define('MYSQL_USER','testinguser');
define('MYSQL_PASS','testingpass');
define('MYSQL_DATA','testing');
define('TABLE_SCHEMA','testing');
define('LDAP_SERV', 'ldapserver.local');
define('LDAP_DOMAIN', 'ldapdomain');
define('ADMINMODE', 1);
define('PRODUCT', 'Generic MySQL REST Interface');
define('APITABLE','api_privs');
date_default_timezone_set("Europe/Berlin");
$admins = array("adminuser");
$showaccess = true;
$message='';    
$mysqlrowid='';

// debug options
// ini_set('display_errors', 'On');
// error_reporting(E_ALL | E_STRICT); 

function die_with_http_response_code ($error,$code=500,$json=false) {
	error_reporting(E_ERROR);
	http_response_code($code);
	if ($json) {
		if (is_array($error))
			die(json_encode($error));
		else
			die(json_encode(array("message" => $error)));
	} else die($error);
}

function get_row_results ($sql,$bind_type,$bind_variables,$mysqli,$errorname,$dorowbind=true) {
	if ($stmt = $mysqli->prepare($sql)) {
		switch (count($bind_variables)) {
			case "0":
				break;
			default:
				$params=array_merge(array($bind_type),$bind_variables);
				// now we need to add references
				$tmp = array();
				foreach($params as $key => $value) $tmp[$key] = &$params[$key];
				// now use the new array
				call_user_func_array(array($stmt, 'bind_param'), $tmp);
				break;
		}
		// PHP Notice:  Array to string conversion in /var/www/html/functions.php on line 396 - TOFIX
		if(!$stmt->execute())
			die_with_http_response_code("Query failed [". $errorname . "]: (" . $mysqli->errno . ") " . $mysqli->error);
	} else {
		die_with_http_response_code("Prepare failed [". $errorname . "]: (" . $mysqli->errno . ") " . $mysqli->error);
	}

	if ($dorowbind) {
		$stmt->store_result();
		
		$resultcount = $stmt->num_rows;

		if ($resultcount == 0) {
			return array($stmt,array(), 0);
		}

		$meta = $stmt->result_metadata();
		while ($column = $meta->fetch_field()) {
			$bindVarsArray[] = &$row[$column->name];
		}
		call_user_func_array(array($stmt, 'bind_result'), $bindVarsArray);

		return array($stmt,$row,$resultcount);
	} else {
		$stmt->close();
		return true;
	}
}

function input_array_to_mysql_set_string ($mysqli,$table,$input,$action='INSERT',$debug=false) {
        $error=false;
        list ($error, $columnnames) = get_mysql_table_columns_as_array ($mysqli,$table);
        $bindparamstring="";
        $bindparamarray=array();
        $idname="";
        $set="";
        $set1="";
        $set2="";
        if ( ! $error ) {
                list ( $idname, , $primarykeydetails ) = get_primary_key_from_table($mysqli,$table);
                // Should not be required - TOTEST
                if ($action == 'INSERT' && $primarykeydetails['EXTRA'] == 'auto_increment' ) {
                    $set1 = "`".$idname."`,";
                    $set2 = "DEFAULT,";
                }
                
		foreach (array_keys($input) as $arraykey) {
			if(in_array($arraykey,$columnnames)) {
				if ($action == 'INSERT') {
                                    $set1 .= "`".$arraykey."`,";
                                    $set2 .= "?,";
				} else {
                                    $set .= "`$arraykey`=?,";
                                }
				array_push($bindparamarray, $input[$arraykey]);
				if (is_numeric($input[$arraykey]))
					$bindparamstring .= "i";
				else
					$bindparamstring .= "s";
			} else $error=true;
		}
                if ($action == 'INSERT') {
                    $set1=rtrim($set1,",");
                    $set2=rtrim($set2,",");
                    $set = "($set1) VALUES($set2)";
                }
                $set=rtrim($set,",");
        } else $error=true;
        if ($debug) echo "$set \n $bindparamstring \n ";
        if ($debug) print_r($bindparamarray);
        return (array($error,$idname,$set,$bindparamstring,$bindparamarray));
}

function get_mysql_table_columns_as_array ($mysqli,$table,$table_schema=TABLE_SCHEMA) {
        $error=false;
        $sql='SELECT `COLUMN_NAME` FROM `INFORMATION_SCHEMA`.`COLUMNS` WHERE `TABLE_SCHEMA`=? AND `TABLE_NAME`=?';
        $columnnames=array();
        list ($stmt, $row, $rowcount) = get_row_results($sql,"ss",array($table_schema,$table),$mysqli,"fields");
        if ($rowcount > 0) {
                while($stmt->fetch()) {
			$columnnames[] = $row['COLUMN_NAME'];
		}
        } else $error=true;
        return (array($error,$columnnames));
}

function input_array_to_mysql_where_string ($mysqli,$table,$input) {
        $error=false;
        $where="";
        $options="";
        $idname="";
        $bindparamstring="";
        $bindparamarray=array();

        if ( in_array("QUERY_ENABLE_EXT_COMPARISON",array_keys($input)) )
            $extentedoperators=true;
        else
            $extentedoperators=false;

        if ( in_array("QUERY_CONDITION",array_keys($input)) ) {
            if ( $input['QUERY_CONDITION'] == "OR" )
                $condition="OR";
            else
                $condition="AND";
        }
                
        list ($error, $columnnames) = get_mysql_table_columns_as_array ($mysqli,$table);
        if ( ! $error ) {
                $idname=$columnnames[0];
		foreach (array_keys($input) as $arraykey) {
		        if (fnmatch("QUERY_*", $arraykey)) {
                                switch ($arraykey) {
                                        case "QUERY_CONDITION":
                                                if ($input['QUERY_CONDITION'] == "OR")
                                                    $condition="OR";
                                                break;
                                        case "QUERY_LIMIT":
                                                ctype_digit($input['QUERY_LIMIT']) || $error=true;
                                                $options .= " LIMIT ".$input['QUERY_LIMIT'];
                                                break;
                                        case "QUERY_ORDERBYASC":
                                                in_array($input['QUERY_ORDERBYASC'],$columnnames) || $error=true;
                                                fnmatch("*ORDER BY*", $options) && $error=true; // Just one time
                                                $options = " ORDER BY `".$input['QUERY_ORDERBYASC']."` ASC".$options;
                                                break;
                                        case "QUERY_ORDERBYDESC":
                                                in_array($input['QUERY_ORDERBYDESC'],$columnnames) || $error=true;
                                                fnmatch("*ORDER BY*", $options) && $error=true; // Just one time
                                                $options = " ORDER BY `".$input['QUERY_ORDERBYDESC']."` DESC".$options;
                                                break;
                                        case "QUERY_ENABLE_EXT_COMPARISON":
                                                break;
                                        case "QUERY_CONDITION":
                                                break;
                                        default:
                                                $error=true;
                                                break;
                                }
			} else {
			        $operator="=";
			        if($extentedoperators) {
                                    if(fnmatch(">*",$input[$arraykey])) {
                                            $operator=" > ";
                                            $input[$arraykey]=ltrim($input[$arraykey],">");
                                    } elseif(fnmatch("<*",$input[$arraykey])) {
                                            $operator=" < ";
                                            $input[$arraykey]=ltrim($input[$arraykey],"<");
                                    } elseif(fnmatch("!*",$input[$arraykey])) {
                                            $operator=" <> ";
                                            $input[$arraykey]=ltrim($input[$arraykey],"!");
                                    } elseif(fnmatch("~*",$input[$arraykey])) {
                                            $operator=" LIKE ";
                                            $input[$arraykey]=ltrim($input[$arraykey],"~");
                                    } else	$operator="=";
                                }                                
                                
                                if(in_array($arraykey,$columnnames)) {
                                        $where .= $arraykey.$operator."? $condition ";
                                        array_push($bindparamarray, $input[$arraykey]);
                                        if (is_numeric($input[$arraykey]))
                                                $bindparamstring .= "i";
                                        else
                                                $bindparamstring .= "s";
                                } else $error=true;
			}
		}
		$where=rtrim($where," $condition ");
        } else $error=true;
        if (!empty($where)) $where = " WHERE ".$where;
        if (!empty($options)) $where .= $options;
        return (array($error,$idname,$where,$bindparamstring,$bindparamarray));
}

function check_api_access($mysqli,$table,$method,$host,$accesstable) {
        if (has_admin_session()) return true;
        if ( !isset($_SESSION['u']) || $_SESSION['u'] == "") {
            $sql = "SELECT * FROM `$accesstable` WHERE ( `User` IS NULL OR `Host`=? ) AND `Table_name`=? AND FIND_IN_SET(?,`Table_priv`)>0";
            $bindparamstring="sss";
            $bindparamarray=array($host,$table,$method);
        } else {
            $sql = "SELECT * FROM `$accesstable` WHERE ( `User` IS NULL OR `User`=? OR Host=? ) AND `Table_name`=? AND FIND_IN_SET(?,`Table_priv`)>0";
            $bindparamstring="ssss";
            $bindparamarray=array($_SESSION['u'],$host,$table,$method);
        }
	list ($stmt, $row, $rowcount) = get_row_results($sql,$bindparamstring,$bindparamarray,$mysqli,$accesstable);
	if ( $rowcount == 0)
	    return false;
	else
	    return true;
}

function get_datatype_from_column($mysqli,$table,$column,$table_schema=TABLE_SCHEMA) {
        $sql='SELECT * FROM `INFORMATION_SCHEMA`.`COLUMNS` WHERE `TABLE_SCHEMA`=? AND `TABLE_NAME`=? AND `COLUMN_NAME`=?';
        list ($stmt, $row, $rowcount) = get_row_results($sql,"sss",array($table_schema,$table,$column),$mysqli,"fields");
        if ($rowcount == 1) {
            $stmt->fetch();
            $stmt->close();
            $datatype=$row['DATA_TYPE'];
            switch ($datatype) {
                    case "tinyint":
                    case "smallint":
                    case "int":
                    case "bigint":
                    case "int":
                        $inputtype="i";
                        break;
                    case "double":
                        $inputtype="d";
                        break;
                    default:
                        $inputtype="s";
                        break;
            }
            return $inputtype;
        } else return NULL;
}

function get_primary_key_from_table($mysqli,$table,$table_schema=TABLE_SCHEMA) {
    list ($error, $columnnames) = get_mysql_table_columns_as_array ($mysqli,$table);
    if ( $error )
        return array('','','');
    
    $sql = "SHOW KEYS FROM `$table` WHERE Key_name='PRIMARY'";
    list ($stmt, $row, $rowcount) = get_row_results($sql,"",array(),$mysqli,"get primary key");
    if ( $rowcount == 0)
        $idname=$columnnames[0];
    else {
        $stmt->fetch();
        $stmt->close();
        $idname=$row['Column_name'];
    }
    $inputtype=get_datatype_from_column($mysqli,$table,$idname,$table_schema);
    if (empty ($inputtype)) return array('','','');
    else return array($idname,$inputtype,$row);
}

function has_admin_session() {
	if ( !isset($_SESSION['a']) || $_SESSION['a'] != ADMINMODE)
		return false;
	else
		return true;
}

function is_active_admin($user,$admins) {
        return in_array($user, $admins); 
}

function database_connect($host=MYSQL_HOST,$user=MYSQL_USER,$pass=MYSQL_PASS,$db=MYSQL_DATA) {
	$mysqli = new mysqli ($host,$user,$pass,$db);
	if ($mysqli->connect_errno) {
	    die( "Failed to connect to MySQL: (" . $mysqli->connect_errno . ") " . $mysqli->connect_error);
	}
	$stmt = $mysqli->stmt_init();
	return array ($mysqli, $stmt);
}

function database_close($mysqli, $stmt) {
	$stmt->close();
	$mysqli->close();
}

// get the HTTP method, path and body of the request
isset($_SERVER['REMOTE_ADDR']) || die("REMOTE_ADDR not set");
isset($_SERVER['REQUEST_METHOD']) || die("missing/invalid input");
$method = $_SERVER['REQUEST_METHOD'];
$request = explode('/', trim($_SERVER['PATH_INFO'],'/'));
$input = json_decode(file_get_contents('php://input'),true);
$arguments = count($request);

// retrieve the table and key from the path
if ($arguments != 0) {
    $table = preg_replace('/[^a-z0-9_]+/i','',array_shift($request));
    if (empty($table)) {
        echo "Welcome to ".sprintf("%s",PRODUCT)." REST API<br /><br />";
        echo "This API supports GET, POST, DELETE and PUT operations.<br />";
        echo "To access specific tables/views go to e.g. <a href='".$_SERVER['REQUEST_URI']."/tablename'>".$_SERVER['REQUEST_URI']."/tablename</a><br />";
        echo "<br />GET parameters supported:<br />";
        echo "<pre>
        	&columnname=value
        	&QUERY_LIMIT=integerlimit
        	&QUERY_CONDITION=[OR|AND] default is AND; can only be used once
        	&QUERY_ORDERBYASC=columnname OR &QUERY_ORDERBYDESC=columnname (single use only)
        	&QUERY_ENABLE_EXT_COMPARISON enables extra comparison operators:
                    &columnname=~value using LIKE ( % need to be url encoded as %25 )
                    &columnname=!value using <>
                    &columnname=&gt;value using > 
                    &columnname=&lt;value using <
        </pre>";
        echo "<br />POST/PUT expects json encoded data via php://input<br />";
        echo "<pre>
                curl -u \$USER -i -X PUT -H \"Content-Type:application/json\" https://".$_SERVER['SERVER_NAME'].$_SERVER['REQUEST_URI']."/tablename/id -d '{\"field1\":1,\"field2\":\"data\"}'
                curl -u \$USER -i -X POST -H \"Content-Type:application/json\" https://".$_SERVER['SERVER_NAME'].$_SERVER['REQUEST_URI']."/tablename -d '{\"field1\":1,\"field2\":\"data\"}'
        </pre>";
        echo "<br />DELETE parameters supported:<br />";
        echo "<pre>
                curl -u \$USER -i -X DELETE https://".$_SERVER['SERVER_NAME'].$_SERVER['REQUEST_URI']."/tablename/id
        </pre>";
        echo "<br />Response codes:<br />";
        echo "<pre>
                200: Everything went fine.
                201: Entry created.
                202: Job created for processing.
                204: Query has no results returned.
                400: You sent a request we didn't understand. Correct the input and try again.
                401: You're not authenticated.
                403: You're not authorized to do this.
                404: The URI doesn't exist.
        </pre>";
        if ($showaccess) {
            echo "<br />Your table access:<br />";
            list ($mysqli, $stmt) = database_connect();
            $sql = sprintf("SELECT * FROM `%s` WHERE ( `User` IS NULL OR `User`=? OR Host=? )",APITABLE);
            $bindparamstring="ss";
            if (isset($_SESSION['u']))
                $queryuser=$_SESSION['u'];
            else
                $queryuser='';
            $bindparamarray=array($queryuser,$_SERVER['REMOTE_ADDR']);
            list ($stmt, $row, $rowcount) = get_row_results($sql,$bindparamstring,$bindparamarray,$mysqli,APITABLE);
            echo "<pre>\n";
            while($stmt->fetch()) {
                echo "                <a href='".$_SERVER['REQUEST_URI']."/".$row['Table_name']."/'>".$row['Table_name']."</a>: ".$row['Table_priv']."\n";
            }
            echo "</pre>\n";
        }
        die_with_http_response_code("",400,false);
    }
}
if ($arguments > 1)
    $key = preg_replace('/[^a-z0-9_]+/i','',array_shift($request));
else
    $key = 0;

list ($mysqli, $stmt) = database_connect();
session_start();

if (isset($_SESSION['LAST_ACTIVITY']) && (time() - $_SESSION['LAST_ACTIVITY'] > 100000)) {
    // last request was more than 1 day ago
    session_unset();     // unset $_SESSION variable for the run-time 
    session_destroy();   // destroy session data in storage
}
$_SESSION['LAST_ACTIVITY'] = time(); // update last activity time stamp

if (!isset($_SESSION['CREATED'])) {
    $_SESSION['CREATED'] = time();
} else if (time() - $_SESSION['CREATED'] > 3600) {
    // session started more than 1 hours ago
    session_regenerate_id(true);    // change session ID for the current session and invalidate old session ID
    $_SESSION['CREATED'] = time();  // update creation time
}

if (!check_api_access($mysqli,$table,$method,$_SERVER['REMOTE_ADDR'],APITABLE)) {
    if(isset($_SERVER['PHP_AUTH_USER']) && isset($_SERVER['PHP_AUTH_PW'])){
	$adServer = "ldaps://".sprintf('%s', LDAP_SERV);
	$ldap = ldap_connect($adServer);
	
	$username = strtolower($_SERVER['PHP_AUTH_USER']);
	$password = $_SERVER['PHP_AUTH_PW'];;
	$ldaprdn = sprintf('%s', LDAP_DOMAIN)."\\".$username;

	ldap_set_option($ldap, LDAP_OPT_PROTOCOL_VERSION, 3);
	ldap_set_option($ldap, LDAP_OPT_REFERRALS, 0);

	$bind = @ldap_bind($ldap, $ldaprdn, $password);
	if ($bind && !empty($password)) {
		$_SESSION['u'] = $username;		
		if (is_active_admin($username,$admins))
			$_SESSION['a'] = 1;
		@ldap_close($ldap);
	} else {
            header(sprintf('WWW-Authenticate: Basic realm="%s API"',PRODUCT));
            header('HTTP/1.0 401 Unauthorized');
            die('{"message":"login failed"}');
	}
    } else {
        header(sprintf('WWW-Authenticate: Basic realm="%s API"',PRODUCT));
        header('HTTP/1.0 401 Unauthorized');
        die('{"message":"unauthorized"}');
    }
}

header('Content-Type: application/json');

if (!check_api_access($mysqli,$table,$method,$_SERVER['REMOTE_ADDR'],APITABLE))
    die_with_http_response_code("unauthorized",401,true);

// create SQL based on HTTP method
switch ($method) {
case 'GET': 
    if ($key) {
        list ( $idname, $bindparamstring, ) = get_primary_key_from_table($mysqli,$table);
        (empty($idname)) && die_with_http_response_code("could not get primary key name",500,true); 
        $bindparamarray=array($key);
        $sql = "SELECT * FROM `".$table."` WHERE `".$idname."`=?";
    } else {
        $sql = "SELECT * FROM `".$table."`";
        if (!empty($_GET)) {
            list ($error,$idname,$where,$bindparamstring,$bindparamarray) = input_array_to_mysql_where_string ($mysqli,$table,$_GET);
            if ( $error ) 
                die_with_http_response_code("missing/invalid input",400,true);
            else
                $sql .= $where;
        } else {
            $bindparamstring="";
            $bindparamarray=array();
        }
    }
    break;
case 'PUT':
    $error=false;
    is_numeric($key) || $error=true;
    if (empty($input)) die_with_http_response_code("missing or faulty json input",400,true);
    list ($error,$idname,$set,$bindparamstring,$bindparamarray) = input_array_to_mysql_set_string ($mysqli,$table,$input,'UPDATE');
    if (empty($input) || $error)
        die_with_http_response_code("missing/invalid input",400,true);

    array_push($bindparamarray, $key);
    $bindparamstring .= "i";
    $sql = "UPDATE `".$table."` SET $set WHERE `".$idname."`=?";
    break;
case 'POST':
    $error=false;
    $uid = $key;
    $set = "";
    // input verification
    if (empty($input)) die_with_http_response_code("missing or faulty json input",400,true);
    list ($error,$idname,$set,$bindparamstring,$bindparamarray) = input_array_to_mysql_set_string ($mysqli,$table,$input);
    $sql = "INSERT INTO `$table` $set";

    if (empty($input) || $error)
        die_with_http_response_code("missing/invalid input",400,true);
    break;
case 'DELETE':
    $error=false;
    $uid = $key;
    is_numeric($key) || $error = true;
    list ( $idname, $bindparamstring, ) = get_primary_key_from_table($mysqli,$table);
    $bindparamarray=array($key);
    $sql = "DELETE FROM `$table` WHERE `$idname`=?";

    if ($error)
        die_with_http_response_code("missing/invalid input",400,true);
    break;
default:
    die_with_http_response_code("invalid method",401,true);
} 

// excecute SQL statement
list ($stmt, $row, $rowcount) = get_row_results($sql,$bindparamstring,$bindparamarray,$mysqli,"$table");

// die if SQL statement failed
if (!$stmt) {
    die_with_http_response_code(str_replace(':','',mysqli_error($mysqli)),400,true);
}
// print results, insert id or affected row count
if ($method == 'GET') {
    // TOFIX - returns nothing but the 204 code
    if (!$rowcount)
        die_with_http_response_code("no results",204,true);
    if ($rowcount > 1) echo '[';
    $i=0;
    while ($stmt->fetch()) {
        echo ($i>0?',':'').json_encode($row);
        $i++;
    }
    if ($rowcount > 1) echo ']';
} elseif ($method == 'POST') {
    $mysqlrowid=mysqli_insert_id($mysqli);
    echo '[{"message":"success","id":"'.$mysqlrowid.'"},'.$message.']';
} else {
    $mysqlrowid=mysqli_affected_rows($mysqli);
    echo '[{"message":"success","updates":"'.$mysqlrowid.'"},'.$message.']';
}

// error_log("API: ".$method." table:".$table."/".$key." input:".json_encode($input)." id:".$mysqlrowid." message:".json_encode($message)."\n", 3, "/var/www/log/api.log");
// close mysql connection
database_close($mysqli, $stmt);
?>

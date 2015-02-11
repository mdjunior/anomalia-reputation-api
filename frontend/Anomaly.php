<?php

/*
 * Frontend plugin: anomaly 
 *
 * Required functions: anomaly_ParseInput and anomaly_Run
 *
 */

/* 
 * anomaly_ParseInput is called prior to any output to the web browser 
 * and is intended for the plugin to parse possible form data. This 
 * function is called only, if this plugin is selected in the plugins tab. 
 * If required, this function may set any number of messages as a result 
 * of the argument parsing.
 * The return value is ignored.
 */
function Anomaly_ParseInput( $plugin_id ) {

	#SetMessage('error', "Error set by demo plugin!");
	#SetMessage('warning', "Warning set by demo plugin!");
	#SetMessage('alert', "Alert set by demo plugin!");
	#SetMessage('info', "Info set by demo plugin!");

} // End of anomaly_ParseInput


/*
 * This function is called after the header and the navigation bar have 
 * are sent to the browser. It's now up to this function what to display.
 * This function is called only, if this plugin is selected in the plugins tab
 * Its return value is ignored.
 */
function Anomaly_Run( $plugin_id ) {

	print "<h3>Anomaly to reputation::api</h3>\n";
	print "For more information about this plugin and how it works go to 
		<a href='https://github.com/mdjunior/anomalia-reputation-api'>https://github.com/mdjunior/anomalia-reputation-api<a>\n<br><br>";

	// prepare arguments
	$opts = array();
	$opts['src'] = $_SERVER['REMOTE_ADDR'];

	// call command in backened plugin
    $out_list = nfsend_query('Anomaly::status', $opts);

	// get result
    if ( !is_array($out_list) ) {
        SetMessage('error', "Error calling backend plugin");
        return FALSE;
    }
	$status = $out_list['status'];
	$endpoint = $out_list['endpoint'];
	$ports_file = $out_list['ports_file'];
	$threshold = $out_list['threshold'];

	print "<br>Backend status: <b>$status</b><br>\n";
	print "<br>Reputation::api Endpoint: <b>$endpoint</b><br>\n";
	print "<br>Ports File: <b>$ports_file</b><br>\n";
	print "<br>Threshold config: <b>$threshold</b><br>\n";

} // End of anomaly_Run


?>

<?php
/**
*
* License:
*
* Copyright (c) 2003-2006 ossim.net
* Copyright (c) 2007-2015 AlienVault
* All rights reserved.
*
* This package is free software; you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation; version 2 dated June, 1991.
* You may not use, modify or distribute this program under any other version
* of the GNU General Public License.
*
* This package is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this package; if not, write to the Free Software
* Foundation, Inc., 51 Franklin St, Fifth Floor, Boston,
* MA  02110-1301  USA
*
*
* On Debian GNU/Linux systems, the complete text of the GNU General
* Public License can be found in `/usr/share/common-licenses/GPL-2'.
*
* Otherwise you can read it here: http://www.gnu.org/licenses/gpl-2.0.txt
*
*/


//
// $Id: sched.php,v 1.17 2010/04/21 15:22:39 josedejoses Exp $
//

/***********************************************************/
/*                    Inprotect                            */
/* --------------------------------------------------------*/
/* Copyright (C) 2006 Inprotect                            */
/*                                                         */
/* This program is free software; you can redistribute it  */
/* and/or modify it under the terms of version 2 of the    */
/* GNU General Public License as published by the Free     */
/* Software Foundation.                                    */
/* This program is distributed in the hope that it will be */
/* useful, but WITHOUT ANY WARRANTY; without even the      */
/* implied warranty of MERCHANTABILITY or FITNESS FOR A    */
/* PARTICULAR PURPOSE. See the GNU General Public License  */
/* for more details.                                       */
/*                                                         */
/* You should have received a copy of the GNU General      */
/* Public License along with this program; if not, write   */
/* to the Free Software Foundation, Inc., 59 Temple Place, */
/* Suite 330, Boston, MA 02111-1307 USA                    */
/*                                                         */
/* Contact Information:                                    */
/* inprotect-devel@lists.sourceforge.net                   */
/* http://inprotect.sourceforge.net/                       */
/***********************************************************/
/* See the README.txt and/or help files for more           */
/* information on how to use & config.                     */
/* See the LICENSE.txt file for more information on the    */
/* License this software is distributed under.             */
/*                                                         */
/* This program is intended for use in an authorized       */
/* manner only, and the author can not be held liable for  */
/* anything done with this program, code, or items         */
/* discovered with this program's use.                     */
/***********************************************************/

require_once 'av_init.php';
require_once 'config.php';
require_once 'functions.inc';

Session::logcheck('environment-menu', 'EventsVulnerabilitiesScan');

$db   = new ossim_db();
$conn = $db->connect();

$conn->SetFetchMode(ADODB_FETCH_BOTH);

// check the number of plugins

$query  = 'select count(*) as total_plugins from vuln_nessus_plugins';

$result = $conn->execute($query);

if ($result->fields['total_plugins'] == 0)
{
   die ('<h2>Please run updateplugins.pl script first before using web interface.</h2>');
}


$tz    = Util::get_timezone();

$force = FALSE;
$close = FALSE;

// get parameters

$parameters = array('action', 'job_name', 'targets', 'schedule_type', 'ROYEAR', 'ROMONTH', 'ROday', 'time_hour',
                    'time_min', 'dayofweek', 'dayofmonth', 'timeout', 'SVRid', 'sid', 'targets', 'job_id',
                    'sched_id', 'user', 'entity', 'hosts_alive','scan_locally', 'nthweekday', 'nthdayofweek',
                    'time_interval', 'biyear', 'bimonth', 'biday', 'not_resolve', 'send_email', 'ssh_credential',
                    'smb_credential', 'hosts_alive', '$scan_locally', 'not_resolve', 'type', 'total_assets');
                     
foreach ($parameters as $variable)
{
    $$variable = REQUEST($variable);
}

$hosts_alive   = intval($hosts_alive);
$scan_locally  = intval($scan_locally);
$not_resolve   = intval($not_resolve);
$send_email    = intval($send_email);
$total_assets  = intval($total_assets);

$scheduled_status =  ($_REQUEST['status'] != '') ? intval($_REQUEST['status']) : 1; // enable scheduled jobs by default

ossim_valid($action, 'create_scan', 'save_scan', OSS_NULLABLE, 'Illegal:'._('Action'));

if (ossim_error())
{
    die(_('Invalid Action Parameter'));
}

$selected = Filter_list::get_total_selection($conn, $type);

if ($selected > Filter_list::MAX_VULNS_ITEMS)
{
    $msg       = _('Vulnerability scans can only be performed on %s assets at a time. Please select less assets and try again.');
    $limit_msg = sprintf($msg, Util::number_format_locale(Filter_list::MAX_VULNS_ITEMS));
}


if (!$limit_msg && in_array ($action, array ('create_scan', 'save_scan')))
{
    // load the default values for the form
    if ($action == 'create_scan')
    {
        $conf         = $GLOBALS['CONF'];
        $scan_locally = $conf->get_conf('nessus_pre_scan_locally');
        $timeout      = 28800;
        $hosts_alive  = 1;
    }
    
    $hosts_alive_data        = get_host_alive_attributes($hosts_alive, $targets);
    
    $scan_locally_checked    = ($scan_locally == 1) ? 'checked="checked"' : '';
    $resolve_names_checked   = ($not_resolve  == 1) ? 'checked="checked"' : '';
    
    $email_notification = array();
    
    $email_notification['no']  = ($send_email == 0) ? 'checked="checked"' : '';
    $email_notification['yes'] = ($send_email == 1) ? 'checked="checked"' : '';;
    
    // load sensors
    
    $filters = array('where' => 'sensor_properties.has_vuln_scanner = 1');
    
    list($all_sensors, $s_total) = Av_sensor::get_list($conn);
    
    foreach ($all_sensors as $_sensor_id => $sensor_data)
    {        
        $all_sensors[$_sensor_id]['selected'] = ($_sensor_id == $SVRid) ? 'selected="selected"' : '';
    }
    
    // load profiles
    
    $args = '';
    
    if (!Session::am_i_admin())
    {
        list($owners, $sqlowners) = Vulnerabilities::get_users_and_entities_filter($conn);
        $owners[]   = '0';
        $sql_perms .= " OR owner IN('".implode("', '",$owners)."')";

        $args = "WHERE name='Default' OR name='Deep' OR name='Ultimate' ".$sql_perms;
    }

    $query = "SELECT id, name, description, owner, type FROM vuln_nessus_settings $args ORDER BY name";

    $conn->SetFetchMode(ADODB_FETCH_BOTH);

    $result = $conn->execute($query);
    
    while (!$result->EOF)
    {
        $p_description = ($result->fields['description'] != '') ? ' - ' . $result->fields['description'] : '';
        
        $v_profiles[$result->fields['id']]['name&description'] = $result->fields['name'] . $p_description;
        
        if (($sid == '' && $result->fields['name'] == 'Default') || $result->fields['id'] == $sid)
        {
            $v_profiles[$result->fields['id']]['selected'] = 'selected="selected"';
        }
        
        $result->MoveNext();
    }
    
    // load users and entities
    
    $users           = Session::get_users_to_assign($conn);
    $users_to_assign = array();
    
    foreach ($users as $u_key => $u_value)
    {
        $users_to_assign[$u_value->get_login()]['selected'] = ($u_value->get_login() == $user) ? 'selected="selected"' : '';
        $users_to_assign[$u_value->get_login()]['name']     = $u_value->get_login();
    }
    
    $entities           = Session::get_entities_to_assign($conn);
    $entities_to_assign = array();
    
    foreach ($entities as $e_key => $e_value) 
	{
    	$entities_to_assign[$e_key]['selected'] = ($e_key == $entity) ? 'selected="selected"' : '';
    	$entities_to_assign[$e_key]['name']     = $e_value;
	}
	
	// load credentials
    
    $ssh_cred = Vulnerabilities::get_credentials($conn, 'ssh');
    $ssh_arr  = array();
        
    foreach ($ssh_cred as $cred) 
	{	
    	$login_text = $cred['login'];
    			
		if ($login_text == '0' || valid_hex32($login_text))
		{
			$login_text =  ($login_text=='0') ? _('All') : Session::get_entity_name($conn, $cred['login']);	
		}
		
		$cred_key = $cred['name'].'#'.$cred['login'];
		
        $ssh_arr[$cred_key]['selected'] = ($cred_key == $ssh_credential) ? 'selected="selected"' : '';
        $ssh_arr[$cred_key]['name']     = $cred['name'] . ' (' . $login_text . ')';
    }
    
    $smb_cred = Vulnerabilities::get_credentials($conn, 'smb');
    $smb_arr  = array();
        
    foreach ($smb_cred as $cred) 
	{			
    	$login_text = $cred['login'];
    	
		if ($login_text == '0' || valid_hex32($login_text))
		{
			$login_text =  ($login_text=='0') ? _('All') : Session::get_entity_name($conn, $cred['login']);	
		}
		
		$cred_key = $cred['name'].'#'.$cred['login'];
		
        $smb_arr[$cred_key]['selected'] = ($cred_key == $smb_credential) ? 'selected="selected"' : '';
        $smb_arr[$cred_key]['name']     = $cred['name'] . ' (' . $login_text . ')';
    }
    
    // fill targets
    
    // array to fill the hidden field with the targets
    $targets_list = array();
    
    // array to fill the message when the window is closed
    $asset_list   = array();
    
    if (empty($targets) == FALSE)
    {
        $select_targets = get_targets($conn, $targets);
    }
    else
    {
        // load selected hosts and nets
        
        if ($type == 'asset' || $type == 'network')
        {
            $params = array(session_id());
        
            if ($type == 'asset')
            {
                $host_perms_where = Asset_host::get_perms_where('h.', TRUE);

                $sql = "SELECT hex(hi.host_id) as id, INET6_NTOA(hi.ip) as ip FROM user_component_filter uf, host h, host_ip hi
                WHERE uf.session_id=? AND h.id=hi.host_id AND uf.asset_id=hi.host_id AND uf.asset_type='asset' $host_perms_where";

            }
            else
            {
                $net_perms_where  = Asset_net::get_perms_where('n.', TRUE);
        
                $sql = "SELECT hex(n.id) as id, nc.cidr as ip FROM user_component_filter uf, net n, net_cidrs nc
                WHERE uf.session_id=? AND uf.asset_id=n.id AND n.id=nc.net_id AND uf.asset_type='network' $net_perms_where";
            }
            
            $rs = $conn->Execute($sql, $params);

            if (!$rs)
            {
                Av_exception::throw_error(Av_exception::DB_ERROR, $conn->ErrorMsg());
            }
            
            while (!$rs->EOF)
            {
                $targets_list[] = $rs->fields['id'] . '#' . $rs->fields['ip'];
                
                $asset_list[]   = array('id' => $rs->fields['id'], 'ip' => $rs->fields['ip']);
                
                $rs->MoveNext();
            }
        
        }
        else if ($type == 'group')
        {
            // load assets groups
            
            $sql = "SELECT hex(uf.asset_id) as gid FROM user_component_filter uf
                    WHERE uf.session_id=? AND uf.asset_type='group'";
            
            $params = array(session_id());
            
            $rs = $conn->Execute($sql, $params);
    
            if (!$rs)
            {
                Av_exception::throw_error(Av_exception::DB_ERROR, $conn->ErrorMsg());
            }
            
            while (!$rs->EOF)
            {
                $targets_list[] = $rs->fields['gid'] . '#hostgroup';
                
                $rs->MoveNext();
            }
            
            // load group assets
            
            $sql = "SELECT hex(hi.host_id) as id, INET6_NTOA(hi.ip) as ip FROM user_component_filter uf, host h, host_ip hi, host_group_reference hgr WHERE h.id=hi.host_id AND uf.session_id=? AND uf.asset_id=hgr.host_group_id AND hgr.host_id=hi.host_id AND uf.asset_type='group' $host_perms_where";
            
            $params = array(session_id());
            
            $rs = $conn->Execute($sql, $params);
    
            if (!$rs)
            {
                Av_exception::throw_error(Av_exception::DB_ERROR, $conn->ErrorMsg());
            }
            
            while (!$rs->EOF)
            {
                $asset_list[]   = array('id' => $rs->fields['id'], 'ip' => $rs->fields['ip']);
                
                $rs->MoveNext();
            }
        }
        
        $select_targets = get_targets($conn, $targets_list);
    }
    
    // Schedule data
    
    $daysMap = array (
        'Su' => array('text' => _('Sunday'),    'number' => '0'),
        'Mo' => array('text' => _('Monday'),    'number' => '1'),
        'Tu' => array('text' => _('Tuesday'),   'number' => '2'),
        'We' => array('text' => _('Wednesday'), 'number' => '3'),
        'Th' => array('text' => _('Thursday'),  'number' => '4'),
        'Fr' => array('text' => _('Friday'),    'number' => '5'),
        'Sa' => array('text' => _('Saturday'),  'number' => '6'),
    );
    
    $nweekday = array(
        '1' =>  array('text' =>  _('First'), 'selected' => 'selected="selected"'),
        '2' =>  array('text' =>  _('Second')),
        '3' =>  array('text' =>  _('Third')),
        '4' =>  array('text' =>  _('Fourth')),
        '5' =>  array('text' =>  _('Fifth')),
        '6' =>  array('text' =>  _('Sixth')),
        '7' =>  array('text' =>  _('Seventh')),
        '8' =>  array('text' =>  _('Eighth')),
        '9' =>  array('text' =>  _('Ninth')),
        '10' => array('text' =>  _('Tenth'))
    );
    
    $s_methods = array(
        'N'   => array('name' => _('Immediately')),
        'O'   => array('name' => _('Run Once')),
        'D'   => array('name' => _('Daily')),
        'W'   => array('name' => _('Day of the Week')),
        'M'   => array('name' => _('Day of the Month')),
        'NW'  => array('name' => _('N<sup>th</sup> week of the month'))
    );
    
    // date to fill the form
    
    // default values
    
    $nextscan = gmdate('Y-m-d H:i:s w', gmdate('U') + 3600*$tz);
        
    preg_match('/(\d+)\-(\d+)\-(\d+)\s(\d+):(\d+):(\d+)\s(\d)/', $nextscan, $found);
        
    $current_year       = $found[1];
    $selected_year      = $found[1];
    
    $current_month      = $found[2];
    $selected_month     = $found[2];
    
    $current_day        = ltrim($found[3], '0');
    $selected_day       = ltrim($found[3], '0');
        
    $selected_time_hour = ltrim($found[4], '0');
    $selected_time_min  = ltrim($found[5], '0');
    
    $selected_week_day  = $found[7];
        
    $selected_frequency = 1;

    if ($action == 'save_scan')
    {   
        if ($schedule_type == 'O')
        {
            $selected_year  = $ROYEAR;
            $selected_month = $ROMONTH;
            $selected_day   = $ROday;
        }
        else
        {
            $selected_year  = $biyear;
            $selected_month = $bimonth;
            $selected_day   = $biday;
        }
        
        if ($schedule_type == 'W')
        {
            $selected_week_day  = $daysMap[$dayofweek]['number'];
        }
        else if ($schedule_type == 'NW')
        {
            $selected_week_day  = $daysMap[$nthdayofweek]['number'];
        }
        
        if ($schedule_type == 'M')
        {
            $selected_dayofmonth = $dayofmonth;
        }
        
        $selected_time_hour = $time_hour;
        $selected_time_min  = $time_min;
        
        $selected_nweekday  = $nthweekday;
        
        $selected_frequency = $time_interval;
        
        foreach ($s_methods as $m => $method_data)
        {
            $s_methods[$m]['selected'] = ($m == $schedule_type) ? 'selected="selected"' : '';
        }
    }

    // day of week
    
    foreach ($daysMap as $d => $day_data)
    {
        $daysMap[$d]['selected'] = ($day_data['number'] == $selected_week_day) ? 'selected="selected"' : '';
    }
    
    // hour and time
    
    $hours = array();
     
    for ($i=0;$i<=23;$i++)
    {
        $hours[$i]['selected'] = ($i == $selected_time_hour) ? 'selected="selected"' : '';
    }
    
    $minutes = array();
    
    for ($i=0;$i<60;$i=$i+15)
    {
        $minutes[$i]['selected'] = ($i == $selected_time_min) ? 'selected="selected"' : '';
    }
    
    // Years
    
    for ($i=$current_year;$i<=$current_year+1;$i++)
    {                                          
        $years[$i]['selected'] = ($i == $selected_year) ? 'selected="selected"' : '';
    }
        
    // Months
    
    $months = array();
    
    for($i=1;$i<=12;$i++)
    {
        $months[$i]['selected'] = ($i == $selected_month) ? 'selected="selected"' : '';
    }
        
    // Days
    
    $days = array();
    
    for($i=1;$i<=31;$i++)
    {
        $days[$i]['selected'] = ($i == $selected_day) ? 'selected="selected"' : '';
    }
    
    // Days of month, another array is needed
    
    $days_of_month = array();
    
    for($i=1;$i<=31;$i++)
    {
        $days_of_month[$i]['selected'] = ($i == $selected_dayofmonth) ? 'selected="selected"' : '';
    }
    
    // Time interval
    
    $frequencies = array();
    
    for ($i=1;$i<=30;$i++)
    {
        $frequencies[$i]['selected'] = ($i == $selected_frequency) ? 'selected="selected"' : '';
    }
    
    foreach ($nweekday as $number => $data)
    {
        $nweekday[$number]['selected'] = ($number == $selected_nweekday) ? 'selected="selected"' : '';
    }
}

if ($action == 'save_scan')
{   
    // validate fields
    
    $validation_errors = array();
    
    if ($timeout == '') {
        $validation_errors[] = _('Invalid Timeout');
    }
    
    ossim_valid($job_name, OSS_SCORE, OSS_ALPHA, OSS_SPACE, 'illegal:' . _('Job name'));
    if (ossim_error()) {
        $force = TRUE;
        $validation_errors[] = _('Invalid Job name');
    }
    
    ossim_set_error(FALSE);
    ossim_valid($entity, OSS_NULLABLE, OSS_HEX, 'illegal:' . _('Entity'));
    if (ossim_error()) {
        $validation_errors[] = _('Invalid entity');
    }
    ossim_set_error(FALSE);
    ossim_valid($net_id, OSS_NULLABLE, OSS_HEX, 'illegal:' . _('Net ID'));
    if (ossim_error()) {
        $validation_errors[] = _('Invalid Net ID');
    }
    
    ossim_set_error(FALSE);
    ossim_valid($user, OSS_SCORE, OSS_NULLABLE, OSS_ALPHA, OSS_SPACE, '\.', 'illegal:' . _('User'));
    if (ossim_error()) {
        $validation_errors[] = _('Invalid user');
    }
    
    ossim_set_error(FALSE);
    ossim_valid($timeout, OSS_DIGIT, OSS_NULLABLE, 'illegal:' . _('Timeout'));
    if (ossim_error()) {
        $validation_errors[] = _('Invalid timeout');
    }
    
    ossim_set_error(FALSE);
    ossim_valid($ssh_credential, OSS_USER, OSS_SPACE, OSS_AT, '#', OSS_NULLABLE, 'illegal:' . _("SSH Credential"));
    if (ossim_error()) {
        $validation_errors[] = _('Invalid SSH Credential');
    }
    
    ossim_set_error(FALSE);
    ossim_valid($smb_credential, OSS_USER, OSS_SPACE, OSS_AT, '#', OSS_NULLABLE, 'illegal:' . _("SMB Credential"));
    if (ossim_error()) {
        $validation_errors[] = _('Invalid SMB Credential');
    }
    
    $tip_target         = array();
    
    if(empty($targets)) { $targets = array(); }
    
    foreach($targets as $target) {
        $target_error = FALSE;
        $target = trim($target);
        
        if (!preg_match("/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(\/\d+)?|hostgroup|netgroup$/",$target)) {
            ossim_valid($target, OSS_FQDNS , 'illegal: Host name'); // asset id
    
            if (ossim_error()) {
                $target_error   = TRUE;
                $validation_errors[] = _('Invalid asset id'). ': ' . $asset_id;
            }
            else {
                $tip_target[] = $target;
            }
        }
        else if (preg_match("/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(\/\d{1,2})?$/", $target)){
            $tip_target[] = $target;
        }
        else {
            
            list($asset_id, $ip_target) = explode("#", $target);
                
            ossim_set_error(FALSE);
            ossim_valid($asset_id, OSS_HEX, OSS_NULLABLE , 'illegal: Asset id'); // asset id
            
            if (ossim_error()) {
                $target_error   = FALSE;
                $validation_errors[] = _('Invalid asset id') . ': ' . $asset_id;
            }
    
            ossim_set_error(FALSE);
            ossim_valid($ip_target, OSS_NULLABLE, OSS_DIGIT, OSS_SPACE, OSS_SCORE, OSS_ALPHA, OSS_PUNC, '\.\,\/\!', 'illegal:' . _("Target"));
            if (ossim_error()) {
                $target_error   = FALSE;
                $validation_errors[] = _('Invalid target') . ': '. $ip_target;
            }
            if(!$target_error) {
                $tip_target[] = str_replace('!', '', $target);
            }
        }
    }
    
    $ip_list = $tip_target;
    
    // validated targets
    
    if (count($tip_target)==0)
    { 
        $validation_errors[] = _('Invalid Targets');
    }
    
    if(empty($validation_errors))
    {     
        // save the scan data
        
        submit_scan($SVRid, $job_name, $ssh_credential, $smb_credential, $schedule_type, $not_resolve, $user, $entity, $targets, $scheduled_status,
                    $hosts_alive, $sid, $send_email, $timeout, $scan_locally, $dayofweek, $dayofmonth, $ROYEAR, $ROMONTH, $ROday, $time_hour, $time_min,
                    $time_interval, $sched_id, $biyear, $bimonth, $biday, $nthweekday, $tz, $daysMap);
                    
        $close = TRUE;
    }
}

$db->close($conn);

?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html>
<head>
	<title> <?php echo gettext('Vulnmeter'); ?> </title>
	<meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1"/>
	<meta http-equiv="Pragma" content="no-cache"/>
	<?php
    //CSS Files
    $_files = array(
        array('src' => 'av_common.css',  'def_path' => TRUE),
        array('src' => 'jquery-ui.css',  'def_path' => TRUE),

    );
    
    Util::print_include_files($_files, 'css');

    //JS Files
    $_files = array(
        array('src' => 'jquery.min.js',    'def_path' => TRUE),
        array('src' => 'jquery-ui.min.js', 'def_path' => TRUE),
        array('src' => 'utils.js',         'def_path' => TRUE),
        array('src' => 'notification.js',  'def_path' => TRUE),
        array('src' => 'combos.js',        'def_path' => TRUE),
        array('src' => 'vulnmeter.js',     'def_path' => TRUE),
    );
    
    Util::print_include_files($_files, 'js');
    ?>
    
	<script type="text/javascript">
    	
        function close_window(usehide)
        {
            if (usehide && typeof parent.GB_hide == 'function')
            {
                <?php
                    if ($schedule_type == 'N')
                    {
                        $message = sprintf(_('Vulnerability scan in progress for (%s) assets'), $total_assets);
                    }
                    else
                    {
                        $message = sprintf(_('Vulnerability scan has been scheduled on (%s) assets'), $total_assets);
                    }
                ?>
                
                top.frames['main'].show_notification('asset_notif', "<?php echo Util::js_entities($message) ?>", 'nf_success', 15000, true);
                parent.GB_hide();
            }

            if (!usehide && typeof parent.GB_close == 'function')
            {
                parent.GB_close();
            }

            return false;
        }
    	
		$(document).ready(function(){
    		
            <?php 
            if ($close) 
            {
                echo "close_window(true);";
            } 
            ?>
    		
            $('#close_button').click(function(event)
            {
                event.preventDefault();
                close_window(false);
            });
    		
    		display_smethod_div();
		
            $('#scan_locally').on('click', function()
            {   
                if ($('#scan_locally').is(':checked') == false)
                {
                    $('#v_info').hide();
                }
            });
						            			
			$('#scheduleM').change(function() 
			{
                display_smethod_div();
			});
			
			// Confirm new job with a lot of targets
			
			$('#mjob').on("click", function(event){
				if( $('#thosts').html() > 255 && $("#hosts_alive").is(":checked")) {
                    var msg_confirm = '<?php echo Util::js_entities(_("You are about to scan a big number of hosts (#HOSTS# hosts). This scan could take a long time depending on your network and the number of assets that are up, are you sure you want to continue?"))?>';
                    
                    msg_confirm = msg_confirm.replace("#HOSTS#", $('#thosts').html());
                                             
                    var keys        = {"yes": "<?php echo _('Yes') ?>","no": "<?php echo _('No') ?>"};
                                    
                    av_confirm(msg_confirm, keys).fail(function(){
                        return false; 
                    }).done(function(){
                        $('#msgform').submit(); 
                    });
				}
				else {
				    $("#hosts_alive").attr('disabled', false);
				    
					$('#msgform').submit();
				}
  			});
			
			$('.section').click(function() { 
				var id = $(this).find('img').attr('id');
				
				toggle_section(id);
			});
            
            $('#SVRid').change(function() {
                simulation();
            });
            
            $('#scan_locally').click(function() { 
                simulation();
			});
            $('#not_resolve').click(function() {
                simulation();
			});
            
            simulation();
            
            $('#ssh_credential, #smb_credential').change(function() {

                var select_name = $(this).attr('name');

                switch_credentials(select_name);
			});

		});
		
		function toggle_section(id){
			var section_id = id.replace('_arrow', '');
			var section    = '.'+section_id;

			if ($(section).is(':visible')){ 
				$('#'+id).attr('src','../pixmaps/arrow_green.gif'); 
			}
			else{ 
				$('#'+id).attr('src','../pixmaps/arrow_green_down.gif');
			}
			$(section).toggle();
		}

		function switch_user(select) {
			if(select=='entity' && $('#entity').val()!=''){
				$('#user').val('');
			}
			else if (select=='user' && $('#user').val()!=''){
				$('#entity').val('');
			}
		}

        function enable_button() 
        {            
            $("#mjob").removeAttr("disabled");
        }

	    function toggle_scan_locally(){
            if($("#hosts_alive").is(":checked")) {
                $("#scan_locally").removeAttr("disabled");
            }
            else {
                if($("#scan_locally").is(":checked")) {
                    $('#scan_locally').trigger('click');
                }

                $("#scan_locally").attr("disabled","disabled");
            }
            
            simulation();
        }
        
        var flag = 0;
        
		function simulation() {
		    $('#v_info').hide();
		
		    $('#sresult').html('');
            
            selectall('targets');
            
            var stargets = getselectedcombovalue('targets');
            
		    if( !flag  && stargets.length > 0 ) {
                if (stargets.length > 0) 
				{
                    var targets = $('#targets').val().join(',');
                    disable_button();
                    $('#loading').show();
                    flag = 1;
                    $.ajax({
                        type: "POST",
                        url: "simulate.php",
                        data: { 
                            hosts_alive: $('input[name=hosts_alive]').is(':checked') ? 1 : 0,
                            scan_locally: $('input[name=scan_locally]').is(':checked') ? 1 : 0,
                            not_resolve: $('input[name=not_resolve]').is(':checked') ? 1 : 0,
                            scan_server: $('select[name=SVRid]').val(),
                            scan_type: 'adhoc',
                            targets: targets
                        },
                        success: function(msg) {     
                            $('#loading').hide();
                            var data = msg.split("|");
                            $('#sresult').html("");
                            $('#sresult').html(data[0]);
                            $('#sresult').show();
                                                                                
                            if(data[1]=="1") {
                                enable_button();
                            }
                            
                            // If any sensor is remote the "pre-scan locally" should be unchecked 
                            
                            if ($('#scan_locally').is(':checked') && typeof(data[3]) != 'undefined' && data[3] == 'remote')
                            {                            
                                $('#v_info').show();
                                
                                show_notification('v_info', "<?php echo _("'Pre-Scan locally' option should be disabled, at least one sensor is external.")?>" , 'nf_info', false, true, 'padding: 3px; width: 90%; margin: 12px auto 12px auto; text-align: center;');
                            }
                            
                            //var h = document.body.scrollHeight || 1000000;window.scrollTo(0,document.body.scrollHeight);
                            //window.scrollTo(0,h);
                            flag = 0;
                        },
                        error: function (request, status, error) {
                            flag = 0;
                        }
                    });
                }
				else {
                    alert("<?php echo Util::js_entities(_("At least one target needed!"))?>");
                }
            }
		}
        
		function disable_button() 
		{                       
			$("#mjob").attr("disabled","disabled");
        }
        
        function display_smethod_div()
        {
            var type = $('#scheduleM').attr('value');
			var id;
		
			switch(type)
			{
				case "N":
					id = 1;
					break;
				case "O":
					id = 3;
					break;
				case "D":
					id = 2;
					break;
				case "W":
					id = 4;
					break;
				case "M":
					id = 5;
					break;
				case "NW":
					id = 6;
					break;
			}
			
		    if(id==1) {
				$("#smethodtr").hide();
			}
			else {
				$("#smethodtr").show();
			}
			showLayer('idSched', id);
        }

        function switch_credentials(select_name)
        {
            if (select_name == 'ssh_credential')
            {
                if ($('#ssh_credential').val() != '')
                {
                    $('#smb_credential').val('');
                    $('#smb_credential').prop('disabled', true);
                    $('#ssh_credential').prop('disabled', false);
                }
                else
                {
                    $('#smb_credential').prop('disabled', false);
                }
            }
            else if (select_name == 'smb_credential')
            {
                if($('#smb_credential').val() != '')
                {
                    $('#ssh_credential').val('');
                    $('#ssh_credential').prop('disabled', true);
                    $('#smb_credential').prop('disabled', false);
                }
                else
                {
                    $('#ssh_credential').prop('disabled', false);
                }
            }
        }
	</script>
	
	<style type='text/css'>
		#user,#entity { width: 220px;}        
        
        .c_back_button {
            display: block;
            top:10px;
            left:10px;
        }
       
        .greyfont{
            color: #666666;
        }
        #title
        {
            margin: 10px auto 0px auto;
        }
        #main_table{
            margin:0px auto;
        }
        
        #targets {
            width:300px;
            height:200px;
        }
		#searchBox {
			width:298px;
		}
		.advanced {display: none;}
		.job_option {
			text-align:left;
			padding: 0px 0px 0px 30px;
		}
		.madvanced {
			text-align:left;
			padding: 0px 0px 4px 30px;
		}
		#user, #entity {
			width: 140px;
		}
		#close_button
		{
    		margin-right: 10px;
		}
	</style>
</head>

<body>

    <div id='v_info'></div>
    
    <?php  
    if (!empty($validation_errors))
    {
        $config_nt = array(
            'content' => implode('<br/>', $validation_errors),
            'options' => array (
            'type'          => 'nf_error',
            'cancel_button' => TRUE),
            'style'   => 'width: 90%; margin: 20px auto; text-align: center;'
        );
        
        $nt = new Notification('nt_2', $config_nt);
        $nt->show();
    }
    
    if (!empty($limit_msg))
    {
        $config_nt = array(
    		'content' => $limit_msg,
    		'options' => array (
    			'type'          => 'nf_error',
    			'cancel_button' => false
    		),
    		'style'   => 'width: 70%; margin: 10px auto 15px auto; text-align:center;'
    	);
    
    	$nt = new Notification('nt_limit', $config_nt);
    	$nt->show();
    }
    ?>
     
    <form method="post" action="new_scan.php" name="msgform" id='msgform'>
        <input type="hidden" name="total_assets" value="<?php echo count($asset_list) ?>">
        <input type="hidden" name="action" value="save_scan">
        <input type="hidden" name="sched_id" value="<?php echo $sched_id ?>">

        <select id="targets" name="targets[]" multiple="multiple" style="display: none">
        <?php
            foreach ($select_targets as $t_id => $t_name)
            {?>
            <option value='<?php echo $t_id ?>'><?php echo $t_name ?></option>
            <?php
            }   
        ?>
        </select>
       
        <table id="title" class="transparent" width="90%" cellspacing="0" cellpadding="0">
            <tr>
                <td class="headerpr_no_bborder">
                    <?php echo _('Create Scan Job'); ?>
                </td>
            </tr>
        </table>
        <table id="main_table" width="90%" cellspacing="4" class="main_tables">
            <tr>
                <td width="25%" class='job_option'> <?php echo _('Job Name:') ?></td>
                <td style="text-align:left;"><input type="text" name="job_name" id="job_name" value="<?php echo $job_name ?>"></td>
            </tr>         
    
            <tr>
                <td class='job_option'><?php echo _('Select Sensor:')?></td>
                <td style='text-align:left;'>
                    <select id='SVRid' style='width:212px' name='SVRid'>
                        <option value='Null'><?php echo _("First Available Sensor-Distributed")?></option>
                        <?php
                        foreach ($all_sensors as $_sensor_id => $sensor_data)
                        {?>
                            <option value='<?php echo $_sensor_id ?>' <?php echo $sensor_data['selected'] ?> ><?php echo $sensor_data['name'] . '[' . $sensor_data['ip'] .']' ?></option>
                        <?php
                        }
                        ?>   
                    </select>
                </td>
            </tr>
            <tr>
                <td class='job_option'><?php echo _('Profile:') ?></td>
                <td style='text-align:left;'>
                    <select name='sid'>
                       <?php
                        foreach ($v_profiles as $v_profile_id => $profile_data)
                        {?>
                            <option value='<?php echo $v_profile_id ?>' <?php echo $profile_data['selected'] ?> ><?php echo $profile_data['name&description'] ?></option>
                        <?php
                        } 
                        ?>
                    </select>
                </td>
            </tr>
    	
            <tr>
                <td class='job_option' style='vertical-align: top;'><div><?php echo _('Schedule Method:') ?></div></td>
    		    <td style='text-align:left'>
        		    <select name='schedule_type' id='scheduleM'>
                        <?php
                        foreach ($s_methods as $s_method_id => $s_method_data)
                        {?>
                            <option value='<?php echo $s_method_id ?>' <?php echo $s_method_data['selected'] ?> ><?php echo $s_method_data['name'] ?></option>
                        <?php
                        }
                        ?>
                    </select>
                </td>
    		</tr>
            
            <tr $smethodtr_display id='smethodtr'>
                <td>&nbsp;</td>
                <td>
                    <div id="idSched1" class="forminput"></div>
                    <div id="idSched8" class="forminput">
                        <table cellspacing="2" cellpadding="0" width="100%">
                            <tr><th width="35%"><?php echo _("Begin in") ?></th>
                                <td class="noborder" nowrap="nowrap">
                                    <?php echo gettext('Year') ?>&nbsp;
                                    <select name='biyear'>
                                        <?php
                                        foreach ($years as $y => $y_data)
                                        {                                          
                                        ?>
                                            <option value="<?php echo $y ?>" <?php echo $y_data['selected'] ?>><?php echo $y ?></option>
                                        <?php
                                        }
                                    ?> 
                                    </select>
                                    &nbsp;&nbsp;&nbsp;
                                    <?php echo gettext('Month') ?>&nbsp;
                                    <select name='bimonth'>
                                        <?php
                                        foreach ($months as $m => $m_data)
                                        {                                          
                                        ?>
                                            <option value="<?php echo $m ?>" <?php echo $m_data['selected'] ?>><?php echo $m ?></option>
                                        <?php
                                        }
                                        ?>    
                                    </select>
                                    &nbsp;&nbsp;&nbsp;
                                    <?php echo gettext('Day') ?>&nbsp;
                                    <select name='biday'>
                                        <?php
                                        foreach ($days as $d => $d_data)
                                        {                                          
                                        ?>
                                            <option value="<?php echo $d ?>" <?php echo $d_data['selected'] ?>><?php echo $d ?></option>
                                        <?php
                                        }
                                        ?>
                                    </select>
                                </td>
                            </tr>
                        </table>
                    </div>
                    <div id="idSched3" class="forminput" style="display: block;">
                        <table cellspacing="2" cellpadding="0" width="100%">
                            <tr><th width="35%"><?php echo _('Day') ?></th>
                                <td colspan="6" class="noborder" nowrap="nowrap">
                                    <?php echo  _('Year') ?>&nbsp;
                                    <select name="ROYEAR">
                                        <?php
                                        foreach ($years as $y => $y_data)
                                        {                                          
                                        ?>
                                            <option value="<?php echo $y ?>" <?php echo $y_data['selected'] ?>><?php echo $y ?></option>
                                        <?php
                                        }?>
                                    </select>
                                    &nbsp;&nbsp;&nbsp;
                                    <?php echo _('Month')?> &nbsp;
                                    <select name="ROMONTH">
                                        <?php
                                        foreach ($months as $m => $m_data)
                                        {                                          
                                        ?>
                                            <option value="<?php echo $m ?>" <?php echo $m_data['selected'] ?>><?php echo $m ?></option>
                                        <?php
                                        }
                                        ?>
                                    </select>
                                    &nbsp;&nbsp;&nbsp;
                                    <?php echo  _('Day') ?>&nbsp;
                                    <select name="ROday">
                                        <?php
                                        foreach ($days as $d => $d_data)
                                        {                                          
                                        ?>
                                            <option value="<?php echo $d ?>" <?php echo $d_data['selected'] ?>><?php echo $d ?></option>
                                        <?php
                                        }
                                        ?>
                                    </select>
                                </td>
                            </tr>
                        </table>
                    </div>
                    <div id="idSched4" class="forminput" > 
                        <table width="100%">
                            <tr>
                                <th align="right" width="35%"><?php echo _('Weekly') ?></th>
                                <td colspan="2" class="noborder">
                                    <select name="dayofweek">
                                        <?php
                                        foreach ($daysMap as $day => $day_data)
                                        {                                          
                                        ?>
                                            <option value="<?php echo $day ?>" <?php echo $day_data['selected'] ?>><?php echo $day_data['text'] ?></option>
                                        <?php
                                        }
                                        ?>
                                    </select>
                                </td>
                            </tr>
                        </table>
                    </div>
                    <div id="idSched5" class="forminput">
                        <table width="100%">
                            <tr>
                                <th width="35%"><?php echo _('Select Day') ?></td>
                                <td colspan="2" class="noborder">
                                    <select name="dayofmonth">
                                        <?php
                                        foreach ($days_of_month as $m => $m_data)
                                        {                                            
                                        ?>
                                            <option value="<?php echo $m ?>" <?php echo $m_data['selected'] ?>><?php echo $m ?></option>
                                        <?php
                                        }
                                        ?>
                                    </select>
                                </td>
                            </tr>
                        </table>
                    </div>
                    <div id="idSched6" class="forminput">
                        <table width="100%">
                            <tr>
                                <th width="35%"><?php echo _('Day of week') ?></th>
                                <td colspan="2" class="noborder">
                                    <select name="nthdayofweek">
                                        <?php
                                        foreach ($daysMap as $i_day => $d_data)
                                        {                                            
                                        ?>
                                            <option value="<?php echo $i_day ?>" <?php echo $d_data['selected'] ?>><?php echo $d_data['text'] ?></option>
                                        <?php
                                        }
                                        ?>
                                    </select>
                            </tr>
                        </table>
                        <br>
                        <table width="100%">
                            <tr>
                                <th align="right"><?echo _('N<sup>th</sup> week') ?></th>
                                <td colspan="2" class="noborder">
                                    <select name='nthweekday'>
                                        <?php
                                        foreach ($nweekday as $n => $nweekday_data)
                                        {                          
                                        ?>
                                            <option value="<?php echo $n ?>" <?php echo $nweekday_data['selected'] ?>><?php echo $nweekday_data['text'] ?></option>
                                        <?php
                                        }
                                        ?>        
                                    </select>
                                </td>
                          </tr>
                        </table>
                    </div>
                    <div id="idSched7" class="forminput" style="margin-bottom:3px;">
                        <table width='100%'>
                            <tr>
                                <th width='35%'><?php echo _('Frequency') ?></th>
                                <td width='100%' style='text-align:center;' class='nobborder'>
                                    <span style='margin-right:5px;'><?php echo _('Every') ?></span>
                                        <select name='time_interval'>
                                        <?php
                                        foreach ($frequencies as $f => $f_data)
                                        {                          
                                        ?>
                                            <option value="<?php echo $f ?>" <?php echo $f_data['selected'] ?>><?php echo $f ?></option>
                                        <?php
                                        }
                                        ?>
                                        </select>
                                    <span id='days' style='margin-left:5px'><?php echo _('day(s)') ?></span>
                                    <span id='weeks' style='margin-left:5px'><?php echo _('week(s)') ?></span>
                                </td>
                            </tr>
                        </table>
                    </div>
                    <div id="idSched2" class="forminput">
                        <table width="100%">
                            <tr>
                                <th rowspan="2" align="right" width="35%"><?php echo _('Time') ?></td>
                                <td align='right'><?php _("Hour") ?></td>
                                <td align="left" class="noborder">
                                    <select name="time_hour">
                                        <?php
                                        foreach ($hours as $h => $h_data)
                                        {?>
                                            <option value="<?php echo $h ?>" <?php echo $h_data['selected'] ?>><?php echo $h ?></option>
                                        <?php
                                        }
                                        ?>
                                    </select>
                                </td>
                                <td align='right'><?php echo _("Minutes")?></td>
                                <td class='noborder' align='left'>
                                    <select name='time_min'>
                                        <?php
                                        foreach ($minutes as $m => $m_data)
                                        {?>
                                            <option value="<?php echo $m ?>" <?php echo $m_data['selected'] ?>><?php echo $m ?></option>
                                        <?php
                                        }
                                        ?>
                                    </select>
                                </td>
                            </tr>
                        </table>
                    </div>
                </td>
            </tr>
            <tr>
    	        <td class="madvanced">
        	       <a class="section"><img id="advanced_arrow" border="0" align="absmiddle" src="../pixmaps/arrow_green.gif"><?php echo _("ADVANCED") ?></a></td>
    	        <td>&nbsp;</td>
    	    </tr>
            <tr class='advanced'>
                <td class='job_option'><?php echo _("SSH Credential:") ?></td>
                <td style='text-align:left'>
                    <select id='ssh_credential' name='ssh_credential'>
                        <option value="">--</option>
    			        <?php
                        foreach ($ssh_arr as $c_key => $c_data)
                        {?>
                            <option value='<?php echo $c_key ?>' <?php echo $c_data['selected'] ?> ><?php echo $c_data['name'] ?></option>
                        <?php
                        }
                        ?>
                    </select></td>
            </tr>
            <tr class='advanced'>
                <td class='job_option'><?php echo _("SMB Credential:") ?></td>
                <td style='text-align:left'>
                    <select id='smb_credential' name='smb_credential'>
                        <option value=''>--</option>
    			        <?php
                        foreach ($smb_arr as $c_key => $c_data)
                        {?>
                            <option value='<?php echo $c_key ?>' <?php echo $c_data['selected'] ?> ><?php echo $c_data['name'] ?></option>
                        <?php
                        }
                        ?>
                    </select></td>
            </tr>
            <tr class="job_option advanced">
                <td class="job_option"><?php echo _("Timeout:")?></td>
                <td style="text-align:left;" nowrap>
                    <input type='text' style='width:80px' name='timeout' value="<?php echo $timeout?>">
                    <?php echo _("Max scan run time in seconds")?>
                </td>
            </tr>
    	    <tr class='advanced'>
        	    <td class='job_option'>
            	    <?echo _("Send an email notification:")?>
    	        </td>
    	        <td style="text-align:left;">
    	            <input type="radio" name="send_email" value="0" <?php echo $email_notification['no'] ?> /><?php echo _("No"); ?>
    	            <input type="radio" name="send_email" value="1" <?php echo $email_notification['yes'] ?> /><?php echo _("Yes"); ?>
    	        </td>
    	    </tr>
    	    <tr class='advanced'>
                <td class='job_option'><?php _("Scan job visible for:")?></td>
    			<td style='text-align: left'>
    				<table cellspacing='0' cellpadding='0' class='transparent' style='margin: 5px 0px;'>
    					<tr>
    						<td class='nobborder'>
        						<span style='margin-right:3px'><?php echo _('User:') ?></span>
        				    </td>	
    						<td class='nobborder'>				
    							<select name='user' id='user' onchange="switch_user('user');return false;">
        				        <option value='' style='text-align:center !important;'>-<?php echo _('Select one user')?>-</option>
        				        <?php
                                foreach ($users_to_assign as $u_key => $u_value)
                                {?>
                                    <option value='<?php echo $u_key ?>' <?php echo $users_to_assign[$u_key]['selected'] ?> ><?php echo $users_to_assign[$u_key]['name'] ?></option>
                                <?php
                                }
                                ?>
    				            </select>
    						</td>
                            <td style='text-align:center; border:none; !important'>
                                <span style='padding:5px;'><?php echo _("OR") ?><span>
                            </td>
    			            <td class='nobborder'>
    				            <span style='margin-right:3px'><?php echo _('Entity:')?></span>
    				        </td>
    						<td class='nobborder'>	
    							<select name='entity' id='entity' onchange="switch_user('entity');return false;">
    								<option value='' style='text-align:center !important;'>-<?php echo _('Select one entity')?>-</option>
            				        <?php
                                    foreach ($entities_to_assign as $e_key => $e_value)
                                    {?>
                                        <option value='<?php echo $e_key ?>' <?php echo $entities_to_assign[$e_key]['selected'] ?> ><?php echo $entities_to_assign[$e_key]['name'] ?></option>
                                    <?php
                                    }
                                    ?>
                				</select>
    						</td>
                        </tr>
                    </table>
                </td>
            </tr>
    	    <tr>
        	    <td valign="top" colspan="2"  class="job_option noborder"><br>
    	            <input onclick="toggle_scan_locally()" type="checkbox" id="hosts_alive" name="hosts_alive" value="1" <?php echo $hosts_alive_data['disabled'] . ' ' . $hosts_alive_data['checked'] ?>><?php echo _('Only scan hosts that are alive (greatly speeds up the scanning process)'); ?>
    	            <br><input type="checkbox" id="scan_locally" name="scan_locally" value="1" <?php echo $scan_locally_checked ?> /><?php echo _('Pre-Scan locally (do not pre-scan from scanning sensor)');?>
                    <br><input type="checkbox" id="not_resolve" name="not_resolve" value="1" <?php echo $resolve_names_checked ?>  /><?php echo _('Do not resolve names');?>
                </td>
            </tr>
        </table>
        
        <br/>
        
        <?php
            
        $button_text = _('NEW JOB'); ?>
        
        <div style="margin:0px auto 10px auto;text-align: center">

            <input type="button" class="av_b_secondary" id="close_button" value="<?php echo _('Cancel') ?>"/>

            <input type='button' id='mjob' value='<?php echo $button_text ?>' disabled='disabled' />
            <span id="loading" style="display:none;margin:0px 0px 0px 10px;" ><?php echo _('Checking Job...') ?></span>
        
            <div id='sresult'></div>
        </div>
    </form>

<?php

function submit_scan($SVRid, $job_name, $ssh_credential, $smb_credential, $schedule_type, $not_resolve, $user, $entity, $targets, $scheduled_status,
                     $hosts_alive, $sid, $send_email, $timeout, $scan_locally, $dayofweek, $dayofmonth, $ROYEAR, $ROMONTH, $ROday, $time_hour,
                     $time_min, $time_interval, $sched_id, $biyear, $bimonth, $biday, $nthweekday, $tz, $daysMap)
{
    $db     = new ossim_db();
    $dbconn = $db->connect();

    $credentials = $ssh_credential . '|' . $smb_credential;
    
    $username = (valid_hex32($entity)) ? $entity : $user;
    
    if (empty($username))
    {
        $username = Session::get_session_user();
    }
    
    $btime_hour = $time_hour;  // save local time
    $btime_min  = $time_min;
     
    $bbiyear    = $biyear;
    $bbimonth   = $bimonth;
    $bbiday     = $biday;
    
    if($schedule_type == 'O')
    {
        // date and time for run once
        if (empty($ROYEAR))  $ROYEAR  = gmdate('Y');
        if (empty($ROMONTH)) $ROMONTH = gmdate('m');
        if (empty($ROday))   $ROday   = gmdate('d');
         
        list ($_y,$_m,$_d,$_h,$_u,$_s,$_time) = Util::get_utc_from_date($dbconn, "$ROYEAR-$ROMONTH-$ROday $time_hour:$time_min:00", $tz);
         
        $ROYEAR    = $_y;
        $ROMONTH   = $_m;
        $ROday     = $_d;
        $time_hour = $_h;
        $time_min  = $_u;
    }
    else if(in_array($schedule_type, array('D', 'W', 'M', 'NW')))
    {
        // date and time for Daily, Day of Week, Day of month, Nth weekday of month
        list ($b_y,$b_m,$b_d,$b_h,$b_u,$b_s,$b_time) = Util::get_utc_from_date($dbconn, "$biyear-$bimonth-$biday $time_hour:$time_min:00", $tz);
         
        $biyear    = $b_y;
        $bimonth   = $b_m;
        $biday     = $b_d;
        $time_hour = $b_h;
        $time_min  = $b_u;
    }
         
    $resolve_names = ($not_resolve=='1') ? 0 : 1;

    if($schedule_type != 'N') {
       // current datetime in UTC
       
       $arrTime = explode(":",gmdate('Y:m:d:w:H:i:s'));
       
       $year = $arrTime[0];
       $mon  = $arrTime[1];
       $mday = $arrTime[2];
       $wday = $arrTime[3];
       $hour = $arrTime[4];
       $min  = $arrTime[5];
       $sec  = $arrTime[6];
       
       $timenow = $hour.$min.$sec;
       
       $run_wday = $daysMap[$dayofweek]['number'];

       $run_time   = sprintf('%02d%02d%02d',  $time_hour, $time_min, '00');
       $run_mday   = $dayofmonth;     
       $time_value = "$time_hour:$time_min:00";  

       $ndays = array('Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday');
       
       $begin_in_seconds   = Util::get_utc_unixtime("$biyear-$bimonth-$biday $time_hour:$time_min:00") - 3600 * $tz;
       $current_in_seconds = gmdate('U');                // current datetime in UTC
       
       if(strlen($bimonth)==1) $bimonth = '0' . $bimonth;
       if(strlen($biday)==1)   $biday   = '0' . $biday;
    }

    switch($schedule_type)
    {
        case 'N':

            $requested_run = gmdate('YmdHis');

        break;
        
        case 'O':
   
            $requested_run = sprintf('%04d%02d%02d%06d', $ROYEAR, $ROMONTH, $ROday, $run_time );

        break;
   
        case 'D':
            if($begin_in_seconds > $current_in_seconds)
            {
                $next_day = $biyear.$bimonth.$biday;  // selected date by user
            }
            else
            {
                if ($run_time > $timenow)
                {
                    $next_day = $year.$mon.$mday; // today
                }
                else
                {
                    $next_day = gmdate("Ymd", strtotime("+1 day GMT",gmdate("U"))); // next day
                }
            }
          
            $requested_run = sprintf("%08d%06d", $next_day, $run_time );
          
        break;
            
        case 'W':

            if( $begin_in_seconds > $current_in_seconds ) { // if it is a future date
                
                $wday  = date("w",mktime ( 0, 0, 0, $bimonth, $biday, $biyear)); // make week day for begin day
                if ($run_wday == $wday) {
                    $next_day = $biyear.$bimonth.$biday;  // selected date by user
                }
                else
                {
                    $next_day = gmdate("Ymd", strtotime("next ".$ndays[$run_wday]." GMT",mktime ( 0, 0, 0, $bimonth, $biday, $biyear)));
                }
            }
            else {
                if ($run_wday == $wday && $run_time > $timenow)
                {
                    $next_day = $year.$mon.$mday; // today
                }               
                else
                {
                    $next_day = gmdate("Ymd", strtotime("next ".$ndays[$run_wday]." GMT",gmdate("U"))); // next week
                }
            }
      
            preg_match("/(\d{4})(\d{2})(\d{2})/", $next_day, $found);

            list ($b_y,$b_m,$b_d,$b_h,$b_u,$b_s,$b_time) = Util::get_utc_from_date($dbconn,$found[1]."-".$found[2]."-".$found[3]." $btime_hour:$btime_min:00", $tz);
            $requested_run = sprintf("%04d%02d%02d%02d%02d%02d", $b_y, $b_m, $b_d, $b_h, $b_u, "00");
        break;
   
        case 'M':
            if( $begin_in_seconds > $current_in_seconds )
            { // if it is a future date
                if ( $run_mday >= $biday)
                {
                    $next_day =  $biyear.$bimonth.($run_mday<10 ? "0" : "").$run_mday; // this month
                }
                else
                {
                    $next_day = sprintf("%06d%02d", gmdate("Ym", strtotime("next month GMT", mktime ( 0, 0, 0, $bimonth, $biday, $biyear))), $run_mday ) ;
                }
            }
            else {
                if ( $run_mday > $mday || ( $run_mday == $mday && $run_time > $timenow ))
                {
                    $next_day = $year.$mon.($run_mday<10 ? "0" : "").$run_mday; // this month
                }
                else
                {
                    $next_day = sprintf("%06d%02d", gmdate("Ym", strtotime("next month GMT", gmdate("U"))), $run_mday ) ;
                }
            }
      
            preg_match("/(\d{4})(\d{2})(\d{2})/", $next_day, $found);

            list ($b_y,$b_m,$b_d,$b_h,$b_u,$b_s,$b_time) = Util::get_utc_from_date($dbconn,$found[1]."-".$found[2]."-".$found[3]." $btime_hour:$btime_min:00",$tz);
            $requested_run = sprintf("%04d%02d%02d%02d%02d%02d", $b_y, $b_m, $b_d, $b_h, $b_u, "00");
      
        break;
            
        case 'NW':
        
            if( $begin_in_seconds > $current_in_seconds )
            {
                // if it is a future date
                $array_time = array('month'=> $bbimonth, 'day' => $bbiday, 'year' => $bbiyear);
                
                $requested_run = weekday_month(strtolower($daysMap[$dayofweek]['text']), $nthweekday, $btime_hour, $btime_min, $array_time);
            }
            else
            {
                $requested_run = weekday_month(strtolower($daysMap[$dayofweek]['text']), $nthweekday, $btime_hour, $btime_min);
            }
        
            preg_match("/(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})/", $requested_run, $found);

            list ($b_y,$b_m,$b_d,$b_h,$b_u,$b_s,$b_time) = Util::get_utc_from_date($dbconn,$found[1]."-".$found[2]."-".$found[3]." ".$found[4].":".$found[5].":00",$tz);
            $requested_run = sprintf("%04d%02d%02d%02d%02d%02d", $b_y, $b_m, $b_d, $b_h, $b_u, "00");
        
            $dayofmonth = $nthweekday;
      
            break;
        default:

        break;
    }
   
    $insert_time = gmdate('YmdHis');

    if(!empty($_SESSION['_vuln_targets']) && count($_SESSION['_vuln_targets'])>0)
    {
        $sgr = array();

        foreach( $_SESSION['_vuln_targets'] as $target_selected => $server_id )
        {
            $sgr[$server_id][] = $target_selected;
        }
        ossim_clean_error();
        
        unset($_SESSION['_vuln_targets']); // clean scan targets
        
        $resolve_names = ($not_resolve == '1') ? 0 : 1;
        
        $queries = array();
        
        $bbimonth = (strlen($bbimonth) == 1) ? '0' . $bbimonth : $bbimonth;
        $bbiday   = (strlen($bbiday) == 1) ?   '0' . $bbiday   : $bbiday;
        
        $qc = 0;
        
        if ($schedule_type == 'N')
        {
            foreach ($sgr as $notify_sensor => $target_list)
            {
                $target_list = implode("\n", $target_list);
                
                $params = array(
                    $job_name,
                    $username,
                    Session::get_session_user(),
                    $schedule_type,
                    $target_list,
                    $hosts_alive,
                    $sid, 
                    $send_email, 
                    $timeout, 
                    $SVRid, 
                    $insert_time, 
                    $requested_run, 
                    '3',
                    'S', 
                    $notify_sensor, 
                    $scan_locally, 
                    '',
                    $resolve_names, 
                    $credentials
                );

                $queries[$qc]['query'] = 'INSERT INTO vuln_jobs ( name, username, fk_name, meth_SCHED, meth_TARGET,  meth_CRED,
                    meth_VSET, meth_Wfile, meth_TIMEOUT, scan_ASSIGNED,
                    scan_SUBMIT, scan_next, scan_PRIORITY, status, notify, authorized, author_uname, resolve_names, credentials )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)';
                
                $queries[$qc]['params'] = $params;
                
                $qc++;
            }
        }
        else
        {   
            $params = array(
                $bbiyear . $bbimonth . $bbiday,
                $job_name,
                $username,
                Session::get_session_user(), 
                $schedule_type,
                $dayofweek,
                $dayofmonth,
                $time_value,
                implode("\n", $targets),
                $hosts_alive,
                $sid,
                $send_email,
                $scan_locally,
                $timeout,
                $requested_run,
                $insert_time ,
                strval($scheduled_status),
                $resolve_names,
                $time_interval, 
                '',
                $credentials,
                $SVRid
            );
            
            $queries[$qc]['query'] = 'INSERT INTO vuln_job_schedule ( begin, name, username, fk_name, schedule_type, day_of_week, day_of_month, time, meth_TARGET, meth_CRED, meth_VSET, meth_Wfile,  meth_Ucheck, meth_TIMEOUT, next_CHECK, createdate, enabled, resolve_names, time_interval, IP_ctx, credentials, email)
                                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ';
            $queries[$qc]['params'] = $params;
            
            $qc++;
        }

        $execute_errors = array();

        foreach ($queries as $id => $sql_data)
        {
            $rs = $dbconn->execute($sql_data['query'], $sql_data['params']);
            
            if ($rs === FALSE)
            {
                $execute_errors[] = $dbconn->ErrorMsg();
            }
        }
        
        if (empty($execute_errors) && $schedule_type != 'N')
        {
            // We have to update the vuln_job_assets
            
            if (intval($sched_id) == 0)
            {
                $query = ossim_query('SELECT LAST_INSERT_ID() as sched_id');
                $rs    = $dbconn->Execute($query);
                
                if (!$rs)
                {
                    Av_exception::throw_error(Av_exception::DB_ERROR, $dbconn->ErrorMsg());
                }
                else
                {
                    $sched_id = $rs->fields['sched_id'];
                }
            }
            
            Vulnerabilities::update_vuln_job_assets($dbconn, 'insert', $sched_id, 0);
        }
        
        $config_nt = array(
            'content' => '',
            'options' => array (
            'type'          => 'nf_success',
            'cancel_button' => FALSE),
            'style'   => 'width: 40%; margin: 20px auto; text-align: center;'
        );
            
        $config_nt['content'] = (empty($execute_errors)) ? _('Successfully Submitted Job') : _('Error creating scan job:') . implode('<br>', $execute_errors);
        
        $nt = new Notification('nt_1', $config_nt);
        $nt->show();
        
        $dbconn->close();
    }
}

function weekday_month($day, $nth, $h, $m, $start_date = array())
{
    $current_year  = ($start_date['year']!="")  ? $start_date['year']  : date('Y');
    $current_month = ($start_date['month']!="") ? $start_date['month'] : date('m');
    $current_day   = ($start_date['day']!="")   ? $start_date['day']   : date('d');
    
    if(empty($start_date)) {
        //Current timestamp
        $today  = mktime(date('H'), date('i'), 0, $current_month, $current_day, $current_year);
    }
    else {
        $today  = mktime(0, 0, 0,  $current_month, $current_day, $current_year);
    }
    //Last day of previous month 
    $date   = strtotime("-1 day", mktime($h, $m, 0, $current_month, 1, $current_year));
    
    //Search date
    for ($i=0; $i<$nth; $i++){
        $date = strtotime("next $day", $date);
    }
    
    $date = $date + (($h*3600) + ($m*60));
                            
    //If date is less than current, we search in next month
    if ( $date < $today )
    {
        $month = (int)$current_month + 1;
        $date  = strtotime("-1 day", mktime ($h, $m, 0, $month, 1, $current_year));
        
        for ($i=0; $i<$nth; $i++){
            $date = strtotime("next $day", $date);
        }
        
        $date = $date + (($h*3600) + ($m*60));
    }

    return date('YmdHi', $date)."00";
}

function get_targets ($conn, $ip_list)
{
    $result = array();
    
    if (!empty($ip_list))
    {
        if (is_array($ip_list)==FALSE)
        {
            $ip_list = explode("\n", trim($ip_list));
        }
        
        foreach ($ip_list as $asset)
        {
            $asset = trim($asset);
            
            if (preg_match('/^([a-f\d]{32})#(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2})$/i', $asset, $found))
            { 
            	$_asset_name = (Asset_net::is_in_db($conn, $found[1])) ? Asset_net::get_name_by_id($conn, $found[1]) : $found[2];

            	$result[$asset] = $_asset_name;
            }
            else if (preg_match('/^([a-f\d]{32})#(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/i', $asset, $found))
            {
            	$_asset_name = (Asset_host::is_in_db($conn, $found[1])) ? Asset_host::get_name_by_id($conn, $found[1]) : $found[2];

            	$result[$asset] = $_asset_name;
            }
            else if (preg_match('/^([a-f\d]{32})#hostgroup$/i', $asset, $found))
            {
                $result[$asset] = Asset_group::get_name_by_id($conn, $found[1]);
            }
            else if (preg_match('/^([a-f\d]{32})#netgroup$/i', $asset, $found))
            {
                $result[$asset] = Net_group::get_name_by_id($conn, $found[1]);
            }            
            else
            {
                $result[$asset] = $asset;
            }
        }
    }

    return $result;
}

function get_host_alive_attributes($value, $targets)
{   
    $result = array();
    
    $targets = (is_array($targets)) ? implode('|', $targets) : '';
    
	$condition1 = (intval($value)==1) ? TRUE : FALSE;
	
	$condition2 = preg_match('/' . EXCLUDING_IP2 . '/', $targets);
	
	$result['checked']  = ($condition1 || $condition2) ? ' checked="checked"' : '';
	
	$result['disabled'] = ($condition2) ? ' disabled="disabled"' : '';
	
	return $result;
}

?>

<?php

if (!defined('WC_VAT_COMPLIANCE_DIR')) die('No direct access');

return;

// This is a debugging example, which, with the conditions given, will log all actually-used hooks/filters from the plugin (or at least, those in a named class) during an HTTP request.

if (isset($_REQUEST['wc-ajax']) && 'ppc-create-order' === $_REQUEST['wc-ajax'] && '1.2.3.4' == $_SERVER['REMOTE_ADDR']) {

	add_filter('all', function($tag) {
		
		global $wp_filter;
		
		if (empty($wp_filter[$tag])) {
			return;
		}
		
		$has_vat_class = false;
		
		foreach ($wp_filter[$tag]->callbacks as $priority => $callbacks) {
			foreach ($callbacks as $cb) {
				if (is_array($cb['function']) && is_object($cb['function'][0])) {
					$class_name = get_class($cb['function'][0]);
					if (preg_match('/^WC_(EU_)?VAT_/', $class_name)) {
						$has_vat_class = true;
						break 2;
					}
				}
			}
		}
		
		if ($has_vat_class) {
			$log = sprintf("[%s] VAT Hook Triggered: %s (%s)\n", date('Y-m-d H:i:s'), $tag, $cb['function'][1]);
			error_log($log, 3, WP_CONTENT_DIR . '/hook-log-345nsjg.txt');
		}
		
		return $tag;
		
	});

}
